/// 密钥管理模块
use crate::constants::{
    DEFAULT_ARGON_M_COST_KIB, DEFAULT_ARGON_P_COST, DEFAULT_ARGON_T_COST, SALT_LEN, XNONCE_LEN,
};
use crate::crypto::{
    decrypt_with_aad, derive_key, encrypt_with_aad, pack_encrypted_blob, unpack_encrypted_blob,
};
use crate::utils::{
    compute_fingerprint, escape_aad_field, hash_metadata_field, parse_aad_map,
    prompt_password_confirm, try_mlockall, write_file_strict, write_file_strict_with_options,
};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::OsRng;
use dialoguer::{Confirm, Password};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::RngCore;
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// 密钥生成结果，持有生成的密钥和相关路径
pub struct GeneratedKeys {
    pub fingerprint: String,
    pub signing_key: SigningKey,
    pub x25519_pub_path: PathBuf,
    pub x25519_enc_path: PathBuf,
    pub enc_path: PathBuf,
    pub pub_path: PathBuf,
}

/// 生成密钥对并安全存储到 keystore（共用逻辑）
///
/// 生成 Ed25519 签名密钥对和 X25519 加密密钥对，
/// 先在内存中完成全部 Argon2id 密钥派生与私钥加密，全部成功后再一次性写入 keystore 目录，
/// 杜绝中途失败或崩溃留下孤儿公钥 (H-2)。
pub fn generate_and_store_keys(
    name: &str,
    email: &str,
) -> Result<GeneratedKeys, Box<dyn std::error::Error>> {
    try_mlockall();

    // 1. 在内存中生成 Ed25519 签名密钥对
    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Export PKCS#8 encoded private key (DER, SecretDocument drops with zeroize)
    let pkcs8_doc =
        signing_key.to_pkcs8_der().map_err(|e| format!("PKCS#8 encoding failed: {}", e))?;
    let pkcs8_der = pkcs8_doc.as_bytes();

    // compute fingerprint on Ed25519 public key bytes
    let pub_bytes = verifying_key.to_bytes();
    let fingerprint = compute_fingerprint(&pub_bytes);

    // 2. 在内存中生成 X25519 加密密钥对
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    let x25519_public_bytes = x25519_public.to_bytes();
    let x25519_secret_bytes = Zeroizing::new(x25519_secret.to_bytes());

    // 3. 获取或自动生成口令（注意：在 Argon2 派生和写盘成功前不提前打印自动口令，避免崩溃误导用户）
    let auto_backup_pass = Confirm::new()
        .with_prompt("Auto-generate backup encryption password?")
        .default(true)
        .interact()?;

    let backup_pass: Zeroizing<String> = if auto_backup_pass {
        let mut rnd = Zeroizing::new(vec![0u8; 48]);
        OsRng.fill_bytes(&mut rnd);
        Zeroizing::new(general_purpose::URL_SAFE_NO_PAD.encode(&*rnd))
    } else {
        match prompt_password_confirm("Enter backup encryption password") {
            Some(x) => Zeroizing::new(x),
            None => return Err("Failed to read backup password".into()),
        }
    };

    // Argon2 params
    let mem_kib = DEFAULT_ARGON_M_COST_KIB;
    let t_cost = DEFAULT_ARGON_T_COST;
    let p_cost = DEFAULT_ARGON_P_COST;

    // 4. 在内存中派生密钥并加密两把私钥（使用身份元数据哈希绑定 AAD，避免明文泄漏姓名/邮箱 M-3）
    let name_escaped = escape_aad_field(name);
    let email_escaped = escape_aad_field(email);
    let id_hash = hash_metadata_field(&format!("{}|{}", name_escaped, email_escaped));

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let sym_key = Zeroizing::new(derive_key(&backup_pass, &salt, mem_kib, t_cost, p_cost)?);
    let aad_str = format!("id_sha256={}|fp={}|type=ed25519", id_hash, fingerprint);
    let aad_bytes = aad_str.as_bytes();
    let ciphertext = encrypt_with_aad(&sym_key, &nonce, pkcs8_der, aad_bytes)?;
    let blob = pack_encrypted_blob(mem_kib, t_cost, p_cost, &salt, &nonce, aad_bytes, &ciphertext)?;

    let mut x25519_salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut x25519_salt);
    let mut x25519_nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut x25519_nonce);

    let x25519_sym_key =
        Zeroizing::new(derive_key(&backup_pass, &x25519_salt, mem_kib, t_cost, p_cost)?);
    let x25519_aad_str = format!("id_sha256={}|fp={}|type=x25519", id_hash, fingerprint);
    let x25519_aad_bytes = x25519_aad_str.as_bytes();
    let x25519_ciphertext =
        encrypt_with_aad(&x25519_sym_key, &x25519_nonce, &*x25519_secret_bytes, x25519_aad_bytes)?;
    let x25519_blob = pack_encrypted_blob(
        mem_kib,
        t_cost,
        p_cost,
        &x25519_salt,
        &x25519_nonce,
        x25519_aad_bytes,
        &x25519_ciphertext,
    )?;

    // 5. 全部密码学运算成功后，一次性落盘写入 keystore（若任一文件写入失败则回滚清理）
    let keystore = PathBuf::from("keystore");
    fs::create_dir_all(&keystore)?;
    fs::set_permissions(&keystore, fs::Permissions::from_mode(0o700))?;

    let pub_path = keystore.join(format!("public_{}.asc", fingerprint));
    let x25519_pub_path = keystore.join(format!("x25519_public_{}.asc", fingerprint));
    let enc_path = keystore.join(format!("private_{}.asc.enc", fingerprint));
    let x25519_enc_path = keystore.join(format!("x25519_private_{}.asc.enc", fingerprint));
    let instr_path = keystore.join(format!("recovery_instructions_{}.txt", fingerprint));

    let instr = format!(
        "Recovery Instructions\n\
        ====================\n\n\
        Fingerprint: {fp}\n\
        Name: {name}\n\
        Email: {email}\n\n\
        === Decrypt an encrypted file ===\n\n\
        To decrypt a .pubenc file encrypted with this keypair:\n\n\
          yacrypt decrypt <file.pubenc> \\\n\
              --private-key {x25519_enc}\n\n\
        You will be prompted for the encryption password you set during key generation.\n\n\
        === Advanced: Decrypt private key only ===\n\n\
        To export the raw private key (DER format):\n\n\
          yacrypt decrypt-private-key {ed_enc} -o private_{fp}.der\n\n\
        ⚠️  SECURITY WARNING:\n\
        - Do NOT store the backup password with the encrypted file\n\
        - Keep the backup password in a secure password manager\n\
        - Store the encrypted backup in a safe location\n\
        - The backup password is required to decrypt the private key\n",
        fp = fingerprint,
        name = name_escaped,
        email = email_escaped,
        x25519_enc = x25519_enc_path.display(),
        ed_enc = enc_path.display(),
    );

    let write_all_files = || -> std::io::Result<()> {
        write_file_strict(&pub_path, general_purpose::STANDARD.encode(pub_bytes).as_bytes())?;
        write_file_strict(
            &x25519_pub_path,
            general_purpose::STANDARD.encode(x25519_public_bytes).as_bytes(),
        )?;
        write_file_strict(&enc_path, &blob)?;
        write_file_strict(&x25519_enc_path, &x25519_blob)?;
        write_file_strict(&instr_path, instr.as_bytes())?;
        Ok(())
    };

    if let Err(e) = write_all_files() {
        for p in [&pub_path, &x25519_pub_path, &enc_path, &x25519_enc_path, &instr_path] {
            let _ = fs::remove_file(p);
        }
        return Err(e.into());
    }

    if auto_backup_pass {
        println!("✅ Backup password generated:");
        println!("   {}", backup_pass.as_str());
        println!("   ⚠️  IMPORTANT: Save this password securely! You will need it to decrypt your private key backup.");
    }

    Ok(GeneratedKeys {
        fingerprint,
        signing_key,
        x25519_pub_path,
        x25519_enc_path,
        enc_path,
        pub_path,
    })
}

/// 从加密的 Ed25519 私钥备份文件加载 SigningKey（用于复用已有密钥签名）
pub fn load_signing_key_from_backup(
    enc_path: &Path,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if !enc_path.exists() {
        return Err(format!("Signing key file not found: {}", enc_path.display()).into());
    }

    let pass = Zeroizing::new(
        Password::new().with_prompt("Enter signing private key password").interact()?,
    );

    let mut f = File::open(enc_path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    let blob = unpack_encrypted_blob(&data)
        .map_err(|s| format!("Invalid signing key blob format: {}", s))?;

    let aad_map =
        parse_aad_map(&blob.aad).map_err(|s| format!("Invalid signing key AAD: {}", s))?;
    if let Some(t) = aad_map.get("type") {
        if t != "ed25519" {
            return Err(format!(
                "Expected Ed25519 signing key (private_<FP>.asc.enc), got key type '{}'",
                t
            )
            .into());
        }
    }

    let key =
        Zeroizing::new(derive_key(&pass, &blob.salt, blob.mem_kib, blob.t_cost, blob.p_cost)?);
    let plaintext =
        Zeroizing::new(decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad)?);

    let signing_key = SigningKey::from_pkcs8_der(&plaintext)
        .map_err(|e| format!("Invalid Ed25519 PKCS#8 DER private key: {}", e))?;

    Ok(signing_key)
}

/// 生成受保护的 Ed25519 密钥对并创建加密备份（CLI 入口）
pub fn cmd_generate_protected_key(
    name: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let keys = generate_and_store_keys(name, email)?;

    println!(
        "✅ Ed25519 keypair generated and encrypted backup written to: {}",
        keys.enc_path.display()
    );
    println!("✅ Ed25519 public key written to: {}", keys.pub_path.display());
    println!("✅ X25519 keypair generated for encryption");
    println!("✅ X25519 public key written to: {}", keys.x25519_pub_path.display());
    println!("✅ X25519 private key encrypted: {}", keys.x25519_enc_path.display());
    println!("Fingerprint: {}", keys.fingerprint);

    Ok(())
}

/// 解密备份文件并输出 Ed25519 PKCS#8 DER 私钥
pub fn cmd_decrypt_backup(
    enc_path: &Path,
    out: Option<&Path>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // 验证输入文件存在
    if !enc_path.exists() {
        return Err(format!("Encrypted file not found: {}", enc_path.display()).into());
    }

    // 读取密码
    let pass = Zeroizing::new(Password::new().with_prompt("Enter backup password").interact()?);

    // 读取加密文件
    let mut f = File::open(enc_path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    // 解析 blob
    let blob = unpack_encrypted_blob(&data).map_err(|s| format!("Invalid blob format: {}", s))?;

    // 校验密钥类型标记，防止误将 X25519 原始私钥导出为 .der (L-5)
    let aad_map = parse_aad_map(&blob.aad).map_err(|s| format!("Invalid blob AAD: {}", s))?;
    if let Some(key_type) = aad_map.get("type") {
        if key_type != "ed25519" {
            return Err(format!(
                "Cannot export '{}' key as PKCS#8 DER — please provide Ed25519 backup (private_<FP>.asc.enc)",
                key_type
            )
            .into());
        }
    }

    // 派生密钥
    let key =
        Zeroizing::new(derive_key(&pass, &blob.salt, blob.mem_kib, blob.t_cost, blob.p_cost)?);

    // 解密（使用 AAD 验证完整性，使用 Zeroizing 确保明文私钥用后清零 L-3）
    let mut plaintext =
        Zeroizing::new(decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad)?);

    // 进一步验证导出内容是合法的 Ed25519 PKCS#8 DER (L-5)
    if SigningKey::from_pkcs8_der(&plaintext).is_err() {
        plaintext.zeroize();
        return Err("Decrypted payload is not a valid Ed25519 PKCS#8 DER private key".into());
    }

    // 确定输出路径
    let out_path = match out {
        Some(p) => p.to_path_buf(),
        None => {
            let stem = enc_path.file_stem().and_then(|s| s.to_str()).unwrap_or("private_out");
            PathBuf::from(format!("{}.der", stem))
        }
    };

    // 写入解密后的私钥
    write_file_strict_with_options(&out_path, &plaintext, force)?;
    plaintext.zeroize();

    println!("✅ Decrypted private key written to: {}", out_path.display());
    Ok(())
}
