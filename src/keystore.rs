/// 密钥管理模块
use crate::constants::{
    DEFAULT_ARGON_M_COST_KIB, DEFAULT_ARGON_P_COST, DEFAULT_ARGON_T_COST, SALT_LEN, XNONCE_LEN,
};
use crate::crypto::{
    decrypt_with_aad, derive_key, encrypt_with_aad, pack_encrypted_blob, unpack_encrypted_blob,
};
use crate::utils::{
    compute_fingerprint, escape_aad_field, prompt_password_confirm, try_mlockall, write_file_strict,
};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::OsRng;
use dialoguer::{Confirm, Password};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pkcs8::EncodePrivateKey;
use rand::RngCore;
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

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
/// 使用密码加密私钥并保存到 keystore 目录。
pub fn generate_and_store_keys(
    name: &str,
    email: &str,
) -> Result<GeneratedKeys, Box<dyn std::error::Error>> {
    try_mlockall();

    // generate ed25519 keypair using cryptographically secure RNG
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    secret_bytes.zeroize();
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Export PKCS#8 encoded private key (DER)
    let pkcs8_doc =
        signing_key.to_pkcs8_der().map_err(|e| format!("PKCS#8 encoding failed: {}", e))?;
    let pkcs8_der = pkcs8_doc.as_bytes();

    // compute fingerprint on public key bytes
    let pub_bytes = verifying_key.to_bytes();
    let fingerprint = compute_fingerprint(&pub_bytes);

    // create keystore dir
    let keystore = PathBuf::from("keystore");
    fs::create_dir_all(&keystore)?;
    fs::set_permissions(&keystore, fs::Permissions::from_mode(0o700))?;

    // write Ed25519 public key (base64)
    let pub_path = keystore.join(format!("public_{}.asc", fingerprint));
    write_file_strict(&pub_path, general_purpose::STANDARD.encode(pub_bytes).as_bytes())?;

    // Generate X25519 keypair for encryption (static key for long-term use)
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    let x25519_public_bytes = x25519_public.to_bytes();
    let mut x25519_secret_bytes = x25519_secret.to_bytes();

    // write X25519 public key (base64) - for encryption
    let x25519_pub_path = keystore.join(format!("x25519_public_{}.asc", fingerprint));
    write_file_strict(
        &x25519_pub_path,
        general_purpose::STANDARD.encode(x25519_public_bytes).as_bytes(),
    )?;

    // Prepare backup password
    let auto_backup_pass = Confirm::new()
        .with_prompt("Auto-generate backup encryption password?")
        .default(true)
        .interact()?;

    let backup_pass = if auto_backup_pass {
        let mut rnd = vec![0u8; 48];
        OsRng.fill_bytes(&mut rnd);
        let s = general_purpose::URL_SAFE_NO_PAD.encode(&rnd);
        rnd.zeroize();
        println!("✅ Backup password generated:");
        println!("   {}", s);
        println!("   ⚠️  IMPORTANT: Save this password securely! You will need it to decrypt your private key backup.");
        s
    } else {
        match prompt_password_confirm("Enter backup encryption password") {
            Some(x) => x,
            None => return Err("Failed to read backup password".into()),
        }
    };

    // Argon2 params
    let mem_kib = DEFAULT_ARGON_M_COST_KIB;
    let t_cost = DEFAULT_ARGON_T_COST;
    let p_cost = DEFAULT_ARGON_P_COST;

    // create salt and nonce for Ed25519 key
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    // derive symmetric key from backup_pass + salt
    let mut sym_key = derive_key(&backup_pass, &salt, mem_kib, t_cost, p_cost)?;

    // 转义特殊字符防止注入，确保 AAD 格式正确
    let name_escaped = escape_aad_field(name);
    let email_escaped = escape_aad_field(email);
    let aad_str = format!("name={}|email={}|fp={}", name_escaped, email_escaped, fingerprint);
    let aad_bytes = aad_str.as_bytes();

    // encrypt Ed25519 PKCS8 DER with XChaCha20Poly1305
    let ciphertext = encrypt_with_aad(&sym_key, &nonce, pkcs8_der, aad_bytes)?;

    // pack blob (now includes AAD)
    let blob = pack_encrypted_blob(mem_kib, t_cost, p_cost, &salt, &nonce, aad_bytes, &ciphertext);

    // write encrypted Ed25519 private key
    let enc_path = keystore.join(format!("private_{}.asc.enc", fingerprint));
    write_file_strict(&enc_path, &blob)?;

    // encrypt X25519 private key with the same password
    let mut x25519_salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut x25519_salt);
    let mut x25519_nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut x25519_nonce);

    let mut x25519_sym_key = derive_key(&backup_pass, &x25519_salt, mem_kib, t_cost, p_cost)?;
    let x25519_aad_str =
        format!("name={}|email={}|fp={}|type=x25519", name_escaped, email_escaped, fingerprint);
    let x25519_aad_bytes = x25519_aad_str.as_bytes();

    let x25519_ciphertext =
        encrypt_with_aad(&x25519_sym_key, &x25519_nonce, &x25519_secret_bytes, x25519_aad_bytes)?;

    let x25519_blob = pack_encrypted_blob(
        mem_kib,
        t_cost,
        p_cost,
        &x25519_salt,
        &x25519_nonce,
        x25519_aad_bytes,
        &x25519_ciphertext,
    );

    // write encrypted X25519 private key
    let x25519_enc_path = keystore.join(format!("x25519_private_{}.asc.enc", fingerprint));
    write_file_strict(&x25519_enc_path, &x25519_blob)?;

    x25519_sym_key.zeroize();
    x25519_secret_bytes.zeroize();

    // write recovery instructions (do NOT show passphrase in clear)
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
    write_file_strict(&instr_path, instr.as_bytes())?;

    // zeroize sensitive material
    sym_key.zeroize();
    let mut bp = backup_pass.into_bytes();
    bp.zeroize();

    Ok(GeneratedKeys {
        fingerprint,
        signing_key,
        x25519_pub_path,
        x25519_enc_path,
        enc_path,
        pub_path,
    })
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

/// 解密备份文件并输出私钥
pub fn cmd_decrypt_backup(
    enc_path: &Path,
    out: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 验证输入文件存在
    if !enc_path.exists() {
        return Err(format!("Encrypted file not found: {}", enc_path.display()).into());
    }

    // 读取密码
    let pass = Password::new().with_prompt("Enter backup password").interact()?;

    // 读取加密文件
    let mut f = File::open(enc_path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    // 解析 blob
    let blob = unpack_encrypted_blob(&data).map_err(|s| format!("Invalid blob format: {}", s))?;

    // 派生密钥
    let mut key = derive_key(&pass, &blob.salt, blob.mem_kib, blob.t_cost, blob.p_cost)?;

    // 解密（使用 AAD 验证完整性）
    let plaintext = decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad)?;

    // 确定输出路径
    let out_path = match out {
        Some(p) => p.to_path_buf(),
        None => {
            let stem = enc_path.file_stem().and_then(|s| s.to_str()).unwrap_or("private_out");
            PathBuf::from(format!("{}.der", stem))
        }
    };

    // 写入解密后的私钥
    write_file_strict(&out_path, &plaintext)?;

    // 清理敏感数据
    key.zeroize();
    let mut pbytes = pass.into_bytes();
    pbytes.zeroize();

    println!("✅ Decrypted private key written to: {}", out_path.display());
    Ok(())
}
