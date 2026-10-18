/// 密钥管理模块
use crate::constants::{
    DEFAULT_ARGON_M_COST_KIB, DEFAULT_ARGON_P_COST, DEFAULT_ARGON_T_COST, SALT_LEN, XNONCE_LEN,
};
use crate::crypto::{
    decrypt_with_aad, derive_key, encrypt_with_aad, pack_encrypted_blob, unpack_encrypted_blob,
};
use crate::error::CryptError;
use crate::utils::{
    compute_fingerprint, parse_aad_map, try_mlockall, validate_password_length, write_file_strict,
    write_file_strict_with_options,
};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::OsRng;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::RngCore;
use std::{
    collections::BTreeMap,
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
    pub instr_path: PathBuf,
    /// 若使用自动生成口令，则返回该口令供调用方安全展示；若为用户自设口令则为 None
    pub auto_generated_password: Option<Zeroizing<String>>,
}

/// 扫描 keystore 目录得到的本地密钥对条目
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringEntry {
    pub fingerprint: String,
    pub ed25519_pub_path: Option<PathBuf>,
    pub ed25519_enc_path: Option<PathBuf>,
    pub x25519_pub_path: Option<PathBuf>,
    pub x25519_enc_path: Option<PathBuf>,
    pub instr_path: Option<PathBuf>,
}

impl KeyringEntry {
    /// 返回简短指纹（前 12 位 + 后 8 位）用于列表展示
    pub fn short_fingerprint(&self) -> String {
        if self.fingerprint.len() >= 20 {
            format!(
                "{}…{}",
                &self.fingerprint[..12],
                &self.fingerprint[self.fingerprint.len() - 8..]
            )
        } else {
            self.fingerprint.clone()
        }
    }
}

/// 在指定 keystore 目录下生成 Ed25519 签名密钥对与 X25519 加密密钥对。
///
/// - 当 `password` 为 `Some(pass)` 时校验口令长度并使用用户口令；
/// - 当 `password` 为 `None` 时自动生成 48 字节 URL-safe Base64 高熵随机口令并随结果返回；
/// - 先在内存中完成全部 Argon2id 密钥派生与私钥加密，全部成功后再一次性写入 `keystore_dir`（0700），
///   杜绝中途失败或崩溃留下孤儿公钥 (H-2)。
pub fn generate_and_store_keys_in_dir(
    keystore_dir: &Path,
    password: Option<&str>,
) -> Result<GeneratedKeys, CryptError> {
    try_mlockall();

    if let Some(pw) = password {
        validate_password_length(pw)?;
    }

    // 1. 在内存中生成 Ed25519 签名密钥对
    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Export PKCS#8 encoded private key (DER, SecretDocument drops with zeroize)
    let pkcs8_doc = signing_key
        .to_pkcs8_der()
        .map_err(|e| CryptError::Key(format!("PKCS#8 encoding failed: {}", e)))?;
    let pkcs8_der = pkcs8_doc.as_bytes();

    // compute fingerprint on Ed25519 public key bytes
    let pub_bytes = verifying_key.to_bytes();
    let fingerprint = compute_fingerprint(&pub_bytes);

    // 2. 在内存中生成 X25519 加密密钥对
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    let x25519_public_bytes = x25519_public.to_bytes();
    let x25519_secret_bytes = Zeroizing::new(x25519_secret.to_bytes());

    // 3. 准备备份口令
    let (backup_pass, auto_generated_password): (Zeroizing<String>, Option<Zeroizing<String>>) =
        match password {
            Some(user_pw) => (Zeroizing::new(user_pw.to_owned()), None),
            None => {
                let mut rnd = Zeroizing::new(vec![0u8; 48]);
                OsRng.fill_bytes(&mut rnd);
                let auto_pw = Zeroizing::new(general_purpose::URL_SAFE_NO_PAD.encode(&*rnd));
                (auto_pw.clone(), Some(auto_pw))
            }
        };

    // Argon2 params
    let mem_kib = DEFAULT_ARGON_M_COST_KIB;
    let t_cost = DEFAULT_ARGON_T_COST;
    let p_cost = DEFAULT_ARGON_P_COST;

    // 4. 在内存中派生密钥并加密两把私钥。AAD 仅绑定指纹与密钥类型；不再写入姓名/邮箱摘要 (M-3)
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let sym_key = Zeroizing::new(derive_key(&backup_pass, &salt, mem_kib, t_cost, p_cost)?);
    let aad_str = format!("fp={}|type=ed25519", fingerprint);
    let aad_bytes = aad_str.as_bytes();
    let ciphertext = encrypt_with_aad(&sym_key, &nonce, pkcs8_der, aad_bytes)?;
    let blob = pack_encrypted_blob(mem_kib, t_cost, p_cost, &salt, &nonce, aad_bytes, &ciphertext)?;

    let mut x25519_salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut x25519_salt);
    let mut x25519_nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut x25519_nonce);

    let x25519_sym_key =
        Zeroizing::new(derive_key(&backup_pass, &x25519_salt, mem_kib, t_cost, p_cost)?);
    let x25519_aad_str = format!("fp={}|type=x25519", fingerprint);
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
    fs::create_dir_all(keystore_dir)?;
    fs::set_permissions(keystore_dir, fs::Permissions::from_mode(0o700))?;

    let pub_path = keystore_dir.join(format!("public_{}.asc", fingerprint));
    let x25519_pub_path = keystore_dir.join(format!("x25519_public_{}.asc", fingerprint));
    let enc_path = keystore_dir.join(format!("private_{}.asc.enc", fingerprint));
    let x25519_enc_path = keystore_dir.join(format!("x25519_private_{}.asc.enc", fingerprint));
    let instr_path = keystore_dir.join(format!("recovery_instructions_{}.txt", fingerprint));

    let instr = format!(
        "Recovery Instructions\n\
        ====================\n\n\
        Fingerprint: {fp}\n\n\
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

    Ok(GeneratedKeys {
        fingerprint,
        signing_key,
        x25519_pub_path,
        x25519_enc_path,
        enc_path,
        pub_path,
        instr_path,
        auto_generated_password,
    })
}

/// 从加密的 Ed25519 私钥备份文件加载 SigningKey（纯函数，接收调用方提供的口令）
pub fn load_signing_key_with_password(
    enc_path: &Path,
    password: &str,
) -> Result<SigningKey, CryptError> {
    if !enc_path.exists() {
        return Err(CryptError::Key(format!(
            "Signing key file not found: {}",
            enc_path.display()
        )));
    }

    let mut f = File::open(enc_path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    let blob = unpack_encrypted_blob(&data)
        .map_err(|s| CryptError::Format(format!("Invalid signing key blob format: {}", s)))?;

    let aad_map = parse_aad_map(&blob.aad)
        .map_err(|s| CryptError::Format(format!("Invalid signing key AAD: {}", s)))?;
    if let Some(t) = aad_map.get("type") {
        if t != "ed25519" {
            return Err(CryptError::Key(format!(
                "Expected Ed25519 signing key (private_<FP>.asc.enc), got key type '{}'",
                t
            )));
        }
    }

    let key = Zeroizing::new(derive_key(
        password,
        &blob.salt,
        blob.mem_kib,
        blob.t_cost,
        blob.p_cost,
    )?);
    let plaintext =
        Zeroizing::new(decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad)?);

    let signing_key = SigningKey::from_pkcs8_der(&plaintext)
        .map_err(|e| CryptError::Key(format!("Invalid Ed25519 PKCS#8 DER private key: {}", e)))?;

    Ok(signing_key)
}

/// 解密备份文件并输出 Ed25519 PKCS#8 DER 私钥到目标文件，返回实际写入路径
pub fn decrypt_backup_with_password(
    enc_path: &Path,
    password: &str,
    out: Option<&Path>,
    force: bool,
) -> Result<PathBuf, CryptError> {
    if !enc_path.exists() {
        return Err(CryptError::Key(format!("Encrypted file not found: {}", enc_path.display())));
    }

    let mut f = File::open(enc_path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    let blob = unpack_encrypted_blob(&data)
        .map_err(|s| CryptError::Format(format!("Invalid blob format: {}", s)))?;

    // 校验密钥类型标记，防止误将 X25519 原始私钥导出为 .der (L-5)
    let aad_map = parse_aad_map(&blob.aad)
        .map_err(|s| CryptError::Format(format!("Invalid blob AAD: {}", s)))?;
    if let Some(key_type) = aad_map.get("type") {
        if key_type != "ed25519" {
            return Err(CryptError::Key(format!(
                "Cannot export '{}' key as PKCS#8 DER — please provide Ed25519 backup (private_<FP>.asc.enc)",
                key_type
            )));
        }
    }

    let key = Zeroizing::new(derive_key(
        password,
        &blob.salt,
        blob.mem_kib,
        blob.t_cost,
        blob.p_cost,
    )?);

    let mut plaintext =
        Zeroizing::new(decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad)?);

    if SigningKey::from_pkcs8_der(&plaintext).is_err() {
        plaintext.zeroize();
        return Err(CryptError::Key(
            "Decrypted payload is not a valid Ed25519 PKCS#8 DER private key".into(),
        ));
    }

    let out_path = match out {
        Some(p) => p.to_path_buf(),
        None => {
            let stem = enc_path.file_stem().and_then(|s| s.to_str()).unwrap_or("private_out");
            PathBuf::from(format!("{}.der", stem))
        }
    };

    write_file_strict_with_options(&out_path, &plaintext, force)?;
    plaintext.zeroize();

    Ok(out_path)
}

/// 扫描指定 keystore 目录，按 64 位十六进制指纹聚合本地密钥对条目
pub fn scan_keystore(keystore_dir: &Path) -> Result<Vec<KeyringEntry>, CryptError> {
    if !keystore_dir.exists() {
        return Ok(Vec::new());
    }

    let mut map: BTreeMap<String, KeyringEntry> = BTreeMap::new();

    for entry_res in fs::read_dir(keystore_dir)? {
        let entry = entry_res?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };

        let matched = if let Some(fp) =
            fname.strip_prefix("x25519_public_").and_then(|s| s.strip_suffix(".asc"))
        {
            Some((fp, "x25519_pub"))
        } else if let Some(fp) =
            fname.strip_prefix("public_").and_then(|s| s.strip_suffix(".asc"))
        {
            Some((fp, "ed25519_pub"))
        } else if let Some(fp) =
            fname.strip_prefix("x25519_private_").and_then(|s| s.strip_suffix(".asc.enc"))
        {
            Some((fp, "x25519_enc"))
        } else if let Some(fp) =
            fname.strip_prefix("private_").and_then(|s| s.strip_suffix(".asc.enc"))
        {
            Some((fp, "ed25519_enc"))
        } else if let Some(fp) =
            fname.strip_prefix("recovery_instructions_").and_then(|s| s.strip_suffix(".txt"))
        {
            Some((fp, "instr"))
        } else {
            None
        };

        if let Some((fp_raw, kind)) = matched {
            if fp_raw.len() == 64 && fp_raw.chars().all(|c| c.is_ascii_hexdigit()) {
                let fp = fp_raw.to_uppercase();
                let item = map.entry(fp.clone()).or_insert_with(|| KeyringEntry {
                    fingerprint: fp,
                    ed25519_pub_path: None,
                    ed25519_enc_path: None,
                    x25519_pub_path: None,
                    x25519_enc_path: None,
                    instr_path: None,
                });
                match kind {
                    "ed25519_pub" => item.ed25519_pub_path = Some(path),
                    "ed25519_enc" => item.ed25519_enc_path = Some(path),
                    "x25519_pub" => item.x25519_pub_path = Some(path),
                    "x25519_enc" => item.x25519_enc_path = Some(path),
                    "instr" => item.instr_path = Some(path),
                    _ => {}
                }
            }
        }
    }

    Ok(map.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_scan_and_decrypt_keystore_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_ks_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let ks_dir = dir.join("keystore");
        let pw = "test-keystore-pass-123";
        let gen = generate_and_store_keys_in_dir(&ks_dir, Some(pw)).unwrap();
        assert!(gen.auto_generated_password.is_none());
        assert_eq!(gen.fingerprint.len(), 64);

        let entries = scan_keystore(&ks_dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fingerprint, gen.fingerprint);
        assert!(entries[0].ed25519_pub_path.is_some());
        assert!(entries[0].ed25519_enc_path.is_some());
        assert!(entries[0].x25519_pub_path.is_some());
        assert!(entries[0].x25519_enc_path.is_some());
        assert!(entries[0].instr_path.is_some());

        let loaded_sk = load_signing_key_with_password(&gen.enc_path, pw).unwrap();
        assert_eq!(loaded_sk.verifying_key(), gen.signing_key.verifying_key());

        let der_out = dir.join("exported.der");
        let out_path =
            decrypt_backup_with_password(&gen.enc_path, pw, Some(&der_out), false).unwrap();
        assert_eq!(out_path, der_out);
        assert!(der_out.exists());

        // L-5: Rejects exporting X25519 backup as PKCS#8 DER
        assert!(decrypt_backup_with_password(&gen.x25519_enc_path, pw, None, true).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
