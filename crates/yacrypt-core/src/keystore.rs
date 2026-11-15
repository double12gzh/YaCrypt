/// 密钥管理模块
use crate::constants::{
    DEFAULT_ARGON_M_COST_KIB, DEFAULT_ARGON_P_COST, DEFAULT_ARGON_T_COST, SALT_LEN, XNONCE_LEN,
};
use crate::crypto::{
    decrypt_with_aad, derive_key, encrypt_with_aad, pack_encrypted_blob, unpack_encrypted_blob,
};
use crate::error::CryptError;
use crate::utils::{
    compute_fingerprint, default_der_output_path, open_regular_file_nonblocking, parse_aad_map,
    preflight_check_output_path, try_mlockall, validate_password_length, write_file_strict,
    write_file_strict_with_options,
};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::OsRng;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::RngCore;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const LABELS_FILE_NAME: &str = "labels.tsv";
const BUNDLE_HEADER: &str = "-----BEGIN YACRYPT PUBLIC KEY BUNDLE V1-----";
const BUNDLE_FOOTER: &str = "-----END YACRYPT PUBLIC KEY BUNDLE V1-----";
const BUNDLE_SIGN_DOMAIN: &[u8] = b"yacrypt-keybundle-v1:";

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
    pub label: Option<String>,
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

    /// 返回包含可选本地别名的友好展示名（如 `[alice] A1B2C3D4E5F6…89ABCDEF`）
    pub fn display_name(&self) -> String {
        match self.label {
            Some(ref lbl) => format!("[{}] {}", lbl, self.short_fingerprint()),
            None => self.short_fingerprint(),
        }
    }
}

/// 解析生效的本地 keystore 目录，优先级：
/// 1. 显式传入的 `--keystore-dir`
/// 2. 环境变量 `YACRYPT_KEYSTORE`
/// 3. 当前工作目录下已存在的 `./keystore`（向后兼容既有脚本与测试）
/// 4. `$HOME/.yacrypt/keystore`
/// 5. 兜底 `./keystore`
pub fn resolve_keystore_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        if !p.as_os_str().is_empty() {
            return p.to_path_buf();
        }
    }
    if let Some(env_dir) = std::env::var_os("YACRYPT_KEYSTORE") {
        if !env_dir.is_empty() {
            return PathBuf::from(env_dir);
        }
    }
    let cwd_ks = PathBuf::from("keystore");
    if cwd_ks.exists() {
        return cwd_ks;
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".yacrypt").join("keystore");
        }
    }
    cwd_ks
}

/// 创建并收紧 keystore 目录权限为 `0700`（若父目录为新建的 `.yacrypt` 也一并设为 `0700`）
pub fn ensure_keystore_dir(keystore_dir: &Path) -> Result<(), CryptError> {
    if let Some(parent) = keystore_dir.parent() {
        if parent.file_name().and_then(|s| s.to_str()) == Some(".yacrypt") && !parent.exists() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    fs::create_dir_all(keystore_dir)?;
    fs::set_permissions(keystore_dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// 校验 X25519 公钥是否为具有贡献性的高阶点（拒绝全零及 8 阶扭曲低阶点 L-1）
pub fn is_contributory_x25519_pubkey(pub_bytes: &[u8; 32]) -> bool {
    let probe = StaticSecret::from([1u8; 32]);
    let pk = X25519PublicKey::from(*pub_bytes);
    probe.diffie_hellman(&pk).was_contributory()
}

/// 校验本地别名合法性（仅存本地 `0600` 索引，严禁含控制字符/路径分隔符或伪装成 `>=16` 位十六进制指纹前缀）
pub fn validate_key_label(label: &str) -> Result<String, CryptError> {
    let trimmed = label.trim();
    let char_count = trimmed.chars().count();
    if trimmed.is_empty() || char_count > 64 {
        return Err(CryptError::Key("Key label must be between 1 and 64 characters".into()));
    }
    if trimmed.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | '|' | '=')) {
        return Err(CryptError::Key(
            "Key label must not contain control characters, '/', '\\', '|', or '='".into(),
        ));
    }
    if trimmed.len() >= 16 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptError::Key(
            "Key label cannot be a >=16-character hex string (reserved for fingerprint prefixes)"
                .into(),
        ));
    }
    Ok(trimmed.to_string())
}

/// 读取 keystore 下的本地 `0600` 别名映射 (`FP -> label`)
pub fn load_key_labels(keystore_dir: &Path) -> BTreeMap<String, String> {
    let labels_path = keystore_dir.join(LABELS_FILE_NAME);
    let Ok(content) = fs::read_to_string(&labels_path) else {
        return BTreeMap::new();
    };
    let mut map = BTreeMap::new();
    for line in content.lines() {
        let Some((fp_raw, lbl_raw)) = line.split_once('\t') else {
            continue;
        };
        let fp = fp_raw.trim().to_uppercase();
        if fp.len() == 64 && fp.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(clean_lbl) = validate_key_label(lbl_raw) {
                map.insert(fp, clean_lbl);
            }
        }
    }
    map
}

/// 设置或移除指定 64 位指纹的本地 `0600` 密钥别名（自动清理已删除密钥的陈旧孤儿别名，绝不修改密文或公钥文件，严守 M-3）
pub fn set_key_label(
    keystore_dir: &Path,
    fingerprint: &str,
    label: Option<&str>,
) -> Result<(), CryptError> {
    let fp = fingerprint.trim().to_uppercase();
    if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptError::Key("Invalid 64-character hex fingerprint for label".into()));
    }

    let active_fps: BTreeSet<String> = scan_keystore(keystore_dir)
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.fingerprint)
        .collect();
    let mut map = load_key_labels(keystore_dir);
    map.retain(|existing_fp, _| existing_fp == &fp || active_fps.contains(existing_fp));

    match label.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            let clean = validate_key_label(raw)?;
            if let Some((other_fp, _)) = map.iter().find(|(existing_fp, existing_lbl)| {
                *existing_fp != &fp && existing_lbl.eq_ignore_ascii_case(&clean)
            }) {
                return Err(CryptError::Key(format!(
                    "Label '{}' is already assigned to key {}",
                    clean, other_fp
                )));
            }
            map.insert(fp, clean);
        }
        None => {
            map.remove(&fp);
        }
    }

    let labels_path = keystore_dir.join(LABELS_FILE_NAME);
    if map.is_empty() {
        if labels_path.exists() {
            let _ = fs::remove_file(&labels_path);
        }
        return Ok(());
    }

    ensure_keystore_dir(keystore_dir)?;
    let mut serialized = String::new();
    for (k, v) in &map {
        serialized.push_str(k);
        serialized.push('\t');
        serialized.push_str(v);
        serialized.push('\n');
    }
    write_file_strict_with_options(&labels_path, serialized.as_bytes(), true)?;
    Ok(())
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
    ensure_keystore_dir(keystore_dir)?;

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
    let (mut f, _) = match open_regular_file_nonblocking(enc_path, "Signing key file not found") {
        Ok(pair) => pair,
        Err(CryptError::Crypto(msg)) => return Err(CryptError::Key(msg)),
        Err(e) => return Err(e),
    };
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

    let key =
        Zeroizing::new(derive_key(password, &blob.salt, blob.mem_kib, blob.t_cost, blob.p_cost)?);
    let plaintext =
        Zeroizing::new(decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad)?);

    let signing_key = SigningKey::from_pkcs8_der(&plaintext)
        .map_err(|e| CryptError::Key(format!("Invalid Ed25519 PKCS#8 DER private key: {}", e)))?;

    Ok(signing_key)
}

/// 生成密钥对并可选写入本地 `0600` 别名（在 Argon2id 派生前校验别名与活跃密钥环冲突，若别名写入失败则回滚）
pub fn generate_and_store_keys_with_label(
    keystore_dir: &Path,
    password: Option<&str>,
    label: Option<&str>,
) -> Result<GeneratedKeys, CryptError> {
    let clean_label = match label.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            let clean = validate_key_label(raw)?;
            let active = scan_keystore(keystore_dir)?;
            if let Some(other) = active
                .iter()
                .find(|e| e.label.as_ref().is_some_and(|l| l.eq_ignore_ascii_case(&clean)))
            {
                return Err(CryptError::Key(format!(
                    "Label '{}' is already assigned to key {}",
                    clean, other.fingerprint
                )));
            }
            Some(clean)
        }
        None => None,
    };

    let keys = generate_and_store_keys_in_dir(keystore_dir, password)?;
    if let Some(ref lbl) = clean_label {
        if let Err(e) = set_key_label(keystore_dir, &keys.fingerprint, Some(lbl)) {
            for p in [
                &keys.pub_path,
                &keys.x25519_pub_path,
                &keys.enc_path,
                &keys.x25519_enc_path,
                &keys.instr_path,
            ] {
                let _ = fs::remove_file(p);
            }
            return Err(e);
        }
    }
    Ok(keys)
}

/// 解密备份文件并输出 Ed25519 PKCS#8 DER 私钥到目标文件，返回实际写入路径
pub fn decrypt_backup_with_password(
    enc_path: &Path,
    password: &str,
    out: Option<&Path>,
    force: bool,
) -> Result<PathBuf, CryptError> {
    let (mut f, _) = match open_regular_file_nonblocking(enc_path, "Encrypted file not found") {
        Ok(pair) => pair,
        Err(CryptError::Crypto(msg)) => return Err(CryptError::Key(msg)),
        Err(e) => return Err(e),
    };

    let out_path = match out {
        Some(p) => p.to_path_buf(),
        None => default_der_output_path(enc_path),
    };
    preflight_check_output_path(Some(enc_path), &out_path, force)?;

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

    let key =
        Zeroizing::new(derive_key(password, &blob.salt, blob.mem_kib, blob.t_cost, blob.p_cost)?);

    let mut plaintext =
        Zeroizing::new(decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad)?);

    if SigningKey::from_pkcs8_der(&plaintext).is_err() {
        plaintext.zeroize();
        return Err(CryptError::Key(
            "Decrypted payload is not a valid Ed25519 PKCS#8 DER private key".into(),
        ));
    }

    write_file_strict_with_options(&out_path, &plaintext, force)?;
    plaintext.zeroize();

    Ok(out_path)
}

/// 扫描指定 keystore 目录，按 64 位十六进制指纹聚合本地密钥对条目及本地别名
pub fn scan_keystore(keystore_dir: &Path) -> Result<Vec<KeyringEntry>, CryptError> {
    if !keystore_dir.exists() {
        return Ok(Vec::new());
    }

    let labels = load_key_labels(keystore_dir);
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
        } else if let Some(fp) = fname.strip_prefix("public_").and_then(|s| s.strip_suffix(".asc"))
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
        } else {
            fname
                .strip_prefix("recovery_instructions_")
                .and_then(|s| s.strip_suffix(".txt"))
                .map(|fp| (fp, "instr"))
        };

        if let Some((fp_raw, kind)) = matched {
            if fp_raw.len() == 64 && fp_raw.chars().all(|c| c.is_ascii_hexdigit()) {
                let fp = fp_raw.to_uppercase();
                let item = map.entry(fp.clone()).or_insert_with(|| KeyringEntry {
                    label: labels.get(&fp).cloned(),
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

/// 在本地密钥环中按完整 64 位指纹、本地别名（不区分大小写）或 `>= 16` 位十六进制指纹前缀查找唯一条目
pub fn find_keyring_entry(keystore_dir: &Path, selector: &str) -> Result<KeyringEntry, CryptError> {
    let trimmed = selector.trim();
    if trimmed.is_empty() {
        return Err(CryptError::Key("Empty key selector".into()));
    }

    // 若用户直接传入了 keystore 中某个密钥文件的路径，自动提取其 64 位指纹
    let as_path = Path::new(trimmed);
    let extracted_fp = as_path
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|fname| {
            fname
                .strip_prefix("x25519_public_")
                .and_then(|s| s.strip_suffix(".asc"))
                .or_else(|| fname.strip_prefix("public_").and_then(|s| s.strip_suffix(".asc")))
                .or_else(|| {
                    fname.strip_prefix("x25519_private_").and_then(|s| s.strip_suffix(".asc.enc"))
                })
                .or_else(|| fname.strip_prefix("private_").and_then(|s| s.strip_suffix(".asc.enc")))
        })
        .filter(|fp| fp.len() == 64 && fp.chars().all(|c| c.is_ascii_hexdigit()));

    let query = extracted_fp.unwrap_or(trimmed);
    let entries = scan_keystore(keystore_dir)?;

    let is_hex_prefix =
        query.len() >= 16 && query.len() <= 64 && query.chars().all(|c| c.is_ascii_hexdigit());
    let upper_query = query.to_uppercase();

    let matches: Vec<KeyringEntry> = entries
        .into_iter()
        .filter(|e| {
            let label_match =
                e.label.as_ref().map(|l| l.eq_ignore_ascii_case(query)).unwrap_or(false);
            let hex_match = is_hex_prefix && e.fingerprint.starts_with(&upper_query);
            label_match || hex_match
        })
        .collect();

    match matches.len() {
        0 => {
            if query.len() < 16 && query.chars().all(|c| c.is_ascii_hexdigit()) {
                Err(CryptError::Key(format!(
                    "Key selector '{}' not found as a label in {} (hex fingerprint prefixes must be >= 16 hex chars)",
                    selector,
                    keystore_dir.display()
                )))
            } else {
                Err(CryptError::Key(format!(
                    "No keypair matching '{}' found in {}",
                    selector,
                    keystore_dir.display()
                )))
            }
        }
        1 => Ok(matches.into_iter().next().unwrap()),
        n => Err(CryptError::Key(format!(
            "Ambiguous key selector '{}' matches {} keys in {}; use a longer fingerprint prefix",
            selector,
            n,
            keystore_dir.display()
        ))),
    }
}

/// 解析 `--key` / `--public-key` 参数（支持既有文件路径、本地别名或 `>= 16` 位十六进制指纹前缀）
pub fn resolve_recipient_key_arg(keystore_dir: &Path, arg: &str) -> Result<PathBuf, CryptError> {
    let p = Path::new(arg.trim());
    if p.exists() {
        return Ok(p.to_path_buf());
    }
    match find_keyring_entry(keystore_dir, arg) {
        Ok(entry) => {
            let disp = entry.display_name();
            entry.x25519_pub_path.ok_or_else(|| {
                CryptError::Key(format!(
                    "Key {} is missing its X25519 encryption public key file in {}",
                    disp,
                    keystore_dir.display()
                ))
            })
        }
        Err(lookup_err) => {
            if arg.contains('/') || arg.contains('\\') || arg.ends_with(".asc") {
                Err(CryptError::Key(format!("Public key file not found: {}", arg)))
            } else {
                Err(lookup_err)
            }
        }
    }
}

/// 解析 `--private-key` 参数（支持既有文件路径、本地别名或 `>= 16` 位十六进制指纹前缀）
pub fn resolve_decrypt_key_arg(keystore_dir: &Path, arg: &str) -> Result<PathBuf, CryptError> {
    let p = Path::new(arg.trim());
    if p.exists() {
        return Ok(p.to_path_buf());
    }
    match find_keyring_entry(keystore_dir, arg) {
        Ok(entry) => {
            let disp = entry.display_name();
            entry.x25519_enc_path.ok_or_else(|| {
                CryptError::Key(format!(
                    "Key {} only has public key(s) in {}; encrypted X25519 private key backup is not present",
                    disp,
                    keystore_dir.display()
                ))
            })
        }
        Err(lookup_err) => {
            if arg.contains('/') || arg.contains('\\') || arg.ends_with(".enc") {
                Err(CryptError::Key(format!("Private key file not found: {}", arg)))
            } else {
                Err(lookup_err)
            }
        }
    }
}

/// 解析 `--sign-key` 参数（支持既有文件路径、本地别名或 `>= 16` 位十六进制指纹前缀）
pub fn resolve_signing_key_arg(keystore_dir: &Path, arg: &str) -> Result<PathBuf, CryptError> {
    let p = Path::new(arg.trim());
    if p.exists() {
        return Ok(p.to_path_buf());
    }
    match find_keyring_entry(keystore_dir, arg) {
        Ok(entry) => {
            let disp = entry.display_name();
            entry.ed25519_enc_path.ok_or_else(|| {
                CryptError::Key(format!(
                    "Key {} only has public key(s) in {}; encrypted Ed25519 signing private key backup is not present",
                    disp,
                    keystore_dir.display()
                ))
            })
        }
        Err(lookup_err) => {
            if arg.contains('/') || arg.contains('\\') || arg.ends_with(".enc") {
                Err(CryptError::Key(format!("Signing key file not found: {}", arg)))
            } else {
                Err(lookup_err)
            }
        }
    }
}

fn build_bundle_signing_payload(ed25519_pub: &[u8; 32], x25519_pub: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BUNDLE_SIGN_DOMAIN.len() + 64);
    msg.extend_from_slice(BUNDLE_SIGN_DOMAIN);
    msg.extend_from_slice(ed25519_pub);
    msg.extend_from_slice(x25519_pub);
    msg
}

/// 默认公钥包导出文件名：`yacrypt_pubkey_<前16位指纹>.asc`
pub fn default_bundle_output_path(fingerprint: &str) -> PathBuf {
    let short = if fingerprint.len() >= 16 { &fingerprint[..16] } else { fingerprint };
    PathBuf::from(format!("yacrypt_pubkey_{}.asc", short))
}

/// 合并导出 Ed25519 + X25519 公钥包，并使用自有 Ed25519 私钥签署自绑定证明（严守 M-3：绝不包含本地别名或身份信息）
pub fn export_public_key_bundle(
    keystore_dir: &Path,
    selector: &str,
    password: &str,
    out: Option<&Path>,
    force: bool,
) -> Result<(String, PathBuf), CryptError> {
    let entry = find_keyring_entry(keystore_dir, selector)?;
    let ed_pub_path = entry.ed25519_pub_path.as_ref().ok_or_else(|| {
        CryptError::Key(format!("Missing Ed25519 public key for {}", entry.display_name()))
    })?;
    let x_pub_path = entry.x25519_pub_path.as_ref().ok_or_else(|| {
        CryptError::Key(format!("Missing X25519 public key for {}", entry.display_name()))
    })?;
    let ed_enc_path = entry.ed25519_enc_path.as_ref().ok_or_else(|| {
        CryptError::Key(format!(
            "Cannot sign public key bundle for {}: Ed25519 private key backup is not in local keystore",
            entry.display_name()
        ))
    })?;

    let out_path = match out {
        Some(p) => p.to_path_buf(),
        None => default_bundle_output_path(&entry.fingerprint),
    };
    preflight_check_output_path(None, &out_path, force)?;

    let ed_b64 = fs::read_to_string(ed_pub_path)?;
    let ed_bytes_vec = general_purpose::STANDARD
        .decode(ed_b64.trim())
        .map_err(|e| CryptError::Key(format!("Invalid Ed25519 public key Base64: {}", e)))?;
    let ed_pub: [u8; 32] = ed_bytes_vec
        .try_into()
        .map_err(|_| CryptError::Key("Invalid Ed25519 public key length".into()))?;

    let x_b64 = fs::read_to_string(x_pub_path)?;
    let x_bytes_vec = general_purpose::STANDARD
        .decode(x_b64.trim())
        .map_err(|e| CryptError::Key(format!("Invalid X25519 public key Base64: {}", e)))?;
    let x_pub: [u8; 32] = x_bytes_vec
        .try_into()
        .map_err(|_| CryptError::Key("Invalid X25519 public key length".into()))?;

    if !is_contributory_x25519_pubkey(&x_pub) {
        return Err(CryptError::Key(
            "Refusing to export non-contributory / low-order X25519 public key".into(),
        ));
    }

    let signing_key = load_signing_key_with_password(ed_enc_path, password)?;
    if signing_key.verifying_key().to_bytes() != ed_pub {
        return Err(CryptError::Key(
            "Ed25519 private key does not match public key file in keystore".into(),
        ));
    }
    let computed_fp = compute_fingerprint(&ed_pub);
    if !computed_fp.eq_ignore_ascii_case(&entry.fingerprint) {
        return Err(CryptError::Key("Ed25519 public key fingerprint mismatch".into()));
    }

    let payload = build_bundle_signing_payload(&ed_pub, &x_pub);
    let sig = signing_key.sign(&payload);

    let bundle_text = format!(
        "{hdr}\n\
        fingerprint={fp}\n\
        ed25519_pub={ed}\n\
        x25519_pub={x}\n\
        binding_sig={sig}\n\
        {ftr}\n",
        hdr = BUNDLE_HEADER,
        fp = computed_fp,
        ed = general_purpose::STANDARD.encode(ed_pub),
        x = general_purpose::STANDARD.encode(x_pub),
        sig = general_purpose::STANDARD.encode(sig.to_bytes()),
        ftr = BUNDLE_FOOTER,
    );

    write_file_strict_with_options(&out_path, bundle_text.as_bytes(), force)?;
    Ok((computed_fp, out_path))
}

/// 验证并导入合并公钥包（强制验证 Ed25519 对 X25519 公钥的自签名绑定与 L-1 低阶点检查）
pub fn import_public_key_bundle(
    keystore_dir: &Path,
    bundle_path: &Path,
    label: Option<&str>,
    force: bool,
) -> Result<String, CryptError> {
    const MAX_BUNDLE_BYTES: u64 = 64 * 1024;

    let (bundle_file, bundle_len) =
        match open_regular_file_nonblocking(bundle_path, "Public key bundle file not found") {
            Ok(pair) => pair,
            Err(CryptError::Crypto(msg)) => return Err(CryptError::Key(msg)),
            Err(e) => return Err(e),
        };
    if bundle_len > MAX_BUNDLE_BYTES {
        return Err(CryptError::Format(format!(
            "Public key bundle file '{}' exceeds maximum size ({} bytes)",
            bundle_path.display(),
            MAX_BUNDLE_BYTES
        )));
    }

    let clean_label = match label.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(validate_key_label(raw)?),
        None => None,
    };

    let mut raw = String::new();
    bundle_file.take(MAX_BUNDLE_BYTES + 1).read_to_string(&mut raw).map_err(|_| {
        CryptError::Format("Invalid public key bundle armor: file is not valid UTF-8 text".into())
    })?;
    if raw.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(CryptError::Format(format!(
            "Public key bundle file '{}' exceeds maximum size ({} bytes)",
            bundle_path.display(),
            MAX_BUNDLE_BYTES
        )));
    }
    let lines: Vec<&str> = raw.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.len() < 6
        || lines.first() != Some(&BUNDLE_HEADER)
        || lines.last() != Some(&BUNDLE_FOOTER)
    {
        return Err(CryptError::Format(
            "Invalid public key bundle armor: missing BEGIN/END YACRYPT PUBLIC KEY BUNDLE V1 markers"
                .into(),
        ));
    }

    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in &lines[1..lines.len() - 1] {
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| CryptError::Format(format!("Malformed bundle line: {}", line)))?;
        if !matches!(k, "fingerprint" | "ed25519_pub" | "x25519_pub" | "binding_sig") {
            return Err(CryptError::Format(format!("Unsupported field in bundle: {}", k)));
        }
        if fields.insert(k, v).is_some() {
            return Err(CryptError::Format(format!("Duplicate field in bundle: {}", k)));
        }
    }

    let fp_str = fields
        .get("fingerprint")
        .ok_or_else(|| CryptError::Format("Bundle missing 'fingerprint'".into()))?;
    if fp_str.len() != 64 || !fp_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptError::Format("Bundle 'fingerprint' must be 64 hex characters".into()));
    }
    let fp = fp_str.to_uppercase();

    let ed_raw = general_purpose::STANDARD
        .decode(
            fields
                .get("ed25519_pub")
                .ok_or_else(|| CryptError::Format("Bundle missing 'ed25519_pub'".into()))?,
        )
        .map_err(|e| CryptError::Format(format!("Invalid bundle ed25519_pub Base64: {}", e)))?;
    let ed_pub: [u8; 32] = ed_raw
        .try_into()
        .map_err(|_| CryptError::Key("Invalid bundle Ed25519 public key length".into()))?;

    let x_raw = general_purpose::STANDARD
        .decode(
            fields
                .get("x25519_pub")
                .ok_or_else(|| CryptError::Format("Bundle missing 'x25519_pub'".into()))?,
        )
        .map_err(|e| CryptError::Format(format!("Invalid bundle x25519_pub Base64: {}", e)))?;
    let x_pub: [u8; 32] = x_raw
        .try_into()
        .map_err(|_| CryptError::Key("Invalid bundle X25519 public key length".into()))?;

    let sig_raw = general_purpose::STANDARD
        .decode(
            fields
                .get("binding_sig")
                .ok_or_else(|| CryptError::Format("Bundle missing 'binding_sig'".into()))?,
        )
        .map_err(|e| CryptError::Format(format!("Invalid bundle binding_sig Base64: {}", e)))?;
    let sig_bytes: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| CryptError::Key("Invalid bundle Ed25519 signature length".into()))?;

    let vk = VerifyingKey::from_bytes(&ed_pub)
        .map_err(|e| CryptError::Key(format!("Invalid Ed25519 public key in bundle: {}", e)))?;
    if vk.is_weak() {
        return Err(CryptError::Key(
            "Refusing to import weak / small-order Ed25519 public key".into(),
        ));
    }
    let actual_fp = compute_fingerprint(&ed_pub);
    if actual_fp != fp {
        return Err(CryptError::Key(format!(
            "Bundle fingerprint mismatch: header claims {}, actual SHA-256 is {}",
            fp, actual_fp
        )));
    }
    if !is_contributory_x25519_pubkey(&x_pub) {
        return Err(CryptError::Key(
            "Refusing to import non-contributory / low-order X25519 public key (L-1)".into(),
        ));
    }

    let payload = build_bundle_signing_payload(&ed_pub, &x_pub);
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&payload, &sig).map_err(|_| {
        CryptError::Crypto(
            "Public key bundle self-signature verification FAILED — X25519 key is not authentically bound to Ed25519 identity"
                .into(),
        )
    })?;

    if let Some(ref lbl) = clean_label {
        let active = scan_keystore(keystore_dir)?;
        if let Some(other) = active.iter().find(|e| {
            e.fingerprint != fp
                && e.label
                    .as_ref()
                    .is_some_and(|existing_lbl| existing_lbl.eq_ignore_ascii_case(lbl))
        }) {
            return Err(CryptError::Key(format!(
                "Label '{}' is already assigned to key {}",
                lbl, other.fingerprint
            )));
        }
    }

    let pub_path = keystore_dir.join(format!("public_{}.asc", fp));
    let x_pub_path = keystore_dir.join(format!("x25519_public_{}.asc", fp));
    let ed_priv_path = keystore_dir.join(format!("private_{}.asc.enc", fp));
    let x_priv_path = keystore_dir.join(format!("x25519_private_{}.asc.enc", fp));
    if (ed_priv_path.exists() || x_priv_path.exists()) && x_pub_path.exists() {
        if let Ok(existing_x_b64) = fs::read_to_string(&x_pub_path) {
            if let Ok(existing_x_bytes) = general_purpose::STANDARD.decode(existing_x_b64.trim()) {
                if existing_x_bytes.as_slice() != x_pub.as_slice() {
                    return Err(CryptError::Key(format!(
                        "Refusing to overwrite local keypair {}'s X25519 public key with a different key while local private key backup exists",
                        fp
                    )));
                }
            }
        }
    }

    preflight_check_output_path(Some(bundle_path), &pub_path, force)?;
    preflight_check_output_path(Some(bundle_path), &x_pub_path, force)?;

    ensure_keystore_dir(keystore_dir)?;
    let had_pub = pub_path.exists();
    let old_pub = if had_pub { fs::read(&pub_path).ok() } else { None };
    let had_x_pub = x_pub_path.exists();
    let old_x_pub = if had_x_pub { fs::read(&x_pub_path).ok() } else { None };

    write_file_strict_with_options(
        &pub_path,
        general_purpose::STANDARD.encode(ed_pub).as_bytes(),
        force,
    )?;
    if let Err(e) = write_file_strict_with_options(
        &x_pub_path,
        general_purpose::STANDARD.encode(x_pub).as_bytes(),
        force,
    ) {
        if let Some(prev) = old_pub {
            let _ = write_file_strict_with_options(&pub_path, &prev, true);
        } else if !had_pub {
            let _ = fs::remove_file(&pub_path);
        }
        return Err(e.into());
    }

    if let Some(ref lbl) = clean_label {
        if let Err(e) = set_key_label(keystore_dir, &fp, Some(lbl)) {
            if let Some(prev) = old_pub {
                let _ = write_file_strict_with_options(&pub_path, &prev, true);
            } else if !had_pub {
                let _ = fs::remove_file(&pub_path);
            }
            if let Some(prev_x) = old_x_pub {
                let _ = write_file_strict_with_options(&x_pub_path, &prev_x, true);
            } else if !had_x_pub {
                let _ = fs::remove_file(&x_pub_path);
            }
            return Err(e);
        }
    }

    Ok(fp)
}

/// 轮换本地密钥对的备份加密口令（同时重加密 Ed25519 与 X25519 私钥，刷新随机 salt/nonce，公钥与指纹保持不变）
pub fn change_keypair_password(
    keystore_dir: &Path,
    selector: &str,
    old_password: &str,
    new_password: &str,
) -> Result<String, CryptError> {
    validate_password_length(new_password)?;

    let entry = find_keyring_entry(keystore_dir, selector)?;
    let ed_enc_path = entry.ed25519_enc_path.as_ref().ok_or_else(|| {
        CryptError::Key(format!(
            "Missing Ed25519 encrypted private key backup for {}",
            entry.display_name()
        ))
    })?;
    let x_enc_path = entry.x25519_enc_path.as_ref().ok_or_else(|| {
        CryptError::Key(format!(
            "Missing X25519 encrypted private key backup for {}",
            entry.display_name()
        ))
    })?;

    let ed_old_raw = fs::read(ed_enc_path)?;
    let x_old_raw = fs::read(x_enc_path)?;

    let ed_blob = unpack_encrypted_blob(&ed_old_raw)
        .map_err(|e| CryptError::Format(format!("Invalid Ed25519 key backup format: {}", e)))?;
    let x_blob = unpack_encrypted_blob(&x_old_raw)
        .map_err(|e| CryptError::Format(format!("Invalid X25519 key backup format: {}", e)))?;

    let ed_aad_map = parse_aad_map(&ed_blob.aad)
        .map_err(|e| CryptError::Format(format!("Invalid Ed25519 key backup AAD: {}", e)))?;
    let x_aad_map = parse_aad_map(&x_blob.aad)
        .map_err(|e| CryptError::Format(format!("Invalid X25519 key backup AAD: {}", e)))?;

    if ed_aad_map.get("type").map(String::as_str) != Some("ed25519")
        || ed_aad_map.get("fp").map(String::as_str) != Some(entry.fingerprint.as_str())
    {
        return Err(CryptError::Key("Ed25519 key backup AAD type/fingerprint mismatch".into()));
    }
    if x_aad_map.get("type").map(String::as_str) != Some("x25519")
        || x_aad_map.get("fp").map(String::as_str) != Some(entry.fingerprint.as_str())
    {
        return Err(CryptError::Key("X25519 key backup AAD type/fingerprint mismatch".into()));
    }

    let old_ed_key = Zeroizing::new(derive_key(
        old_password,
        &ed_blob.salt,
        ed_blob.mem_kib,
        ed_blob.t_cost,
        ed_blob.p_cost,
    )?);
    let ed_plain = Zeroizing::new(decrypt_with_aad(
        &old_ed_key,
        &ed_blob.nonce,
        &ed_blob.ciphertext,
        &ed_blob.aad,
    )?);
    let sk = SigningKey::from_pkcs8_der(&ed_plain)
        .map_err(|e| CryptError::Key(format!("Invalid Ed25519 PKCS#8 DER payload: {}", e)))?;
    if compute_fingerprint(&sk.verifying_key().to_bytes()) != entry.fingerprint {
        return Err(CryptError::Key("Decrypted Ed25519 key does not match fingerprint".into()));
    }

    let old_x_key = Zeroizing::new(derive_key(
        old_password,
        &x_blob.salt,
        x_blob.mem_kib,
        x_blob.t_cost,
        x_blob.p_cost,
    )?);
    let x_plain = Zeroizing::new(decrypt_with_aad(
        &old_x_key,
        &x_blob.nonce,
        &x_blob.ciphertext,
        &x_blob.aad,
    )?);
    if x_plain.len() != 32 {
        return Err(CryptError::Key("Invalid X25519 private key payload length".into()));
    }

    let mem_kib = DEFAULT_ARGON_M_COST_KIB;
    let t_cost = DEFAULT_ARGON_T_COST;
    let p_cost = DEFAULT_ARGON_P_COST;

    let mut new_ed_salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut new_ed_salt);
    let mut new_ed_nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut new_ed_nonce);
    let new_ed_key =
        Zeroizing::new(derive_key(new_password, &new_ed_salt, mem_kib, t_cost, p_cost)?);
    let new_ed_ct = encrypt_with_aad(&new_ed_key, &new_ed_nonce, &ed_plain, &ed_blob.aad)?;
    let new_ed_packed = pack_encrypted_blob(
        mem_kib,
        t_cost,
        p_cost,
        &new_ed_salt,
        &new_ed_nonce,
        &ed_blob.aad,
        &new_ed_ct,
    )?;

    let mut new_x_salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut new_x_salt);
    let mut new_x_nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut new_x_nonce);
    let new_x_key = Zeroizing::new(derive_key(new_password, &new_x_salt, mem_kib, t_cost, p_cost)?);
    let new_x_ct = encrypt_with_aad(&new_x_key, &new_x_nonce, &x_plain, &x_blob.aad)?;
    let new_x_packed = pack_encrypted_blob(
        mem_kib,
        t_cost,
        p_cost,
        &new_x_salt,
        &new_x_nonce,
        &x_blob.aad,
        &new_x_ct,
    )?;

    write_file_strict_with_options(ed_enc_path, &new_ed_packed, true)?;
    if let Err(e) = write_file_strict_with_options(x_enc_path, &new_x_packed, true) {
        let _ = write_file_strict_with_options(ed_enc_path, &ed_old_raw, true);
        return Err(e.into());
    }

    Ok(entry.fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_scan_and_decrypt_keystore_roundtrip() {
        let dir = std::env::temp_dir().join(format!("yacrypt_ks_test_{}", std::process::id()));
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
        assert!(entries[0].label.is_none());
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

    #[test]
    fn labels_bundle_export_import_and_password_rotation_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_ks_bundle_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let alice_ks = dir.join("alice_ks");
        let bob_ks = dir.join("bob_ks");
        let old_pw = "alice-old-pass-123";
        let new_pw = "alice-new-pass-456";

        // 1. Generate with local 0600 label; ensure label is NOT leaked in key files
        let alice = generate_and_store_keys_with_label(&alice_ks, Some(old_pw), Some("alice-work"))
            .unwrap();
        let labels_meta = fs::metadata(alice_ks.join("labels.tsv")).unwrap();
        assert_eq!(labels_meta.permissions().mode() & 0o777, 0o600);
        let raw_ed = fs::read(&alice.enc_path).unwrap();
        assert!(!String::from_utf8_lossy(&raw_ed).contains("alice-work"));

        // Lookup by label and by >=16 hex prefix; <16 hex rejected
        assert_eq!(
            find_keyring_entry(&alice_ks, "ALICE-WORK").unwrap().fingerprint,
            alice.fingerprint
        );
        assert_eq!(
            find_keyring_entry(&alice_ks, &alice.fingerprint[..16]).unwrap().fingerprint,
            alice.fingerprint
        );
        assert!(find_keyring_entry(&alice_ks, &alice.fingerprint[..12]).is_err());

        // 2. Rotate password: wrong old password fails without corrupting; right old password rotates both keys
        assert!(
            change_keypair_password(&alice_ks, "alice-work", "wrong-old-pass-12", new_pw).is_err()
        );
        change_keypair_password(&alice_ks, "alice-work", old_pw, new_pw).unwrap();
        assert!(load_signing_key_with_password(&alice.enc_path, old_pw).is_err());
        assert!(load_signing_key_with_password(&alice.enc_path, new_pw).is_ok());

        // 3. Export signed public key bundle (verify label is NOT leaked in bundle)
        let bundle_path = dir.join("alice_bundle.asc");
        let (exported_fp, _) =
            export_public_key_bundle(&alice_ks, "alice-work", new_pw, Some(&bundle_path), false)
                .unwrap();
        assert_eq!(exported_fp, alice.fingerprint);
        let bundle_str = fs::read_to_string(&bundle_path).unwrap();
        assert!(!bundle_str.contains("alice-work"));

        // 4. Tampering X25519 public key in bundle MUST fail Ed25519 binding signature verification
        let fake_x = general_purpose::STANDARD
            .encode(X25519PublicKey::from(&StaticSecret::from([9u8; 32])).to_bytes());
        let tampered_bundle = dir.join("tampered_bundle.asc");
        let tampered_str = bundle_str
            .lines()
            .map(|l| {
                if l.starts_with("x25519_pub=") {
                    format!("x25519_pub={}", fake_x)
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&tampered_bundle, tampered_str).unwrap();
        let err_tamper =
            import_public_key_bundle(&bob_ks, &tampered_bundle, Some("alice"), false).unwrap_err();
        assert!(err_tamper.to_string().contains("self-signature verification FAILED"));
        assert!(scan_keystore(&bob_ks).unwrap().is_empty());

        // 5. L-1 low-order X25519 key in bundle (even validly self-signed by attacker!) MUST be rejected
        let attacker_sk = SigningKey::from_bytes(&[0x5Au8; 32]);
        let attacker_vk = attacker_sk.verifying_key().to_bytes();
        let attacker_fp = compute_fingerprint(&attacker_vk);
        let zero_x = [0u8; 32];
        let low_payload = build_bundle_signing_payload(&attacker_vk, &zero_x);
        let low_sig = attacker_sk.sign(&low_payload);
        let low_bundle = dir.join("low_order_bundle.asc");
        fs::write(
            &low_bundle,
            format!(
                "{}\nfingerprint={}\ned25519_pub={}\nx25519_pub={}\nbinding_sig={}\n{}\n",
                BUNDLE_HEADER,
                attacker_fp,
                general_purpose::STANDARD.encode(attacker_vk),
                general_purpose::STANDARD.encode(zero_x),
                general_purpose::STANDARD.encode(low_sig.to_bytes()),
                BUNDLE_FOOTER
            ),
        )
        .unwrap();
        let err_l1 = import_public_key_bundle(&bob_ks, &low_bundle, None, false).unwrap_err();
        assert!(err_l1.to_string().contains("low-order"));

        // 6. Valid import into Bob's keystore succeeds and resolves recipient key, but refuses private-key role
        let imported_fp =
            import_public_key_bundle(&bob_ks, &bundle_path, Some("alice"), false).unwrap();
        assert_eq!(imported_fp, alice.fingerprint);
        assert!(resolve_recipient_key_arg(&bob_ks, "alice").is_ok());
        assert!(resolve_decrypt_key_arg(&bob_ks, "alice").is_err());
        assert!(resolve_signing_key_arg(&bob_ks, "alice").is_err());

        // 7. Orphan label cleanup & local keypair desync protection:
        //    - Attempting to force-import a bundle that swaps Alice's X25519 pubkey while Alice's private key exists MUST fail
        let alt_x_bytes = X25519PublicKey::from(&StaticSecret::from([0x33u8; 32])).to_bytes();
        let alice_ed_sk = load_signing_key_with_password(&alice.enc_path, new_pw).unwrap();
        let alice_ed_vk = alice_ed_sk.verifying_key().to_bytes();
        let desync_sig =
            alice_ed_sk.sign(&build_bundle_signing_payload(&alice_ed_vk, &alt_x_bytes));
        let desync_bundle = dir.join("desync_bundle.asc");
        fs::write(
            &desync_bundle,
            format!(
                "{}\nfingerprint={}\ned25519_pub={}\nx25519_pub={}\nbinding_sig={}\n{}\n",
                BUNDLE_HEADER,
                alice.fingerprint,
                general_purpose::STANDARD.encode(alice_ed_vk),
                general_purpose::STANDARD.encode(alt_x_bytes),
                general_purpose::STANDARD.encode(desync_sig.to_bytes()),
                BUNDLE_FOOTER
            ),
        )
        .unwrap();
        assert!(import_public_key_bundle(&alice_ks, &desync_bundle, None, true).is_err());

        //    - Deleting Bob's imported files for "alice" must NOT wedge reusing "alice" on a new keypair
        fs::remove_file(bob_ks.join(format!("public_{}.asc", imported_fp))).unwrap();
        fs::remove_file(bob_ks.join(format!("x25519_public_{}.asc", imported_fp))).unwrap();
        let fresh_alice =
            generate_and_store_keys_with_label(&bob_ks, Some(old_pw), Some("alice")).unwrap();
        assert_eq!(
            find_keyring_entry(&bob_ks, "alice").unwrap().fingerprint,
            fresh_alice.fingerprint
        );

        // 8. Domain separation: SGPGv2 symmetric file MUST be rejected by key backup loaders
        let sym_plain = dir.join("sym_file.txt");
        let sym_enc = dir.join("sym_file.txt.enc");
        fs::write(&sym_plain, b"not a key backup").unwrap();
        crate::file_ops::encrypt_file_symmetric(&sym_plain, old_pw, Some(&sym_enc), false).unwrap();
        assert!(load_signing_key_with_password(&sym_enc, old_pw).is_err());
        assert!(decrypt_backup_with_password(&sym_enc, old_pw, Some(&dir.join("out.der")), false)
            .is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
