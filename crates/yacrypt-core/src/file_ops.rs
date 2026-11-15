/// 文件加密/解密操作模块
use crate::constants::{
    DEFAULT_ARGON_M_COST_KIB, DEFAULT_ARGON_P_COST, DEFAULT_ARGON_T_COST, SALT_LEN, XNONCE_LEN,
};
use crate::crypto::{
    build_pubenc_v2_sig_transcript, decrypt_with_aad, derive_key, derive_pubenc_v2_symmetric_key,
    encrypt_with_aad, pack_encrypted_blob_v2, pack_pubenc_v2_blob, pack_pubenc_v2_inner_payload,
    pad_sgpg_v2_plaintext, unpack_encrypted_blob_any, unpad_sgpg_v2_plaintext, PubencSignature,
};
use crate::error::CryptError;
use crate::keystore::{is_contributory_x25519_pubkey, resolve_keystore_dir, scan_keystore};
use crate::utils::{
    compute_fingerprint, default_decrypt_output_path, default_pubenc_output_path,
    default_symmetric_output_path, open_regular_file_nonblocking, parse_aad_map,
    preflight_check_output_path, validate_password_length, write_file_strict_with_options,
};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::OsRng;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::{Zeroize, Zeroizing};

/// 拦截将 Ed25519 签名公钥（`public_<FP>.asc` 或其重命名副本）误传为 X25519 加密公钥，防止文件被加密到无人持有私钥的曲线点
fn reject_ed25519_pubkey_passed_as_x25519(
    public_key_path: &Path,
    pub_bytes: Option<&[u8; 32]>,
    keystore_dir: Option<&Path>,
) -> Result<(), CryptError> {
    let fname_opt = public_key_path.file_name().and_then(|s| s.to_str());
    let parent_dir = public_key_path.parent().unwrap_or_else(|| Path::new("."));

    if let Some(fname) = fname_opt {
        if let Some(fp_part) = fname.strip_prefix("public_").and_then(|s| s.strip_suffix(".asc")) {
            let suggested = parent_dir.join(format!("x25519_public_{}.asc", fp_part));
            return Err(CryptError::Key(format!(
                "Refusing to encrypt with Ed25519 signing public key '{}'; use the X25519 encryption public key '{}' instead",
                public_key_path.display(),
                suggested.display()
            )));
        }
    }

    if let Some(bytes) = pub_bytes {
        let self_fp = compute_fingerprint(bytes);
        if let Some(fname) = fname_opt {
            if fname.to_uppercase().contains(&self_fp) {
                let suggested = parent_dir.join(format!("x25519_public_{}.asc", self_fp));
                return Err(CryptError::Key(format!(
                    "Refusing to encrypt with Ed25519 signing public key '{}' (SHA-256 matches fingerprint {}); use '{}' instead",
                    public_key_path.display(),
                    self_fp,
                    suggested.display()
                )));
            }
        }

        let sibling_x = parent_dir.join(format!("x25519_public_{}.asc", self_fp));
        let sibling_ed = parent_dir.join(format!("public_{}.asc", self_fp));
        if sibling_x.exists() || sibling_ed.exists() {
            return Err(CryptError::Key(format!(
                "Refusing to encrypt with Ed25519 signing public key '{}' (matches keypair {}); use '{}' instead",
                public_key_path.display(),
                self_fp,
                sibling_x.display()
            )));
        }

        let default_ks = resolve_keystore_dir(keystore_dir);
        for dir_to_check in [keystore_dir, Some(default_ks.as_path())].into_iter().flatten() {
            if let Ok(entries) = scan_keystore(dir_to_check) {
                if let Some(entry) = entries.into_iter().find(|e| e.fingerprint == self_fp) {
                    let hint = entry.x25519_pub_path.unwrap_or_else(|| {
                        dir_to_check.join(format!("x25519_public_{}.asc", self_fp))
                    });
                    return Err(CryptError::Key(format!(
                        "Refusing to encrypt with Ed25519 signing public key '{}' (matches local keyring fingerprint {}); use '{}' instead",
                        public_key_path.display(),
                        self_fp,
                        hint.display()
                    )));
                }
            }
        }
    }

    Ok(())
}

/// 前置校验接收方 X25519 公钥文件（存在性、拒绝误传 Ed25519 公钥/未导入 Bundle、Base64 长度及 L-1 低阶点检查）
pub fn preflight_validate_recipient_pubkey(
    public_key_path: &Path,
    keystore_dir: Option<&Path>,
) -> Result<[u8; 32], CryptError> {
    let (pub_file, _) =
        match open_regular_file_nonblocking(public_key_path, "Public key file not found") {
            Ok(res) => res,
            Err(CryptError::Crypto(msg)) => return Err(CryptError::Key(msg)),
            Err(e) => return Err(e),
        };

    reject_ed25519_pubkey_passed_as_x25519(public_key_path, None, keystore_dir)?;

    const MAX_PUBKEY_BYTES: u64 = 64 * 1024;
    let mut pub_data = String::new();
    pub_file.take(MAX_PUBKEY_BYTES + 1).read_to_string(&mut pub_data).map_err(|e| {
        CryptError::Key(format!("Failed to read public key '{}': {}", public_key_path.display(), e))
    })?;
    if pub_data.len() as u64 > MAX_PUBKEY_BYTES {
        return Err(CryptError::Key(format!(
            "Public key file '{}' exceeds 64 KiB size limit",
            public_key_path.display()
        )));
    }
    let pub_data = pub_data.trim();
    if pub_data.starts_with("-----BEGIN YACRYPT PUBLIC KEY BUNDLE") {
        return Err(CryptError::Key(format!(
            "'{}' is a combined public key bundle; import it first via 'yacrypt key-import {}'",
            public_key_path.display(),
            public_key_path.display()
        )));
    }

    let pub_bytes = general_purpose::STANDARD
        .decode(pub_data)
        .map_err(|e| CryptError::Key(format!("Failed to decode public key: {}", e)))?;

    if pub_bytes.len() != 32 {
        return Err(CryptError::Key("Invalid X25519 public key length".into()));
    }

    let pub_bytes_array: [u8; 32] =
        pub_bytes.try_into().map_err(|_| CryptError::Key("Invalid public key length".into()))?;
    reject_ed25519_pubkey_passed_as_x25519(public_key_path, Some(&pub_bytes_array), keystore_dir)?;

    if !is_contributory_x25519_pubkey(&pub_bytes_array) {
        return Err(CryptError::Key(
            "Invalid recipient X25519 public key (non-contributory / low-order point)".into(),
        ));
    }

    Ok(pub_bytes_array)
}

/// 使用 X25519 公钥加密文件（混合加密：X25519 + XChaCha20-Poly1305）
/// 可选地使用 Ed25519 密钥对文件签名，签名将嵌入加密文件格式中，返回输出文件路径
pub fn encrypt_file_with_key(
    input: &Path,
    public_key_path: &Path,
    output: Option<&Path>,
    signing_key: Option<&SigningKey>,
    force: bool,
) -> Result<PathBuf, CryptError> {
    encrypt_file_with_key_in_dir(input, public_key_path, output, signing_key, force, None)
}

/// 在指定密钥环目录上下文中使用 X25519 公钥加密文件（支持使用自定义 keystore_dir 检测误传的 Ed25519 公钥）
pub fn encrypt_file_with_key_in_dir(
    input: &Path,
    public_key_path: &Path,
    output: Option<&Path>,
    signing_key: Option<&SigningKey>,
    force: bool,
    keystore_dir: Option<&Path>,
) -> Result<PathBuf, CryptError> {
    let (mut f, _) = open_regular_file_nonblocking(input, "Input file not found")?;
    let pub_bytes_array = preflight_validate_recipient_pubkey(public_key_path, keystore_dir)?;

    // 确定输出路径并执行前置冲突与同文件自覆盖预检
    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => default_pubenc_output_path(input),
    };
    preflight_check_output_path(Some(input), &out_path, force)?;

    let recipient_public = X25519PublicKey::from(pub_bytes_array);

    // 读取要加密的文件（使用 Zeroizing 确保明文在任何提前返回路径也被清零 L-3）
    let mut plaintext = Zeroizing::new(Vec::new());
    f.read_to_end(&mut plaintext)?;

    // 生成临时 X25519 密钥对用于密钥交换
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let ephemeral_public_bytes = ephemeral_public.to_bytes();

    // 执行密钥交换，得到共享密钥（EphemeralSecret 在此被消费并自动清零）
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    // 拒绝低阶点/全零共享密钥 (L-1)
    if !shared_secret.was_contributory() {
        return Err(CryptError::Key(
            "Invalid recipient X25519 public key (non-contributory / low-order point)".into(),
        ));
    }
    let shared_secret_bytes = Zeroizing::new(*shared_secret.as_bytes());

    // 若提供了签名密钥，则在内层对绑定了 ephemeral_pub + recipient_pub + SHA256(plaintext) 的转录本签名；
    // 签名与签名者公钥随后一并放入 AEAD 密文内层，彻底阻止外层无密钥的已知明文离线验证与指纹泄漏
    let signature_data = signing_key.map(|sk| {
        let transcript =
            build_pubenc_v2_sig_transcript(&ephemeral_public_bytes, &pub_bytes_array, &plaintext);
        let sig = sk.sign(&*transcript);
        let vk = sk.verifying_key();
        PubencSignature { verifying_key: vk.to_bytes(), signature: sig.to_bytes() }
    });

    // 构建包含内层签名与随机长度混淆填充的加密内层载荷，并立即擦除原始明文
    let mut inner_payload = pack_pubenc_v2_inner_payload(&plaintext, signature_data.as_ref())?;
    plaintext.zeroize();

    // 使用 HKDF 从共享密钥派生与临时公钥、接收者公钥共同绑定的对称加密密钥
    let sym_key_array = Zeroizing::new(derive_pubenc_v2_symmetric_key(
        &shared_secret_bytes,
        &ephemeral_public_bytes,
        &pub_bytes_array,
    ));

    // 生成随机 nonce
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    // 外层 AAD 仅绑定版本与临时公钥，绝不暴露签名存在性、签名者公钥或文件名 (M-3)
    let aad_str = format!("v=2|ephemeral_pub={}", hex::encode(ephemeral_public_bytes));
    let aad_bytes = aad_str.as_bytes();

    // 使用 XChaCha20-Poly1305 加密内层载荷
    let ciphertext = encrypt_with_aad(&sym_key_array, &nonce, &inner_payload, aad_bytes)?;
    inner_payload.zeroize();

    // 使用 SCFv2 格式打包（外层 flags 恒为 0x00，不含任何明文签名字段）
    let blob = pack_pubenc_v2_blob(&ephemeral_public_bytes, &nonce, aad_bytes, &ciphertext)?;

    // 写入加密文件
    write_file_strict_with_options(&out_path, &blob, force)?;

    Ok(out_path)
}

/// 使用口令直接对称加密文件（Argon2id + XChaCha20-Poly1305，SGPGv2 容器，带随机长度混淆填充，AAD 绑定 `type=file|v=2`）
pub fn encrypt_file_symmetric(
    input: &Path,
    password: &str,
    output: Option<&Path>,
    force: bool,
) -> Result<PathBuf, CryptError> {
    let (mut f, _) = open_regular_file_nonblocking(input, "Input file not found")?;
    validate_password_length(password)?;

    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => default_symmetric_output_path(input),
    };
    preflight_check_output_path(Some(input), &out_path, force)?;

    let mut plaintext = Zeroizing::new(Vec::new());
    f.read_to_end(&mut plaintext)?;

    let mut padded_payload = pad_sgpg_v2_plaintext(&plaintext)?;
    plaintext.zeroize();

    let mem_kib = DEFAULT_ARGON_M_COST_KIB;
    let t_cost = DEFAULT_ARGON_T_COST;
    let p_cost = DEFAULT_ARGON_P_COST;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let sym_key = Zeroizing::new(derive_key(password, &salt, mem_kib, t_cost, p_cost)?);
    // AAD 仅绑定 `type=file|v=2` 实现与私钥备份 (`type=ed25519` / `type=x25519`) 的严格域分离，不泄漏文件名 (M-3)
    let aad_bytes = b"type=file|v=2";
    let ciphertext = encrypt_with_aad(&sym_key, &nonce, &padded_payload, aad_bytes)?;
    padded_payload.zeroize();

    let blob =
        pack_encrypted_blob_v2(mem_kib, t_cost, p_cost, &salt, &nonce, aad_bytes, &ciphertext)?;

    write_file_strict_with_options(&out_path, &blob, force)?;

    Ok(out_path)
}

/// 解密使用 `encrypt_file_symmetric` 加密的 `SGPGv2` 或遗留 `SGPGv1` 对称文件（强制校验 AAD `type=file`）
pub fn decrypt_file_symmetric(
    input: &Path,
    password: &str,
    output: Option<&Path>,
    force: bool,
) -> Result<PathBuf, CryptError> {
    let (mut f, _) = open_regular_file_nonblocking(input, "Encrypted file not found")?;

    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => default_decrypt_output_path(input, "enc"),
    };
    preflight_check_output_path(Some(input), &out_path, force)?;

    let mut raw = Vec::new();
    f.read_to_end(&mut raw)?;

    let parsed = unpack_encrypted_blob_any(&raw)?;
    let blob = parsed.blob;
    let aad_map = parse_aad_map(&blob.aad)
        .map_err(|e| CryptError::Format(format!("Invalid SGPGv{} AAD: {}", parsed.version, e)))?;

    match aad_map.get("type").map(String::as_str) {
        Some("file") => {}
        Some(other) => {
            return Err(CryptError::Key(format!(
                "Refusing to decrypt key backup (type='{}') as a regular file — use 'decrypt-private-key' instead",
                other
            )));
        }
        None => {
            return Err(CryptError::Format(format!(
                "Missing 'type=file' in SGPGv{} AAD",
                parsed.version
            )));
        }
    }

    if parsed.version == 2 && aad_map.get("v").map(String::as_str) != Some("2") {
        return Err(CryptError::Format("Missing or mismatched 'v=2' in SGPGv2 AAD".into()));
    }
    if parsed.version == 1 && aad_map.get("v").is_some_and(|v| v != "1") {
        return Err(CryptError::Format("Unexpected format version marker in SGPGv1 AAD".into()));
    }

    let sym_key =
        Zeroizing::new(derive_key(password, &blob.salt, blob.mem_kib, blob.t_cost, blob.p_cost)?);
    let mut inner =
        Zeroizing::new(decrypt_with_aad(&sym_key, &blob.nonce, &blob.ciphertext, &blob.aad)?);

    if parsed.version == 2 {
        let pt_slice = unpad_sgpg_v2_plaintext(&inner)?;
        write_file_strict_with_options(&out_path, pt_slice, force)?;
    } else {
        write_file_strict_with_options(&out_path, &inner, force)?;
    }
    inner.zeroize();

    Ok(out_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_file_encrypt_decrypt_roundtrip_and_domain_separation() {
        let dir = std::env::temp_dir().join(format!("yacrypt_sym_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let input = dir.join("notes.txt");
        std::fs::write(&input, b"symmetric secret payload").unwrap();

        let pw = "symmetric-pass-1234";
        let enc_path = encrypt_file_symmetric(&input, pw, None, false).unwrap();
        assert_eq!(enc_path.parent(), Some(dir.as_path()));
        assert_eq!(enc_path.extension().and_then(|s| s.to_str()), Some("enc"));
        assert!(
            !enc_path.file_name().unwrap().to_string_lossy().contains("notes.txt"),
            "default symmetric output filename must not leak original filename: {:?}",
            enc_path
        );

        // Ensure SGPGv2 magic + padded size hiding + no filename leaked in the blob
        let raw_blob = std::fs::read(&enc_path).unwrap();
        assert!(raw_blob.starts_with(crate::constants::MAGIC_V2));
        assert!(raw_blob.len() > 1024);
        assert!(!String::from_utf8_lossy(&raw_blob).contains("notes.txt"));

        // Empty 0-byte file roundtrips cleanly and still produces >= 1KB padded ciphertext
        let empty_in = dir.join("empty.bin");
        let empty_enc = dir.join("empty.bin.enc");
        let empty_dec = dir.join("empty_out.bin");
        std::fs::write(&empty_in, b"").unwrap();
        encrypt_file_symmetric(&empty_in, pw, Some(&empty_enc), false).unwrap();
        assert!(std::fs::metadata(&empty_enc).unwrap().len() > 1024);
        decrypt_file_symmetric(&empty_enc, pw, Some(&empty_dec), false).unwrap();
        assert_eq!(std::fs::read(&empty_dec).unwrap(), b"");

        // Wrong password fails
        let dec_out = dir.join("notes_out.txt");
        assert!(
            decrypt_file_symmetric(&enc_path, "wrong-password-123", Some(&dec_out), false).is_err()
        );
        assert!(!dec_out.exists());

        // Correct password succeeds
        let got_out = decrypt_file_symmetric(&enc_path, pw, Some(&dec_out), false).unwrap();
        assert_eq!(got_out, dec_out);
        assert_eq!(std::fs::read(&dec_out).unwrap(), b"symmetric secret payload");

        // Backward compatibility: legacy SGPGv1 (unpadded type=file) MUST still decrypt cleanly
        let legacy_salt = [0x44u8; SALT_LEN];
        let legacy_nonce = [0x55u8; XNONCE_LEN];
        let legacy_key = crate::crypto::derive_key(pw, &legacy_salt, 256, 1, 1).unwrap();
        let legacy_ct = crate::crypto::encrypt_with_aad(
            &legacy_key,
            &legacy_nonce,
            b"legacy sgpgv1 content",
            b"type=file",
        )
        .unwrap();
        let legacy_blob = crate::crypto::pack_encrypted_blob(
            256,
            1,
            1,
            &legacy_salt,
            &legacy_nonce,
            b"type=file",
            &legacy_ct,
        )
        .unwrap();
        let legacy_enc = dir.join("legacy.enc");
        let legacy_dec = dir.join("legacy_dec.txt");
        std::fs::write(&legacy_enc, &legacy_blob).unwrap();
        decrypt_file_symmetric(&legacy_enc, pw, Some(&legacy_dec), false).unwrap();
        assert_eq!(std::fs::read(&legacy_dec).unwrap(), b"legacy sgpgv1 content");

        // Domain separation: an SGPGv1 key backup (type=ed25519) MUST be rejected by decrypt_file_symmetric
        let ks_dir = dir.join("keystore");
        let keys = crate::keystore::generate_and_store_keys_in_dir(&ks_dir, Some(pw)).unwrap();
        let err = decrypt_file_symmetric(&keys.enc_path, pw, Some(&dir.join("leak.bin")), false)
            .unwrap_err();
        assert!(err.to_string().contains("Refusing to decrypt key backup"));

        // Public-key encryption writes SCFv2 with flags=0x00 and no plaintext sig_vk / size leak
        let out_pub =
            encrypt_file_with_key(&input, &keys.x25519_pub_path, None, None, false).unwrap();
        let raw_pub = std::fs::read(&out_pub).unwrap();
        assert!(raw_pub.starts_with(crate::constants::PUBENC_V2_MAGIC));
        assert_eq!(raw_pub[5], 0x00);
        assert!(raw_pub.len() > 1024);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_file_with_key_appends_pubenc_and_rejects_ed25519_pubkey() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_ed_guard_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ks_dir = dir.join("keystore");
        let keys =
            crate::keystore::generate_and_store_keys_in_dir(&ks_dir, Some("guard-pass-12345"))
                .unwrap();

        let input = dir.join("report.pdf");
        std::fs::write(&input, b"quarterly numbers").unwrap();

        // 1. Passing public_<FP>.asc directly is rejected and suggests x25519_public_<FP>.asc
        let err_direct =
            encrypt_file_with_key(&input, &keys.pub_path, None, None, false).unwrap_err();
        let msg_direct = err_direct.to_string();
        assert!(msg_direct.contains("Ed25519 signing public key"));
        assert!(msg_direct.contains("x25519_public_"));

        // 2. Copying public_<FP>.asc next to x25519_public_<FP>.asc under an alias name is also caught via SHA-256 match
        let renamed_ed = ks_dir.join("recipient_key.asc");
        std::fs::copy(&keys.pub_path, &renamed_ed).unwrap();
        let err_renamed =
            encrypt_file_with_key(&input, &renamed_ed, None, None, false).unwrap_err();
        assert!(err_renamed.to_string().contains("Ed25519 signing public key"));

        // 3. Valid x25519_public_<FP>.asc generates anonymous <16hex>.pubenc in input dir
        let out = encrypt_file_with_key(&input, &keys.x25519_pub_path, None, None, false).unwrap();
        assert_eq!(out.parent(), Some(dir.as_path()));
        assert_eq!(out.extension().and_then(|s| s.to_str()), Some("pubenc"));
        assert!(
            !out.file_name().unwrap().to_string_lossy().contains("report.pdf"),
            "default pubenc output filename must not leak original filename: {:?}",
            out
        );

        // 4. Same-file self-overwrite is rejected even with force=true
        let err_same =
            encrypt_file_with_key(&input, &keys.x25519_pub_path, Some(&input), None, true)
                .unwrap_err();
        assert!(err_same.to_string().contains("same file inode"));
        assert_eq!(std::fs::read(&input).unwrap(), b"quarterly numbers");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
