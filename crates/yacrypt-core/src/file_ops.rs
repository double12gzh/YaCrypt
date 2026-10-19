/// 文件加密/解密操作模块
use crate::constants::{
    DEFAULT_ARGON_M_COST_KIB, DEFAULT_ARGON_P_COST, DEFAULT_ARGON_T_COST, SALT_LEN, XNONCE_LEN,
};
use crate::crypto::{
    decrypt_with_aad, derive_key, derive_symmetric_key_from_shared_secret, encrypt_with_aad,
    pack_encrypted_blob, pack_pubenc_blob, unpack_encrypted_blob, PubencSignature,
};
use crate::error::CryptError;
use crate::utils::{parse_aad_map, validate_password_length, write_file_strict_with_options};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::OsRng;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::{Zeroize, Zeroizing};

/// 使用 X25519 公钥加密文件（混合加密：X25519 + XChaCha20-Poly1305）
/// 可选地使用 Ed25519 密钥对文件签名，签名将嵌入加密文件格式中，返回输出文件路径
pub fn encrypt_file_with_key(
    input: &Path,
    public_key_path: &Path,
    output: Option<&Path>,
    signing_key: Option<&SigningKey>,
    force: bool,
) -> Result<PathBuf, CryptError> {
    if !input.exists() {
        return Err(CryptError::Crypto(format!("Input file not found: {}", input.display())));
    }
    if !public_key_path.exists() {
        return Err(CryptError::Key(format!(
            "Public key file not found: {}",
            public_key_path.display()
        )));
    }

    // 读取 X25519 公钥文件（Base64 编码）
    let mut pub_file = File::open(public_key_path)?;
    let mut pub_data = String::new();
    pub_file.read_to_string(&mut pub_data)?;
    let pub_data = pub_data.trim();

    // 解码 Base64 公钥
    let pub_bytes = general_purpose::STANDARD
        .decode(pub_data)
        .map_err(|e| CryptError::Key(format!("Failed to decode public key: {}", e)))?;

    if pub_bytes.len() != 32 {
        return Err(CryptError::Key("Invalid X25519 public key length".into()));
    }

    let pub_bytes_array: [u8; 32] =
        pub_bytes.try_into().map_err(|_| CryptError::Key("Invalid public key length".into()))?;
    let recipient_public = X25519PublicKey::from(pub_bytes_array);

    // 读取要加密的文件（使用 Zeroizing 确保明文在任何提前返回路径也被清零 L-3）
    let mut f = File::open(input)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    f.read_to_end(&mut plaintext)?;

    // 如果提供了签名密钥，则对明文签名（签名将嵌入加密文件）
    let signature_data = signing_key.map(|sk| {
        let sig = sk.sign(&plaintext);
        let vk = sk.verifying_key();
        PubencSignature { verifying_key: vk.to_bytes(), signature: sig.to_bytes() }
    });

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

    // 使用 HKDF 从共享密钥派生加密密钥（符合 RFC 5869）
    let sym_key_array = Zeroizing::new(derive_symmetric_key_from_shared_secret(
        &shared_secret_bytes,
        &ephemeral_public_bytes,
        b"yacrypt-file-encryption-v1",
    ));

    // 生成随机 nonce
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    // 构建 AAD（仅绑定安全关键头部字段：flags、临时公钥、签名公钥，防篡改/剥离 M-1）。
    // 不携带任何文件名/身份元数据或其低熵摘要——可被字典还原（2026-10-18 复审收口 M-3）
    let aad_str = if let Some(ref sig) = signature_data {
        format!(
            "flags=01|ephemeral_pub={}|sig_vk={}",
            hex::encode(ephemeral_public_bytes),
            hex::encode(sig.verifying_key)
        )
    } else {
        format!("flags=00|ephemeral_pub={}", hex::encode(ephemeral_public_bytes))
    };
    let aad_bytes = aad_str.as_bytes();

    // 使用 XChaCha20-Poly1305 加密文件
    let ciphertext = encrypt_with_aad(&sym_key_array, &nonce, &plaintext, aad_bytes)?;
    plaintext.zeroize();

    // 使用标准 pubenc 格式打包（含 magic、版本和可选签名）
    let blob = pack_pubenc_blob(
        &ephemeral_public_bytes,
        &nonce,
        aad_bytes,
        &ciphertext,
        signature_data.as_ref(),
    )?;

    // 确定输出路径
    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut path = input.to_path_buf();
            path.set_extension("pubenc");
            path
        }
    };

    // 写入加密文件
    write_file_strict_with_options(&out_path, &blob, force)?;

    Ok(out_path)
}

/// 使用口令直接对称加密文件（Argon2id + XChaCha20-Poly1305，SGPGv1 容器，AAD 绑定 `type=file`）
pub fn encrypt_file_symmetric(
    input: &Path,
    password: &str,
    output: Option<&Path>,
    force: bool,
) -> Result<PathBuf, CryptError> {
    if !input.exists() {
        return Err(CryptError::Crypto(format!("Input file not found: {}", input.display())));
    }
    validate_password_length(password)?;

    let mut f = File::open(input)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    f.read_to_end(&mut plaintext)?;

    let mem_kib = DEFAULT_ARGON_M_COST_KIB;
    let t_cost = DEFAULT_ARGON_T_COST;
    let p_cost = DEFAULT_ARGON_P_COST;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let sym_key = Zeroizing::new(derive_key(password, &salt, mem_kib, t_cost, p_cost)?);
    // AAD 仅绑定 `type=file` 实现与私钥备份 (`type=ed25519` / `type=x25519`) 的严格域分离，不泄漏文件名 (M-3)
    let aad_bytes = b"type=file";
    let ciphertext = encrypt_with_aad(&sym_key, &nonce, &plaintext, aad_bytes)?;
    plaintext.zeroize();

    let blob = pack_encrypted_blob(mem_kib, t_cost, p_cost, &salt, &nonce, aad_bytes, &ciphertext)?;

    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(format!("{}.enc", input.display())),
    };

    write_file_strict_with_options(&out_path, &blob, force)?;

    Ok(out_path)
}

/// 解密使用 `encrypt_file_symmetric` 加密的 `SGPGv1` 对称文件（强制校验 AAD `type=file`）
pub fn decrypt_file_symmetric(
    input: &Path,
    password: &str,
    output: Option<&Path>,
    force: bool,
) -> Result<PathBuf, CryptError> {
    if !input.exists() {
        return Err(CryptError::Crypto(format!("Encrypted file not found: {}", input.display())));
    }

    let mut f = File::open(input)?;
    let mut raw = Vec::new();
    f.read_to_end(&mut raw)?;

    let blob = unpack_encrypted_blob(&raw)?;
    let aad_map = parse_aad_map(&blob.aad)
        .map_err(|e| CryptError::Format(format!("Invalid SGPGv1 AAD: {}", e)))?;

    match aad_map.get("type").map(String::as_str) {
        Some("file") => {}
        Some(other) => {
            return Err(CryptError::Key(format!(
                "Refusing to decrypt key backup (type='{}') as a regular file — use 'decrypt-private-key' instead",
                other
            )));
        }
        None => {
            return Err(CryptError::Format("Missing 'type=file' in SGPGv1 AAD".into()));
        }
    }

    let sym_key =
        Zeroizing::new(derive_key(password, &blob.salt, blob.mem_kib, blob.t_cost, blob.p_cost)?);
    let mut plaintext =
        Zeroizing::new(decrypt_with_aad(&sym_key, &blob.nonce, &blob.ciphertext, &blob.aad)?);

    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut path = input.to_path_buf();
            if path.extension().and_then(|s| s.to_str()) == Some("enc") {
                let file_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| "decrypted".to_owned());
                path.set_file_name(file_name);
            } else {
                path.set_extension("decrypted");
            }
            path
        }
    };

    write_file_strict_with_options(&out_path, &plaintext, force)?;
    plaintext.zeroize();

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
        assert_eq!(enc_path, dir.join("notes.txt.enc"));

        // Ensure no filename is leaked in the blob
        let raw_blob = std::fs::read(&enc_path).unwrap();
        assert!(!String::from_utf8_lossy(&raw_blob).contains("notes.txt"));

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

        // Domain separation: an SGPGv1 key backup (type=ed25519) MUST be rejected by decrypt_file_symmetric
        let ks_dir = dir.join("keystore");
        let keys = crate::keystore::generate_and_store_keys_in_dir(&ks_dir, Some(pw)).unwrap();
        let err = decrypt_file_symmetric(&keys.enc_path, pw, Some(&dir.join("leak.bin")), false)
            .unwrap_err();
        assert!(err.to_string().contains("Refusing to decrypt key backup"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
