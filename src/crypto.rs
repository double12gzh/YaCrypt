/// 加密相关函数模块
use crate::constants::{
    KEY_LEN, MAGIC, MAX_ARGON_M_COST_KIB, MAX_ARGON_P_COST, MAX_ARGON_T_COST, MIN_ARGON_M_COST_KIB,
    PUBENC_FLAG_HAS_SIGNATURE, PUBENC_MAGIC, SALT_LEN, XNONCE_LEN,
};
use crate::error::CryptError;
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// 使用 Argon2id 从密码派生密钥
/// 对参数进行范围验证，防止恶意构造的参数导致 OOM 或 panic
pub fn derive_key(
    password: &str,
    salt: &[u8],
    mem_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; KEY_LEN], CryptError> {
    if salt.len() != SALT_LEN {
        return Err(CryptError::Key(format!(
            "Argon2 salt length {} invalid (expected {})",
            salt.len(),
            SALT_LEN
        )));
    }
    // 验证 Argon2 参数范围，防止恶意 blob 导致 OOM 或过弱参数
    if !(MIN_ARGON_M_COST_KIB..=MAX_ARGON_M_COST_KIB).contains(&mem_kib) {
        return Err(CryptError::Key(format!(
            "Argon2 mem_kib {} out of valid range [{}, {}]",
            mem_kib, MIN_ARGON_M_COST_KIB, MAX_ARGON_M_COST_KIB
        )));
    }
    if t_cost == 0 || t_cost > MAX_ARGON_T_COST {
        return Err(CryptError::Key(format!(
            "Argon2 t_cost {} out of valid range [1, {}]",
            t_cost, MAX_ARGON_T_COST
        )));
    }
    if p_cost == 0 || p_cost > MAX_ARGON_P_COST {
        return Err(CryptError::Key(format!(
            "Argon2 p_cost {} out of valid range [1, {}]",
            p_cost, MAX_ARGON_P_COST
        )));
    }

    let params = Params::new(mem_kib, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|e| CryptError::Key(format!("Invalid Argon2 params: {}", e)))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| CryptError::Key(format!("Argon2 key derivation failed: {}", e)))?;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&out);
    out.zeroize();
    Ok(key)
}

/// File format (binary) — updated to include AAD:
/// MAGIC (6 bytes) "SGPGv1"
/// ARGON2 params: mem_kib (u32 BE), t_cost (u32 BE), p_cost (u32 BE)
/// salt_len (u8), salt (salt_len bytes)
/// nonce_len (u8), nonce (nonce_len bytes)
/// aad_len (u16 BE), aad (aad_len bytes)
/// ciphertext_len (u64 BE), ciphertext bytes
pub fn pack_encrypted_blob(
    argon_mem_kib: u32,
    argon_t: u32,
    argon_p: u32,
    salt: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptError> {
    if salt.len() != SALT_LEN {
        return Err(CryptError::Format(format!(
            "invalid salt length: expected {}, got {}",
            SALT_LEN,
            salt.len()
        )));
    }
    if nonce.len() != XNONCE_LEN {
        return Err(CryptError::Format(format!(
            "invalid nonce length: expected {}, got {}",
            XNONCE_LEN,
            nonce.len()
        )));
    }
    let aad_len = u16::try_from(aad.len())
        .map_err(|_| CryptError::Format("AAD length exceeds maximum of 65535 bytes".into()))?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&argon_mem_kib.to_be_bytes());
    out.extend_from_slice(&argon_t.to_be_bytes());
    out.extend_from_slice(&argon_p.to_be_bytes());
    out.push(salt.len() as u8);
    out.extend_from_slice(salt);
    out.push(nonce.len() as u8);
    out.extend_from_slice(nonce);
    // AAD length as u16 BE
    out.extend_from_slice(&aad_len.to_be_bytes());
    out.extend_from_slice(aad);
    out.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// 解析后的加密 blob 数据
pub struct EncryptedBlob {
    pub mem_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// 解析加密的 blob 文件格式
pub fn unpack_encrypted_blob(data: &[u8]) -> Result<EncryptedBlob, CryptError> {
    let mut idx = 0usize;

    // 检查 magic
    let magic_slice =
        data.get(..MAGIC.len()).ok_or_else(|| CryptError::Format("blob too small".into()))?;
    if magic_slice != MAGIC {
        return Err(CryptError::Format("bad magic - invalid file format".into()));
    }
    idx += MAGIC.len();

    // 读取 Argon2 参数
    let params_end =
        idx.checked_add(12).ok_or_else(|| CryptError::Format("offset overflow".into()))?;
    let params_bytes = data
        .get(idx..params_end)
        .ok_or_else(|| CryptError::Format("blob missing Argon2 params".into()))?;
    let mem_kib =
        u32::from_be_bytes([params_bytes[0], params_bytes[1], params_bytes[2], params_bytes[3]]);
    let t_cost =
        u32::from_be_bytes([params_bytes[4], params_bytes[5], params_bytes[6], params_bytes[7]]);
    let p_cost =
        u32::from_be_bytes([params_bytes[8], params_bytes[9], params_bytes[10], params_bytes[11]]);
    idx = params_end;

    // 读取 salt
    let salt_len =
        *data.get(idx).ok_or_else(|| CryptError::Format("missing salt length".into()))? as usize;
    idx += 1;
    if salt_len != SALT_LEN {
        return Err(CryptError::Format(format!(
            "invalid salt length: expected {}, got {}",
            SALT_LEN, salt_len
        )));
    }
    let salt_end = idx
        .checked_add(salt_len)
        .ok_or_else(|| CryptError::Format("salt length overflow".into()))?;
    let salt = data
        .get(idx..salt_end)
        .ok_or_else(|| CryptError::Format("missing salt bytes".into()))?
        .to_vec();
    idx = salt_end;

    // 读取 nonce
    let nonce_len =
        *data.get(idx).ok_or_else(|| CryptError::Format("missing nonce length".into()))? as usize;
    idx += 1;
    if nonce_len != XNONCE_LEN {
        return Err(CryptError::Format(format!(
            "invalid nonce length: expected {}, got {}",
            XNONCE_LEN, nonce_len
        )));
    }
    let nonce_end = idx
        .checked_add(nonce_len)
        .ok_or_else(|| CryptError::Format("nonce length overflow".into()))?;
    let nonce = data
        .get(idx..nonce_end)
        .ok_or_else(|| CryptError::Format("missing nonce bytes".into()))?
        .to_vec();
    idx = nonce_end;

    // 读取 AAD
    let aad_len_end = idx
        .checked_add(2)
        .ok_or_else(|| CryptError::Format("AAD length offset overflow".into()))?;
    let aad_len_bytes = data
        .get(idx..aad_len_end)
        .ok_or_else(|| CryptError::Format("missing AAD length".into()))?;
    let aad_len = u16::from_be_bytes([aad_len_bytes[0], aad_len_bytes[1]]) as usize;
    idx = aad_len_end;
    let aad_end =
        idx.checked_add(aad_len).ok_or_else(|| CryptError::Format("AAD length overflow".into()))?;
    let aad = data
        .get(idx..aad_end)
        .ok_or_else(|| CryptError::Format("missing AAD bytes".into()))?
        .to_vec();
    idx = aad_end;

    // 读取密文
    let ct_len_end = idx
        .checked_add(8)
        .ok_or_else(|| CryptError::Format("ciphertext length offset overflow".into()))?;
    let ct_len_bytes = data
        .get(idx..ct_len_end)
        .ok_or_else(|| CryptError::Format("missing ciphertext length".into()))?;
    let ct_len_u64 = u64::from_be_bytes([
        ct_len_bytes[0],
        ct_len_bytes[1],
        ct_len_bytes[2],
        ct_len_bytes[3],
        ct_len_bytes[4],
        ct_len_bytes[5],
        ct_len_bytes[6],
        ct_len_bytes[7],
    ]);
    let ct_len = usize::try_from(ct_len_u64)
        .map_err(|_| CryptError::Format("ciphertext length overflow".into()))?;
    idx = ct_len_end;

    let ct_end = idx
        .checked_add(ct_len)
        .ok_or_else(|| CryptError::Format("ciphertext length overflow".into()))?;
    let ct = data
        .get(idx..ct_end)
        .ok_or_else(|| CryptError::Format("missing ciphertext bytes".into()))?
        .to_vec();
    idx = ct_end;

    if idx != data.len() {
        return Err(CryptError::Format("unexpected trailing bytes in encrypted blob".into()));
    }

    Ok(EncryptedBlob { mem_kib, t_cost, p_cost, salt, nonce, aad, ciphertext: ct })
}

/// 使用 XChaCha20-Poly1305 加密数据
pub fn encrypt_with_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptError> {
    if nonce.len() != XNONCE_LEN {
        return Err(CryptError::Crypto(format!(
            "Invalid nonce length: expected {}, got {}",
            XNONCE_LEN,
            nonce.len()
        )));
    }
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(xnonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
        .map_err(|e| CryptError::Crypto(format!("Encryption failed: {}", e)))
}

/// 使用 XChaCha20-Poly1305 解密数据
pub fn decrypt_with_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptError> {
    if nonce.len() != XNONCE_LEN {
        return Err(CryptError::Crypto(format!(
            "Invalid nonce length: expected {}, got {}",
            XNONCE_LEN,
            nonce.len()
        )));
    }
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    cipher.decrypt(xnonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad }).map_err(|_| {
        CryptError::Crypto("Decryption failed — wrong password or file tampered".into())
    })
}

/// 使用 HKDF 从 X25519 共享密钥派生对称加密密钥
pub fn derive_symmetric_key_from_shared_secret(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm).expect("HKDF expansion should succeed");
    okm
}

/// pubenc 文件中嵌入的签名数据
pub struct PubencSignature {
    pub verifying_key: [u8; 32],
    pub signature: [u8; 64],
}

/// 解析后的 pubenc 文件数据
pub struct UnpackedPubenc {
    pub ephemeral_pub: [u8; 32],
    pub nonce: [u8; 24],
    pub aad: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: Option<PubencSignature>,
}

/// 打包 pubenc 格式的加密文件
/// 格式: MAGIC(5) + flags(1) + [vk(32)+sig(64)] + ephemeral_pub(32) + nonce(24) + aad_len(2) + aad + ct_len(8) + ct
pub fn pack_pubenc_blob(
    ephemeral_pub: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
    signature: Option<&PubencSignature>,
) -> Result<Vec<u8>, CryptError> {
    let aad_len = u16::try_from(aad.len())
        .map_err(|_| CryptError::Format("AAD length exceeds maximum of 65535 bytes".into()))?;

    let mut out = Vec::new();
    out.extend_from_slice(PUBENC_MAGIC);

    let flags = if signature.is_some() { PUBENC_FLAG_HAS_SIGNATURE } else { 0 };
    out.push(flags);

    if let Some(sig) = signature {
        out.extend_from_slice(&sig.verifying_key);
        out.extend_from_slice(&sig.signature);
    }

    out.extend_from_slice(ephemeral_pub);
    out.extend_from_slice(nonce);

    out.extend_from_slice(&aad_len.to_be_bytes());
    out.extend_from_slice(aad);

    out.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    out.extend_from_slice(ciphertext);

    Ok(out)
}

/// 解析 pubenc 格式的加密文件
pub fn unpack_pubenc_blob(data: &[u8]) -> Result<UnpackedPubenc, CryptError> {
    let mut idx = 0usize;

    // 检查 magic
    let magic_slice = data
        .get(..PUBENC_MAGIC.len())
        .ok_or_else(|| CryptError::Format("pubenc blob too small".into()))?;
    if magic_slice != PUBENC_MAGIC {
        return Err(CryptError::Format("bad magic — not a valid pubenc file".into()));
    }
    idx += PUBENC_MAGIC.len();

    // 读取 flags
    let flags = *data.get(idx).ok_or_else(|| CryptError::Format("missing flags byte".into()))?;
    idx += 1;

    if flags & !PUBENC_FLAG_HAS_SIGNATURE != 0 {
        return Err(CryptError::Format(format!("unsupported pubenc flags: 0x{:02x}", flags)));
    }

    // 读取可选的签名数据
    let signature = if flags & PUBENC_FLAG_HAS_SIGNATURE != 0 {
        let sig_end = idx
            .checked_add(32 + 64)
            .ok_or_else(|| CryptError::Format("signature offset overflow".into()))?;
        let sig_slice = data
            .get(idx..sig_end)
            .ok_or_else(|| CryptError::Format("missing signature data".into()))?;
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&sig_slice[..32]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_slice[32..96]);
        idx = sig_end;
        Some(PubencSignature { verifying_key: vk, signature: sig })
    } else {
        None
    };

    // 读取 ephemeral public key
    let eph_end = idx
        .checked_add(32)
        .ok_or_else(|| CryptError::Format("ephemeral key offset overflow".into()))?;
    let eph_slice = data
        .get(idx..eph_end)
        .ok_or_else(|| CryptError::Format("missing ephemeral public key".into()))?;
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(eph_slice);
    idx = eph_end;

    // 读取 nonce
    let nonce_end =
        idx.checked_add(24).ok_or_else(|| CryptError::Format("nonce offset overflow".into()))?;
    let nonce_slice =
        data.get(idx..nonce_end).ok_or_else(|| CryptError::Format("missing nonce".into()))?;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(nonce_slice);
    idx = nonce_end;

    // 读取 AAD
    let aad_len_end = idx
        .checked_add(2)
        .ok_or_else(|| CryptError::Format("AAD length offset overflow".into()))?;
    let aad_len_bytes = data
        .get(idx..aad_len_end)
        .ok_or_else(|| CryptError::Format("missing AAD length".into()))?;
    let aad_len = u16::from_be_bytes([aad_len_bytes[0], aad_len_bytes[1]]) as usize;
    idx = aad_len_end;
    let aad_end =
        idx.checked_add(aad_len).ok_or_else(|| CryptError::Format("AAD length overflow".into()))?;
    let aad = data
        .get(idx..aad_end)
        .ok_or_else(|| CryptError::Format("missing AAD bytes".into()))?
        .to_vec();
    idx = aad_end;

    // 读取密文
    let ct_len_end = idx
        .checked_add(8)
        .ok_or_else(|| CryptError::Format("ciphertext length offset overflow".into()))?;
    let ct_len_bytes = data
        .get(idx..ct_len_end)
        .ok_or_else(|| CryptError::Format("missing ciphertext length".into()))?;
    let ct_len_u64 = u64::from_be_bytes([
        ct_len_bytes[0],
        ct_len_bytes[1],
        ct_len_bytes[2],
        ct_len_bytes[3],
        ct_len_bytes[4],
        ct_len_bytes[5],
        ct_len_bytes[6],
        ct_len_bytes[7],
    ]);
    let ct_len = usize::try_from(ct_len_u64)
        .map_err(|_| CryptError::Format("ciphertext length overflow".into()))?;
    idx = ct_len_end;

    let ct_end = idx
        .checked_add(ct_len)
        .ok_or_else(|| CryptError::Format("ciphertext length overflow".into()))?;
    let ciphertext = data
        .get(idx..ct_end)
        .ok_or_else(|| CryptError::Format("missing ciphertext bytes".into()))?
        .to_vec();
    idx = ct_end;

    if idx != data.len() {
        return Err(CryptError::Format("unexpected trailing bytes in pubenc blob".into()));
    }

    Ok(UnpackedPubenc { ephemeral_pub, nonce, aad, ciphertext, signature })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── derive_key ─────────────────────────────────────

    #[test]
    fn derive_key_roundtrip() {
        let salt = [0xABu8; 16];
        let k1 = derive_key("test-password-1234", &salt, 256, 1, 1).unwrap();
        let k2 = derive_key("test-password-1234", &salt, 256, 1, 1).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), KEY_LEN);

        let k3 = derive_key("different-password-5678", &salt, 256, 1, 1).unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn derive_key_rejects_excessive_mem() {
        let r = derive_key("p", &[0u8; 16], MAX_ARGON_M_COST_KIB + 1, 1, 1);
        assert!(matches!(r, Err(CryptError::Key(_))));
    }

    #[test]
    fn derive_key_rejects_zero_t_cost() {
        assert!(derive_key("p", &[0u8; 16], 256, 0, 1).is_err());
    }

    #[test]
    fn derive_key_rejects_excessive_t_cost() {
        assert!(derive_key("p", &[0u8; 16], 256, MAX_ARGON_T_COST + 1, 1).is_err());
    }

    #[test]
    fn derive_key_rejects_zero_p_cost() {
        assert!(derive_key("p", &[0u8; 16], 256, 1, 0).is_err());
    }

    #[test]
    fn derive_key_rejects_excessive_p_cost() {
        assert!(derive_key("p", &[0u8; 16], 256, 1, MAX_ARGON_P_COST + 1).is_err());
    }

    #[test]
    fn derive_key_rejects_below_min_mem() {
        let r = derive_key("p", &[0u8; 16], MIN_ARGON_M_COST_KIB - 1, 1, 1);
        assert!(matches!(r, Err(CryptError::Key(_))));
    }

    #[test]
    fn derive_key_rejects_invalid_salt_len() {
        let r = derive_key("p", &[0u8; 15], 256, 1, 1);
        assert!(matches!(r, Err(CryptError::Key(_))));
    }

    // ── encrypted blob ─────────────────────────────────

    #[test]
    fn encrypted_blob_roundtrip() {
        let salt = vec![1u8; 16];
        let nonce = vec![2u8; 24];
        let aad = b"name=test|email=t@t.com";
        let ct = vec![3u8; 100];

        let blob = pack_encrypted_blob(65536, 2, 1, &salt, &nonce, aad, &ct).unwrap();
        let p = unpack_encrypted_blob(&blob).unwrap();

        assert_eq!(p.mem_kib, 65536);
        assert_eq!(p.t_cost, 2);
        assert_eq!(p.p_cost, 1);
        assert_eq!(p.salt, salt);
        assert_eq!(p.nonce, nonce);
        assert_eq!(p.aad, aad.to_vec());
        assert_eq!(p.ciphertext, ct);
    }

    #[test]
    fn encrypted_blob_rejects_bad_magic() {
        let r = unpack_encrypted_blob(b"BADMAGrest_of_data_padding_aaaa");
        assert!(matches!(r, Err(CryptError::Format(_))));
    }

    #[test]
    fn encrypted_blob_rejects_empty() {
        assert!(unpack_encrypted_blob(&[]).is_err());
    }

    #[test]
    fn encrypted_blob_rejects_truncated() {
        assert!(unpack_encrypted_blob(MAGIC).is_err());
    }

    #[test]
    fn encrypted_blob_rejects_invalid_nonce_len() {
        // M-2(a): nonce_len = 23 must return Format error, not panic
        let mut raw = Vec::new();
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&256u32.to_be_bytes());
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.push(16);
        raw.extend_from_slice(&[0u8; 16]);
        raw.push(23);
        raw.extend_from_slice(&[0u8; 23]);
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&40u64.to_be_bytes());
        raw.extend_from_slice(&[0u8; 40]);

        assert!(matches!(unpack_encrypted_blob(&raw), Err(CryptError::Format(_))));
    }

    #[test]
    fn encrypted_blob_rejects_overflow_ct_len() {
        // M-2(b): ct_len = u64::MAX must return Format error, not wrap/panic
        let mut raw = Vec::new();
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&256u32.to_be_bytes());
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.push(16);
        raw.extend_from_slice(&[0u8; 16]);
        raw.push(24);
        raw.extend_from_slice(&[0u8; 24]);
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&u64::MAX.to_be_bytes());
        raw.extend_from_slice(b"JUNK");

        assert!(matches!(unpack_encrypted_blob(&raw), Err(CryptError::Format(_))));
    }

    #[test]
    fn encrypted_blob_rejects_trailing_bytes() {
        let mut blob =
            pack_encrypted_blob(256, 1, 1, &[1u8; 16], &[2u8; 24], b"aad", &[3u8; 32]).unwrap();
        blob.push(0xFF);
        assert!(matches!(unpack_encrypted_blob(&blob), Err(CryptError::Format(_))));
    }

    #[test]
    fn pack_encrypted_blob_rejects_oversized_aad() {
        let big_aad = vec![b'A'; 65536];
        let r = pack_encrypted_blob(256, 1, 1, &[1u8; 16], &[2u8; 24], &big_aad, &[3u8; 32]);
        assert!(matches!(r, Err(CryptError::Format(_))));
    }

    // ── pubenc blob ────────────────────────────────────

    #[test]
    fn pubenc_roundtrip_no_sig() {
        let eph = [0xAAu8; 32];
        let nonce = [0xBBu8; 24];
        let aad = b"file=test.txt";
        let ct = vec![0xCCu8; 200];

        let blob = pack_pubenc_blob(&eph, &nonce, aad, &ct, None).unwrap();
        let p = unpack_pubenc_blob(&blob).unwrap();
        assert_eq!(p.ephemeral_pub, eph);
        assert_eq!(p.nonce, nonce);
        assert_eq!(p.ciphertext, ct);
        assert!(p.signature.is_none());
    }

    #[test]
    fn pubenc_roundtrip_with_sig() {
        let eph = [0xAAu8; 32];
        let nonce = [0xBBu8; 24];
        let sig = PubencSignature { verifying_key: [0xDDu8; 32], signature: [0xEEu8; 64] };

        let blob = pack_pubenc_blob(&eph, &nonce, b"aad", &[0xCCu8; 50], Some(&sig)).unwrap();
        let p = unpack_pubenc_blob(&blob).unwrap();
        let ps = p.signature.unwrap();
        assert_eq!(ps.verifying_key, [0xDDu8; 32]);
        assert_eq!(ps.signature, [0xEEu8; 64]);
    }

    #[test]
    fn pubenc_rejects_bad_magic() {
        assert!(matches!(unpack_pubenc_blob(b"WRONG"), Err(CryptError::Format(_))));
    }

    #[test]
    fn pubenc_rejects_overflow_ct_len() {
        // M-2(b): ct_len = u64::MAX must return Format error, not wrap/panic
        let mut raw = Vec::new();
        raw.extend_from_slice(PUBENC_MAGIC);
        raw.push(0x00);
        raw.extend_from_slice(&[0u8; 32]);
        raw.extend_from_slice(&[0u8; 24]);
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&u64::MAX.to_be_bytes());
        raw.extend_from_slice(b"JUNK");

        assert!(matches!(unpack_pubenc_blob(&raw), Err(CryptError::Format(_))));
    }

    #[test]
    fn pubenc_rejects_unknown_flags() {
        let mut blob =
            pack_pubenc_blob(&[0xAAu8; 32], &[0xBBu8; 24], b"aad", &[1u8; 20], None).unwrap();
        blob[PUBENC_MAGIC.len()] = 0x80; // unknown flag bit
        assert!(matches!(unpack_pubenc_blob(&blob), Err(CryptError::Format(_))));
    }

    #[test]
    fn pubenc_rejects_trailing_bytes() {
        let mut blob =
            pack_pubenc_blob(&[0xAAu8; 32], &[0xBBu8; 24], b"aad", &[1u8; 20], None).unwrap();
        blob.push(0x00);
        assert!(matches!(unpack_pubenc_blob(&blob), Err(CryptError::Format(_))));
    }

    #[test]
    fn pack_pubenc_blob_rejects_oversized_aad() {
        let big_aad = vec![b'B'; 65536];
        let r = pack_pubenc_blob(&[0xAAu8; 32], &[0xBBu8; 24], &big_aad, &[1u8; 20], None);
        assert!(matches!(r, Err(CryptError::Format(_))));
    }

    // ── encrypt / decrypt ──────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; KEY_LEN];
        let nonce = [7u8; XNONCE_LEN];
        let pt = b"Hello, secret message!";
        let aad = b"associated-data";

        let ct = encrypt_with_aad(&key, &nonce, pt, aad).unwrap();
        assert_ne!(ct, pt.to_vec());

        let dec = decrypt_with_aad(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(dec, pt.to_vec());
    }

    #[test]
    fn decrypt_with_aad_rejects_invalid_nonce_len() {
        let r = decrypt_with_aad(&[42u8; KEY_LEN], &[7u8; 23], &[0u8; 32], b"a");
        assert!(matches!(r, Err(CryptError::Crypto(_))));
    }

    #[test]
    fn decrypt_fails_wrong_key() {
        let ct = encrypt_with_aad(&[42u8; KEY_LEN], &[7u8; XNONCE_LEN], b"x", b"a").unwrap();
        assert!(decrypt_with_aad(&[99u8; KEY_LEN], &[7u8; XNONCE_LEN], &ct, b"a").is_err());
    }

    #[test]
    fn decrypt_fails_wrong_aad() {
        let key = [42u8; KEY_LEN];
        let nonce = [7u8; XNONCE_LEN];
        let ct = encrypt_with_aad(&key, &nonce, b"x", b"good").unwrap();
        assert!(decrypt_with_aad(&key, &nonce, &ct, b"bad").is_err());
    }

    #[test]
    fn decrypt_fails_tampered_ciphertext() {
        let key = [42u8; KEY_LEN];
        let nonce = [7u8; XNONCE_LEN];
        let mut ct = encrypt_with_aad(&key, &nonce, b"x", b"a").unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt_with_aad(&key, &nonce, &ct, b"a").is_err());
    }

    // ── HKDF ───────────────────────────────────────────

    #[test]
    fn hkdf_deterministic() {
        let s = [0xABu8; 32];
        let k1 = derive_symmetric_key_from_shared_secret(&s, &[0xCDu8; 32], b"info");
        let k2 = derive_symmetric_key_from_shared_secret(&s, &[0xCDu8; 32], b"info");
        assert_eq!(k1, k2);
    }

    #[test]
    fn hkdf_different_info() {
        let s = [0xABu8; 32];
        let k1 = derive_symmetric_key_from_shared_secret(&s, &[0xCDu8; 32], b"A");
        let k2 = derive_symmetric_key_from_shared_secret(&s, &[0xCDu8; 32], b"B");
        assert_ne!(k1, k2);
    }

    // ── Full E2E ───────────────────────────────────────

    #[test]
    fn full_blob_e2e() {
        let pw = "test-password-1234";
        let salt = [0x11u8; SALT_LEN];
        let nonce = [0x22u8; XNONCE_LEN];
        let aad = b"name=Test|email=t@t.com";
        let pt = b"secret key data";

        let key = derive_key(pw, &salt, 256, 1, 1).unwrap();
        let ct = encrypt_with_aad(&key, &nonce, pt, aad).unwrap();
        let blob = pack_encrypted_blob(256, 1, 1, &salt, &nonce, aad, &ct).unwrap();

        let p = unpack_encrypted_blob(&blob).unwrap();
        let k2 = derive_key(pw, &p.salt, p.mem_kib, p.t_cost, p.p_cost).unwrap();
        let dec = decrypt_with_aad(&k2, &p.nonce, &p.ciphertext, &p.aad).unwrap();
        assert_eq!(dec, pt.to_vec());
    }

    #[test]
    fn full_pubenc_e2e() {
        use chacha20poly1305::aead::OsRng;
        use rand::RngCore;
        use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

        let pt = b"Sensitive document";
        let recipient = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = X25519PublicKey::from(&recipient);

        let eph = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = X25519PublicKey::from(&eph);
        let eph_bytes = eph_pub.to_bytes();
        let shared = eph.diffie_hellman(&recipient_pub);
        let sym = derive_symmetric_key_from_shared_secret(
            shared.as_bytes(),
            &eph_bytes,
            b"yacrypt-file-encryption-v1",
        );
        let mut nonce = [0u8; XNONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = encrypt_with_aad(&sym, &nonce, pt, b"aad").unwrap();

        let blob = pack_pubenc_blob(&eph_bytes, &nonce, b"aad", &ct, None).unwrap();
        let p = unpack_pubenc_blob(&blob).unwrap();

        let shared2 = recipient.diffie_hellman(&X25519PublicKey::from(p.ephemeral_pub));
        let sym2 = derive_symmetric_key_from_shared_secret(
            shared2.as_bytes(),
            &p.ephemeral_pub,
            b"yacrypt-file-encryption-v1",
        );
        let dec = decrypt_with_aad(&sym2, &p.nonce, &p.ciphertext, &p.aad).unwrap();
        assert_eq!(dec, pt.to_vec());
    }
}
