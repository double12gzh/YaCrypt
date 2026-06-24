/// 加密相关函数模块
use crate::constants::{
    KEY_LEN, MAGIC, MAX_ARGON_M_COST_KIB, MAX_ARGON_P_COST, MAX_ARGON_T_COST,
    PUBENC_FLAG_HAS_SIGNATURE, PUBENC_MAGIC,
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
    // 验证 Argon2 参数范围，防止恶意 blob 导致 OOM
    if mem_kib > MAX_ARGON_M_COST_KIB {
        return Err(CryptError::Key(format!(
            "Argon2 mem_kib {} exceeds maximum allowed {}",
            mem_kib, MAX_ARGON_M_COST_KIB
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
) -> Vec<u8> {
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
    let aad_len = aad.len() as u16;
    out.extend_from_slice(&aad_len.to_be_bytes());
    out.extend_from_slice(aad);
    out.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
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
    if data.len() < MAGIC.len() {
        return Err(CryptError::Format("blob too small".into()));
    }
    if &data[..MAGIC.len()] != MAGIC {
        return Err(CryptError::Format("bad magic - invalid file format".into()));
    }
    idx += MAGIC.len();

    // 读取 Argon2 参数
    if data.len() < idx + 12 {
        return Err(CryptError::Format("blob missing Argon2 params".into()));
    }
    let mem_kib = u32::from_be_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);
    idx += 4;
    let t_cost = u32::from_be_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);
    idx += 4;
    let p_cost = u32::from_be_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);
    idx += 4;

    // 读取 salt
    if data.len() < idx + 1 {
        return Err(CryptError::Format("missing salt length".into()));
    }
    let salt_len = data[idx] as usize;
    idx += 1;
    if data.len() < idx + salt_len {
        return Err(CryptError::Format("missing salt bytes".into()));
    }
    let salt = data[idx..idx + salt_len].to_vec();
    idx += salt_len;

    // 读取 nonce
    if data.len() < idx + 1 {
        return Err(CryptError::Format("missing nonce length".into()));
    }
    let nonce_len = data[idx] as usize;
    idx += 1;
    if data.len() < idx + nonce_len {
        return Err(CryptError::Format("missing nonce bytes".into()));
    }
    let nonce = data[idx..idx + nonce_len].to_vec();
    idx += nonce_len;

    // 读取 AAD
    if data.len() < idx + 2 {
        return Err(CryptError::Format("missing AAD length".into()));
    }
    let aad_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
    idx += 2;
    if data.len() < idx + aad_len {
        return Err(CryptError::Format("missing AAD bytes".into()));
    }
    let aad = data[idx..idx + aad_len].to_vec();
    idx += aad_len;

    // 读取密文
    if data.len() < idx + 8 {
        return Err(CryptError::Format("missing ciphertext length".into()));
    }
    let ct_len = u64::from_be_bytes([
        data[idx],
        data[idx + 1],
        data[idx + 2],
        data[idx + 3],
        data[idx + 4],
        data[idx + 5],
        data[idx + 6],
        data[idx + 7],
    ]) as usize;
    idx += 8;

    if data.len() < idx + ct_len {
        return Err(CryptError::Format("missing ciphertext bytes".into()));
    }
    let ct = data[idx..idx + ct_len].to_vec();

    Ok(EncryptedBlob { mem_kib, t_cost, p_cost, salt, nonce, aad, ciphertext: ct })
}

/// 使用 XChaCha20-Poly1305 加密数据
pub fn encrypt_with_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptError> {
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
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(xnonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| CryptError::Crypto("Decryption failed — wrong password or file tampered".into()))
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
) -> Vec<u8> {
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

    let aad_len = aad.len() as u16;
    out.extend_from_slice(&aad_len.to_be_bytes());
    out.extend_from_slice(aad);

    out.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    out.extend_from_slice(ciphertext);

    out
}

/// 解析 pubenc 格式的加密文件
pub fn unpack_pubenc_blob(data: &[u8]) -> Result<UnpackedPubenc, CryptError> {
    let mut idx = 0usize;

    // 检查 magic
    if data.len() < PUBENC_MAGIC.len() {
        return Err(CryptError::Format("pubenc blob too small".into()));
    }
    if &data[..PUBENC_MAGIC.len()] != PUBENC_MAGIC {
        return Err(CryptError::Format("bad magic — not a valid pubenc file".into()));
    }
    idx += PUBENC_MAGIC.len();

    // 读取 flags
    if data.len() < idx + 1 {
        return Err(CryptError::Format("missing flags byte".into()));
    }
    let flags = data[idx];
    idx += 1;

    // 读取可选的签名数据
    let signature = if flags & PUBENC_FLAG_HAS_SIGNATURE != 0 {
        if data.len() < idx + 32 + 64 {
            return Err(CryptError::Format("missing signature data".into()));
        }
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&data[idx..idx + 32]);
        idx += 32;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[idx..idx + 64]);
        idx += 64;
        Some(PubencSignature { verifying_key: vk, signature: sig })
    } else {
        None
    };

    // 读取 ephemeral public key
    if data.len() < idx + 32 {
        return Err(CryptError::Format("missing ephemeral public key".into()));
    }
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&data[idx..idx + 32]);
    idx += 32;

    // 读取 nonce
    if data.len() < idx + 24 {
        return Err(CryptError::Format("missing nonce".into()));
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[idx..idx + 24]);
    idx += 24;

    // 读取 AAD
    if data.len() < idx + 2 {
        return Err(CryptError::Format("missing AAD length".into()));
    }
    let aad_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
    idx += 2;
    if data.len() < idx + aad_len {
        return Err(CryptError::Format("missing AAD bytes".into()));
    }
    let aad = data[idx..idx + aad_len].to_vec();
    idx += aad_len;

    // 读取密文
    if data.len() < idx + 8 {
        return Err(CryptError::Format("missing ciphertext length".into()));
    }
    let ct_len = u64::from_be_bytes([
        data[idx],
        data[idx + 1],
        data[idx + 2],
        data[idx + 3],
        data[idx + 4],
        data[idx + 5],
        data[idx + 6],
        data[idx + 7],
    ]) as usize;
    idx += 8;

    if data.len() < idx + ct_len {
        return Err(CryptError::Format("missing ciphertext bytes".into()));
    }
    let ciphertext = data[idx..idx + ct_len].to_vec();

    Ok(UnpackedPubenc { ephemeral_pub, nonce, aad, ciphertext, signature })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;

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

    // ── encrypted blob ─────────────────────────────────

    #[test]
    fn encrypted_blob_roundtrip() {
        let salt = vec![1u8; 16];
        let nonce = vec![2u8; 24];
        let aad = b"name=test|email=t@t.com";
        let ct = vec![3u8; 100];

        let blob = pack_encrypted_blob(65536, 2, 1, &salt, &nonce, aad, &ct);
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

    // ── pubenc blob ────────────────────────────────────

    #[test]
    fn pubenc_roundtrip_no_sig() {
        let eph = [0xAAu8; 32];
        let nonce = [0xBBu8; 24];
        let aad = b"file=test.txt";
        let ct = vec![0xCCu8; 200];

        let blob = pack_pubenc_blob(&eph, &nonce, aad, &ct, None);
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

        let blob = pack_pubenc_blob(&eph, &nonce, b"aad", &[0xCCu8; 50], Some(&sig));
        let p = unpack_pubenc_blob(&blob).unwrap();
        let ps = p.signature.unwrap();
        assert_eq!(ps.verifying_key, [0xDDu8; 32]);
        assert_eq!(ps.signature, [0xEEu8; 64]);
    }

    #[test]
    fn pubenc_rejects_bad_magic() {
        assert!(matches!(unpack_pubenc_blob(b"WRONG"), Err(CryptError::Format(_))));
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
        let blob = pack_encrypted_blob(256, 1, 1, &salt, &nonce, aad, &ct);

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
            shared.as_bytes(), &eph_bytes, b"yacrypt-file-encryption-v1",
        );
        let mut nonce = [0u8; XNONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = encrypt_with_aad(&sym, &nonce, pt, b"aad").unwrap();

        let blob = pack_pubenc_blob(&eph_bytes, &nonce, b"aad", &ct, None);
        let p = unpack_pubenc_blob(&blob).unwrap();

        let shared2 = recipient.diffie_hellman(&X25519PublicKey::from(p.ephemeral_pub));
        let sym2 = derive_symmetric_key_from_shared_secret(
            shared2.as_bytes(), &p.ephemeral_pub, b"yacrypt-file-encryption-v1",
        );
        let dec = decrypt_with_aad(&sym2, &p.nonce, &p.ciphertext, &p.aad).unwrap();
        assert_eq!(dec, pt.to_vec());
    }
}
