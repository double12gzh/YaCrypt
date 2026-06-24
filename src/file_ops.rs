/// 文件加密/解密操作模块
use crate::constants::XNONCE_LEN;
use crate::crypto::{
    derive_symmetric_key_from_shared_secret, encrypt_with_aad, pack_pubenc_blob, PubencSignature,
};
use crate::utils::{escape_aad_field, write_file_strict};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::OsRng;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use std::{fs::File, io::Read, path::Path};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

/// 使用 X25519 公钥加密文件（混合加密：X25519 + XChaCha20-Poly1305）
/// 可选地使用 Ed25519 密钥对文件签名，签名将嵌入加密文件格式中
pub fn cmd_encrypt_file_with_key(
    input: &Path,
    public_key_path: &Path,
    output: Option<&Path>,
    signing_key: Option<&SigningKey>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 验证输入文件存在
    if !input.exists() {
        return Err(format!("Input file not found: {}", input.display()).into());
    }
    if !public_key_path.exists() {
        return Err(format!("Public key file not found: {}", public_key_path.display()).into());
    }

    // 读取 X25519 公钥文件（Base64 编码）
    let mut pub_file = File::open(public_key_path)?;
    let mut pub_data = String::new();
    pub_file.read_to_string(&mut pub_data)?;
    let pub_data = pub_data.trim();

    // 解码 Base64 公钥
    let pub_bytes = general_purpose::STANDARD
        .decode(pub_data)
        .map_err(|e| format!("Failed to decode public key: {}", e))?;

    if pub_bytes.len() != 32 {
        return Err("Invalid X25519 public key length".into());
    }

    // 从字节创建 X25519 公钥
    let pub_bytes_array: [u8; 32] =
        pub_bytes.try_into().map_err(|_| "Invalid public key length")?;
    let recipient_public = X25519PublicKey::from(pub_bytes_array);

    // 读取要加密的文件
    let mut f = File::open(input)?;
    let mut plaintext = Vec::new();
    f.read_to_end(&mut plaintext)?;

    // 如果提供了签名密钥，则对明文签名（签名将嵌入加密文件）
    let signature_data = signing_key.map(|sk| {
        let sig = sk.sign(&plaintext);
        let vk = sk.verifying_key();
        PubencSignature {
            verifying_key: vk.to_bytes(),
            signature: sig.to_bytes(),
        }
    });

    // 生成临时 X25519 密钥对用于密钥交换
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let ephemeral_public_bytes = ephemeral_public.to_bytes();

    // 执行密钥交换，得到共享密钥（EphemeralSecret 在此被消费并自动清零）
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    let mut shared_secret_bytes = *shared_secret.as_bytes();

    // 使用 HKDF 从共享密钥派生加密密钥（符合 RFC 5869）
    let mut sym_key_array = derive_symmetric_key_from_shared_secret(
        &shared_secret_bytes,
        &ephemeral_public_bytes,
        b"yacrypt-file-encryption-v1",
    );

    // 生成随机 nonce
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    // 构建 AAD（包含文件名、临时公钥，以及签名公钥（如果有）用于防篡改）
    let filename = input.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let aad_str = if let Some(ref sig) = signature_data {
        format!(
            "file={}|ephemeral_pub={}|sig_vk={}",
            escape_aad_field(filename),
            hex::encode(ephemeral_public_bytes),
            hex::encode(sig.verifying_key)
        )
    } else {
        format!(
            "file={}|ephemeral_pub={}",
            escape_aad_field(filename),
            hex::encode(ephemeral_public_bytes)
        )
    };
    let aad_bytes = aad_str.as_bytes();

    // 使用 XChaCha20-Poly1305 加密文件
    let ciphertext = encrypt_with_aad(&sym_key_array, &nonce, &plaintext, aad_bytes)?;

    // 立即清理敏感数据（在打包前）
    shared_secret_bytes.zeroize();
    sym_key_array.zeroize();
    plaintext.zeroize();

    // 使用标准 pubenc 格式打包（含 magic、版本和可选签名）
    let blob = pack_pubenc_blob(
        &ephemeral_public_bytes,
        &nonce,
        aad_bytes,
        &ciphertext,
        signature_data.as_ref(),
    );

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
    write_file_strict(&out_path, &blob)?;

    println!("✅ File encrypted with public key: {}", out_path.display());
    Ok(())
}
