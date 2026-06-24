/// 工作流模块
use crate::crypto::{derive_symmetric_key_from_shared_secret, unpack_pubenc_blob};
use crate::file_ops::cmd_encrypt_file_with_key;
use crate::keystore::generate_and_store_keys;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::{io::Read, path::Path};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

/// 完整的加密流程：生成密钥对 -> 加密密钥 -> 签名并加密文件
/// 如果提供了 existing_key，则跳过密钥生成，直接使用已有公钥加密（不签名）
pub fn cmd_encrypt_workflow(
    input: &Path,
    name: &str,
    email: &str,
    output: Option<&Path>,
    existing_key: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 验证输入文件存在
    if !input.exists() {
        return Err(format!("Input file not found: {}", input.display()).into());
    }

    if let Some(key_path) = existing_key {
        // P2-12: 复用已有密钥，跳过密钥生成
        if !key_path.exists() {
            return Err(format!("Public key file not found: {}", key_path.display()).into());
        }
        println!("🔐 Encrypting file with existing key: {}", key_path.display());
        cmd_encrypt_file_with_key(input, key_path, output, None)?;

        let out_path = match output {
            Some(p) => p.to_path_buf(),
            None => {
                let mut p = input.to_path_buf();
                p.set_extension("pubenc");
                p
            }
        };

        // 生成解密说明文件
        let decrypt_instructions = format!(
            "Decryption Instructions\n\
            =======================\n\n\
            Encrypted file: {enc}\n\
            Encrypted with key: {key}\n\n\
            To decrypt this file, run:\n\n\
              yacrypt decrypt {enc} \\\n\
                  --private-key <corresponding x25519_private_*.asc.enc>\n\n\
            You will be prompted for the encryption password.\n\n\
            Note: This file was encrypted without a signature.\n",
            enc = out_path.display(),
            key = key_path.display(),
        );
        let instr_path = {
            let mut p = out_path.clone();
            let new_ext = format!(
                "{}.decrypt.txt",
                p.extension().and_then(|s| s.to_str()).unwrap_or("")
            );
            p.set_extension(new_ext);
            p
        };
        crate::utils::write_file_strict(&instr_path, decrypt_instructions.as_bytes())?;

        println!("✅ File encrypted (no signature — use full workflow for signed encryption)");
        println!();
        println!("📋 To decrypt, you need the corresponding encrypted private key:");
        println!("   yacrypt decrypt {} --private-key <x25519_private_*.asc.enc>", out_path.display());
        println!();
        println!("📄 Decryption instructions saved to: {}", instr_path.display());
    } else {
        // 完整工作流：生成密钥 + 签名 + 加密
        println!("🔐 Step 1/2: Generating keypair and encrypting keys...");
        let keys = generate_and_store_keys(name, email)?;

        println!("✅ Keys generated and encrypted. Fingerprint: {}", keys.fingerprint);
        println!("🔐 Step 2/2: Signing and encrypting file...");

        cmd_encrypt_file_with_key(input, &keys.x25519_pub_path, output, Some(&keys.signing_key))?;

        let out_path = match output {
            Some(p) => p.to_path_buf(),
            None => {
                let mut p = input.to_path_buf();
                p.set_extension("pubenc");
                p
            }
        };

        // 生成解密说明文件
        let decrypt_instructions = format!(
            "Decryption Instructions\n\
            =======================\n\n\
            Encrypted file: {enc}\n\
            Fingerprint:    {fp}\n\
            Private key:    {priv_key}\n\n\
            To decrypt this file, run:\n\n\
              yacrypt decrypt {enc} \\\n\
                  --private-key {priv_key}\n\n\
            You will be prompted for the encryption password\n\
            you set during key generation.\n\n\
            ⚠️  IMPORTANT:\n\
            - Keep your encryption password safe\n\
            - Do NOT store the password with this file\n\
            - The encrypted private key file is also required\n",
            enc = out_path.display(),
            fp = keys.fingerprint,
            priv_key = keys.x25519_enc_path.display(),
        );
        let instr_path = {
            let mut p = out_path.clone();
            let new_ext = format!(
                "{}.decrypt.txt",
                p.extension().and_then(|s| s.to_str()).unwrap_or("")
            );
            p.set_extension(new_ext);
            p
        };
        crate::utils::write_file_strict(&instr_path, decrypt_instructions.as_bytes())?;

        println!("✅ Complete encryption workflow finished!");
        println!();
        println!("📦 Generated files:");
        println!("   - Encrypted file:       {}", out_path.display());
        println!("   - Public key:           {}", keys.x25519_pub_path.display());
        println!("   - Encrypted private key: {}", keys.x25519_enc_path.display());
        println!("   - Fingerprint:          {}", keys.fingerprint);
        println!();
        println!("📋 To decrypt this file, run:");
        println!("   yacrypt decrypt {} \\", out_path.display());
        println!("       --private-key {}", keys.x25519_enc_path.display());
        println!();
        println!("📄 Decryption instructions saved to: {}", instr_path.display());
        println!("⚠️  Keep your encryption password safe! It is required for decryption.");
    }

    Ok(())
}

/// 完整的解密流程：解密密钥 -> 解密文件 -> 验证签名
pub fn cmd_decrypt_workflow(
    input: &Path,
    private_key_path: &Path,
    output: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 验证输入文件存在
    if !input.exists() {
        return Err(format!("Encrypted file not found: {}", input.display()).into());
    }
    if !private_key_path.exists() {
        return Err(format!("Private key file not found: {}", private_key_path.display()).into());
    }

    println!("🔓 Step 1/2: Decrypting private key...");

    // 读取密码
    let pass = dialoguer::Password::new().with_prompt("Enter private key password").interact()?;

    // 读取加密的私钥文件
    let mut key_file = std::fs::File::open(private_key_path)?;
    let mut key_data = Vec::new();
    key_file.read_to_end(&mut key_data)?;

    // 解析私钥 blob（P1-7: 使用 EncryptedBlob 结构体）
    let blob = crate::crypto::unpack_encrypted_blob(&key_data)
        .map_err(|s| format!("Invalid private key blob format: {}", s))?;

    // 派生密钥
    let mut key =
        crate::crypto::derive_key(&pass, &blob.salt, blob.mem_kib, blob.t_cost, blob.p_cost)?;

    // 解密 X25519 私钥
    let mut x25519_secret_bytes =
        crate::crypto::decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad)?;

    if x25519_secret_bytes.len() != 32 {
        x25519_secret_bytes.zeroize();
        return Err("Invalid X25519 private key length".into());
    }

    // 从字节重建 X25519 私钥（立即清零所有中间数据）
    let mut x25519_secret_bytes_array: [u8; 32] =
        x25519_secret_bytes.as_slice().try_into().unwrap();
    x25519_secret_bytes.zeroize();
    let static_secret = StaticSecret::from(x25519_secret_bytes_array);
    x25519_secret_bytes_array.zeroize();

    // 清理密钥相关数据
    key.zeroize();
    let mut pbytes = pass.into_bytes();
    pbytes.zeroize();

    println!("✅ Private key decrypted");
    println!("🔓 Step 2/2: Decrypting and verifying file...");

    // 读取加密的文件
    let mut f = std::fs::File::open(input)?;
    let mut enc_blob = Vec::new();
    f.read_to_end(&mut enc_blob)?;

    // 使用标准格式解析 pubenc 文件（含 magic 验证和可选签名提取）
    let pubenc = unpack_pubenc_blob(&enc_blob)
        .map_err(|s| format!("Invalid pubenc file format: {}", s))?;

    // 将临时公钥转换为 X25519 PublicKey
    let ephemeral_public = X25519PublicKey::from(pubenc.ephemeral_pub);

    // 执行密钥交换
    let shared_secret = static_secret.diffie_hellman(&ephemeral_public);
    let mut shared_secret_bytes = *shared_secret.as_bytes();

    // 使用 HKDF 从共享密钥派生解密密钥（符合 RFC 5869）
    let mut sym_key_array = derive_symmetric_key_from_shared_secret(
        &shared_secret_bytes,
        &pubenc.ephemeral_pub,
        b"yacrypt-file-encryption-v1",
    );

    // 解密
    let mut plaintext = crate::crypto::decrypt_with_aad(
        &sym_key_array,
        &pubenc.nonce,
        &pubenc.ciphertext,
        &pubenc.aad,
    )?;

    // 立即清理对称密钥
    shared_secret_bytes.zeroize();
    sym_key_array.zeroize();

    // 验证签名（必须在写入文件之前，失败则拒绝输出）
    if let Some(ref sig_data) = pubenc.signature {
        let verifying_key = VerifyingKey::from_bytes(&sig_data.verifying_key)
            .map_err(|e| format!("Invalid Ed25519 verifying key in file: {}", e))?;
        let signature = Signature::from_bytes(&sig_data.signature);
        if verifying_key.verify(&plaintext, &signature).is_err() {
            plaintext.zeroize();
            return Err(
                "❌ Signature verification FAILED — file may have been tampered with. \
                 Decrypted content NOT written to disk."
                    .into(),
            );
        }
        println!("✅ File signature verified successfully");
    } else {
        println!("ℹ️  No signature embedded in encrypted file, skipping verification");
    }

    // 确定输出路径
    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut path = input.to_path_buf();
            if path.extension().and_then(|s| s.to_str()) == Some("pubenc") {
                path.set_extension("");
            } else {
                path.set_extension("decrypted");
            }
            path
        }
    };

    // 写入解密后的文件（仅在签名验证通过后）
    crate::utils::write_file_strict(&out_path, &plaintext)?;

    // 清理明文
    plaintext.zeroize();

    println!("✅ Complete decryption workflow finished!");
    println!("   - Decrypted file: {}", out_path.display());

    Ok(())
}
