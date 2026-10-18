/// 工作流模块
use crate::crypto::{derive_symmetric_key_from_shared_secret, unpack_pubenc_blob, UnpackedPubenc};
use crate::error::CryptError;
use crate::file_ops::encrypt_file_with_key;
use crate::keystore::{generate_and_store_keys_in_dir, GeneratedKeys};
use crate::utils::{compute_fingerprint, parse_aad_map, write_file_strict_with_options};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// 免密解析 `.pubenc` 文件头部所得的元信息（供 TUI 实时预览与自动私钥匹配）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubencInfo {
    pub has_signature: bool,
    pub signer_fingerprint: Option<String>,
    pub ephemeral_pub_hex: String,
    pub ciphertext_len: usize,
}

/// 复用已有公钥加密的工作流返回结果
pub struct ExistingKeyEncryptOutcome {
    pub encrypted_file: PathBuf,
    pub instructions_file: PathBuf,
    pub instructions_written: bool,
    pub signed_fingerprint: Option<String>,
}

/// 生成新密钥对并加密的工作流返回结果
pub struct NewKeyEncryptOutcome {
    pub encrypted_file: PathBuf,
    pub instructions_file: PathBuf,
    pub instructions_written: bool,
    pub keys: GeneratedKeys,
}

/// 解密与验签工作流返回结果
pub struct DecryptOutcome {
    pub decrypted_file: PathBuf,
    pub verified_signer_fingerprint: Option<String>,
}

/// 免密读取并校验 `.pubenc` 头部结构，返回签名存在性与内嵌签名公钥指纹
pub fn inspect_pubenc_file(path: &Path) -> Result<PubencInfo, CryptError> {
    if !path.exists() {
        return Err(CryptError::Crypto(format!("Encrypted file not found: {}", path.display())));
    }
    let mut f = File::open(path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    let pubenc = unpack_pubenc_blob(&data)?;
    let signer_fingerprint =
        pubenc.signature.as_ref().map(|sig| compute_fingerprint(&sig.verifying_key));

    Ok(PubencInfo {
        has_signature: pubenc.signature.is_some(),
        signer_fingerprint,
        ephemeral_pub_hex: hex::encode(pubenc.ephemeral_pub),
        ciphertext_len: pubenc.ciphertext.len(),
    })
}

/// 使用已有公钥（及可选的已解密签名私钥）执行文件加密并写入 `.decrypt.txt` 说明
pub fn encrypt_workflow_with_existing_key(
    input: &Path,
    key_path: &Path,
    output: Option<&Path>,
    signing_key: Option<&SigningKey>,
    force: bool,
) -> Result<ExistingKeyEncryptOutcome, CryptError> {
    if !input.exists() {
        return Err(CryptError::Crypto(format!("Input file not found: {}", input.display())));
    }
    if !key_path.exists() {
        return Err(CryptError::Key(format!("Public key file not found: {}", key_path.display())));
    }

    let out_path = encrypt_file_with_key(input, key_path, output, signing_key, force)?;

    let signed_fingerprint = signing_key.map(|sk| compute_fingerprint(&sk.verifying_key().to_bytes()));
    let sig_note = match signed_fingerprint {
        Some(ref fp) => format!("Signed with key fingerprint: {}\n", fp),
        None => "Note: This file was encrypted without a signature.\n".to_string(),
    };

    let decrypt_instructions = format!(
        "Decryption Instructions\n\
        =======================\n\n\
        Encrypted file: {enc}\n\
        Encrypted with key: {key}\n\n\
        To decrypt this file, run:\n\n\
          yacrypt decrypt {enc} \\\n\
              --private-key <corresponding x25519_private_*.asc.enc>\n\n\
        You will be prompted for the encryption password.\n\n\
        {sig_note}",
        enc = out_path.display(),
        key = key_path.display(),
        sig_note = sig_note,
    );
    let instr_path = {
        let mut p = out_path.clone();
        let new_ext =
            format!("{}.decrypt.txt", p.extension().and_then(|s| s.to_str()).unwrap_or(""));
        p.set_extension(new_ext);
        p
    };
    let instructions_written =
        write_file_strict_with_options(&instr_path, decrypt_instructions.as_bytes(), force).is_ok();

    Ok(ExistingKeyEncryptOutcome {
        encrypted_file: out_path,
        instructions_file: instr_path,
        instructions_written,
        signed_fingerprint,
    })
}

/// 生成全新密钥对、签名并加密文件；若步骤 2 文件加密失败则自动回滚新生成的密钥对
pub fn encrypt_workflow_with_new_keys(
    keystore_dir: &Path,
    input: &Path,
    password: Option<&str>,
    output: Option<&Path>,
    force: bool,
) -> Result<NewKeyEncryptOutcome, CryptError> {
    if !input.exists() {
        return Err(CryptError::Crypto(format!("Input file not found: {}", input.display())));
    }

    let keys = generate_and_store_keys_in_dir(keystore_dir, password)?;

    let out_path = match encrypt_file_with_key(
        input,
        &keys.x25519_pub_path,
        output,
        Some(&keys.signing_key),
        force,
    ) {
        Ok(p) => p,
        Err(e) => {
            for p in [
                &keys.pub_path,
                &keys.x25519_pub_path,
                &keys.enc_path,
                &keys.x25519_enc_path,
                &keys.instr_path,
            ] {
                let _ = std::fs::remove_file(p);
            }
            return Err(CryptError::Crypto(format!(
                "{} (the keypair generated by this run was rolled back)",
                e
            )));
        }
    };

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
        let new_ext =
            format!("{}.decrypt.txt", p.extension().and_then(|s| s.to_str()).unwrap_or(""));
        p.set_extension(new_ext);
        p
    };
    let instructions_written =
        write_file_strict_with_options(&instr_path, decrypt_instructions.as_bytes(), force).is_ok();

    Ok(NewKeyEncryptOutcome {
        encrypted_file: out_path,
        instructions_file: instr_path,
        instructions_written,
        keys,
    })
}

/// 解析用户传入的 `--signer` 参数（支持 64 位十六进制指纹或 Ed25519 公钥 `.asc` 文件路径）
pub fn resolve_signer_fingerprint(signer_arg: &str) -> Result<String, CryptError> {
    // 先按 64 位十六进制指纹解析，避免工作目录中与指纹同名的文件遮蔽用户显式指定的信任锚
    let trimmed = signer_arg.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(trimmed.to_uppercase());
    }

    let as_path = Path::new(trimmed);
    if as_path.exists() {
        let mut f = File::open(as_path)?;
        let mut content = String::new();
        f.read_to_string(&mut content)?;
        let bytes = general_purpose::STANDARD
            .decode(content.trim())
            .map_err(|e| CryptError::Key(format!("Failed to decode signer public key file: {}", e)))?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            CryptError::Key("Invalid Ed25519 public key length (expected 32 bytes)".into())
        })?;
        let vk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CryptError::Key(format!("Invalid Ed25519 public key: {}", e)))?;
        return Ok(compute_fingerprint(&vk.to_bytes()));
    }

    Err(CryptError::Key(format!(
        "Invalid --signer value '{}': must be a 64-character hex fingerprint or a path to an Ed25519 public key file",
        signer_arg
    )))
}

/// 校验 `.pubenc` 的 AAD 与头部字段一致性（防签名剥离 M-1），并在写盘前验证 Ed25519 签名与信任锚指纹（H-1）。
/// 返回验证通过的签名者指纹 `Some(fp)`，若文件无签名且允许跳过则返回 `None`。
pub fn verify_pubenc_aad_and_signature(
    pubenc: &UnpackedPubenc,
    plaintext: &[u8],
    trusted_fp: Option<&str>,
    require_signature: bool,
) -> Result<Option<String>, String> {
    let aad_map =
        parse_aad_map(&pubenc.aad).map_err(|e| format!("Invalid pubenc AAD format: {}", e))?;

    // 1. 强制校验 AAD 中的 ephemeral_pub 与二进制头一致
    let expected_eph_hex = hex::encode(pubenc.ephemeral_pub);
    match aad_map.get("ephemeral_pub") {
        Some(eph) if eph.eq_ignore_ascii_case(&expected_eph_hex) => {}
        _ => {
            return Err(
                "❌ Header integrity check FAILED — AAD ephemeral_pub mismatch. Decrypted content NOT written to disk."
                    .into(),
            );
        }
    }

    // 2. 校验签名存在性与 AAD (sig_vk / flags) 一致性，彻底阻断签名剥离降级攻击 (M-1)
    if let Some(ref sig_data) = pubenc.signature {
        if let Some(fl) = aad_map.get("flags") {
            if fl != "01" {
                return Err(
                    "❌ Header integrity check FAILED — AAD flags mismatch for signed file. Decrypted content NOT written to disk."
                        .into(),
                );
            }
        }
        let expected_vk_hex = hex::encode(sig_data.verifying_key);
        match aad_map.get("sig_vk") {
            Some(vk_hex) if vk_hex.eq_ignore_ascii_case(&expected_vk_hex) => {}
            _ => {
                return Err(
                    "❌ Header integrity check FAILED — AAD sig_vk missing or mismatched. Decrypted content NOT written to disk."
                        .into(),
                );
            }
        }

        // 3. 验证 Ed25519 签名本身
        let verifying_key = VerifyingKey::from_bytes(&sig_data.verifying_key)
            .map_err(|e| format!("Invalid Ed25519 verifying key in file: {}", e))?;
        let signature = Signature::from_bytes(&sig_data.signature);
        if verifying_key.verify(plaintext, &signature).is_err() {
            return Err(
                "❌ Signature verification FAILED — file may have been tampered with. Decrypted content NOT written to disk."
                    .into(),
            );
        }

        // 4. 验证签名公钥信任锚指纹 (H-1)
        let actual_fp = compute_fingerprint(&sig_data.verifying_key);
        match trusted_fp {
            Some(expected_fp) if actual_fp.eq_ignore_ascii_case(expected_fp) => Ok(Some(actual_fp)),
            Some(expected_fp) => Err(format!(
                "❌ Signature verification FAILED — untrusted signer fingerprint {} (expected {}). Decrypted content NOT written to disk.",
                actual_fp,
                expected_fp.to_uppercase()
            )),
            None => Err(format!(
                "❌ Signature verification FAILED — no trusted signer anchor available for signer {}. Specify --signer <fingerprint>. Decrypted content NOT written to disk.",
                actual_fp
            )),
        }
    } else {
        // 文件头部 flags 显示无签名：若 AAD 中存在 sig_vk 或 flags=01，说明签名块被剥离！(M-1)
        if aad_map.contains_key("sig_vk") || aad_map.get("flags").map(String::as_str) == Some("01")
        {
            return Err(
                "❌ Signature stripped — AAD indicates file was signed, but signature block is missing! Decrypted content NOT written to disk."
                    .into(),
            );
        }

        if require_signature {
            return Err(
                "❌ Signature verification FAILED — file has no embedded signature, but signature verification was required. Decrypted content NOT written to disk."
                    .into(),
            );
        }

        Ok(None)
    }
}

/// 完整的解密与验签流程（接收已获取的私钥口令，严格执行先验签后落盘）
pub fn decrypt_workflow_with_password(
    input: &Path,
    private_key_path: &Path,
    password: &str,
    output: Option<&Path>,
    signer: Option<&str>,
    require_signature: bool,
    force: bool,
) -> Result<DecryptOutcome, CryptError> {
    if !input.exists() {
        return Err(CryptError::Crypto(format!("Encrypted file not found: {}", input.display())));
    }
    if !private_key_path.exists() {
        return Err(CryptError::Key(format!(
            "Private key file not found: {}",
            private_key_path.display()
        )));
    }

    let explicit_signer_fp = match signer {
        Some(s) => Some(resolve_signer_fingerprint(s)?),
        None => None,
    };

    // 读取加密的私钥文件
    let mut key_file = File::open(private_key_path)?;
    let mut key_data = Vec::new();
    key_file.read_to_end(&mut key_data)?;

    let blob = crate::crypto::unpack_encrypted_blob(&key_data)
        .map_err(|s| CryptError::Format(format!("Invalid private key blob format: {}", s)))?;

    // 解析私钥 AAD，校验密钥类型 (L-5) 并提取配对的 Ed25519 身份指纹作为默认信任锚 (H-1)
    let key_aad_map = parse_aad_map(&blob.aad)
        .map_err(|s| CryptError::Format(format!("Invalid private key AAD: {}", s)))?;
    if key_aad_map.get("type").map(String::as_str) != Some("x25519") {
        return Err(CryptError::Key(
            "Invalid private key type: expected X25519 encryption key (x25519_private_<FP>.asc.enc)"
                .into(),
        ));
    }
    let key_owner_fp = key_aad_map.get("fp").cloned();

    let key = Zeroizing::new(crate::crypto::derive_key(
        password,
        &blob.salt,
        blob.mem_kib,
        blob.t_cost,
        blob.p_cost,
    )?);

    let x25519_secret_bytes = Zeroizing::new(crate::crypto::decrypt_with_aad(
        &key,
        &blob.nonce,
        &blob.ciphertext,
        &blob.aad,
    )?);

    if x25519_secret_bytes.len() != 32 {
        return Err(CryptError::Key("Invalid X25519 private key length".into()));
    }

    let mut x25519_secret_bytes_array: [u8; 32] =
        x25519_secret_bytes.as_slice().try_into().unwrap();
    let static_secret = StaticSecret::from(x25519_secret_bytes_array);
    x25519_secret_bytes_array.zeroize();
    drop(x25519_secret_bytes);
    drop(key);

    // 读取加密的文件
    let mut f = File::open(input)?;
    let mut enc_blob = Vec::new();
    f.read_to_end(&mut enc_blob)?;

    let pubenc = unpack_pubenc_blob(&enc_blob)
        .map_err(|s| CryptError::Format(format!("Invalid pubenc file format: {}", s)))?;

    let ephemeral_public = X25519PublicKey::from(pubenc.ephemeral_pub);

    let shared_secret = static_secret.diffie_hellman(&ephemeral_public);
    if !shared_secret.was_contributory() {
        return Err(CryptError::Crypto(
            "Invalid ephemeral X25519 public key in file (non-contributory / low-order point)"
                .into(),
        ));
    }
    let shared_secret_bytes = Zeroizing::new(*shared_secret.as_bytes());

    let sym_key_array = Zeroizing::new(derive_symmetric_key_from_shared_secret(
        &shared_secret_bytes,
        &pubenc.ephemeral_pub,
        b"yacrypt-file-encryption-v1",
    ));

    let mut plaintext = Zeroizing::new(crate::crypto::decrypt_with_aad(
        &sym_key_array,
        &pubenc.nonce,
        &pubenc.ciphertext,
        &pubenc.aad,
    )?);

    drop(shared_secret_bytes);
    drop(sym_key_array);

    let trusted_fp = explicit_signer_fp.as_deref().or(key_owner_fp.as_deref());
    let must_have_sig = require_signature || explicit_signer_fp.is_some();

    let verified_signer_fingerprint =
        match verify_pubenc_aad_and_signature(&pubenc, &plaintext, trusted_fp, must_have_sig) {
            Ok(fp_opt) => fp_opt,
            Err(err_msg) => {
                plaintext.zeroize();
                return Err(CryptError::Crypto(err_msg));
            }
        };

    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut path = input.to_path_buf();
            if path.extension().and_then(|s| s.to_str()) == Some("pubenc") {
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

    Ok(DecryptOutcome { decrypted_file: out_path, verified_signer_fingerprint })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PubencSignature;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verify_rejects_forged_signer_fingerprint_h1() {
        let eph = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let payload = b"FORGED CONTENT";

        let attacker_sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let attacker_vk = attacker_sk.verifying_key().to_bytes();
        let sig = attacker_sk.sign(payload).to_bytes();

        let aad = format!(
            "flags=01|ephemeral_pub={}|sig_vk={}",
            hex::encode(eph),
            hex::encode(attacker_vk)
        );
        let pubenc = UnpackedPubenc {
            ephemeral_pub: eph,
            nonce,
            aad: aad.into_bytes(),
            ciphertext: vec![],
            signature: Some(PubencSignature { verifying_key: attacker_vk, signature: sig }),
        };

        let victim_fp = "A".repeat(64);
        let res = verify_pubenc_aad_and_signature(&pubenc, payload, Some(&victim_fp), false);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("untrusted signer fingerprint"));

        let attacker_fp = compute_fingerprint(&attacker_vk);
        let ok_res =
            verify_pubenc_aad_and_signature(&pubenc, payload, Some(&attacker_fp), true).unwrap();
        assert_eq!(ok_res, Some(attacker_fp));
    }

    #[test]
    fn verify_rejects_stripped_signature_m1() {
        let eph = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let payload = b"secret document";
        let vk = [0x33u8; 32];

        let aad =
            format!("file=f2.txt|ephemeral_pub={}|sig_vk={}", hex::encode(eph), hex::encode(vk));
        let stripped_pubenc = UnpackedPubenc {
            ephemeral_pub: eph,
            nonce,
            aad: aad.into_bytes(),
            ciphertext: vec![],
            signature: None,
        };

        let res = verify_pubenc_aad_and_signature(&stripped_pubenc, payload, None, false);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Signature stripped"));
    }

    #[test]
    fn verify_rejects_unsigned_when_signature_required() {
        let eph = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let aad = format!("flags=00|ephemeral_pub={}", hex::encode(eph));
        let unsigned_pubenc = UnpackedPubenc {
            ephemeral_pub: eph,
            nonce,
            aad: aad.into_bytes(),
            ciphertext: vec![],
            signature: None,
        };

        assert_eq!(
            verify_pubenc_aad_and_signature(&unsigned_pubenc, b"msg", None, false).unwrap(),
            None
        );
        assert!(verify_pubenc_aad_and_signature(&unsigned_pubenc, b"msg", None, true).is_err());
    }

    #[test]
    fn resolve_signer_fingerprint_prefers_hex_over_path() {
        let upper = "AB".repeat(32);
        assert_eq!(resolve_signer_fingerprint(&upper).unwrap(), upper);
        let lower = "ab".repeat(32);
        assert_eq!(resolve_signer_fingerprint(&lower).unwrap(), upper);
        assert_eq!(resolve_signer_fingerprint(&format!("  {}  ", lower)).unwrap(), upper);
    }

    #[test]
    fn resolve_signer_fingerprint_accepts_pubkey_file_and_rejects_garbage() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_signer_fp_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let sk = SigningKey::from_bytes(&[0x21u8; 32]);
        let vk = sk.verifying_key();
        let pub_path = dir.join("public_test.asc");
        std::fs::write(&pub_path, general_purpose::STANDARD.encode(vk.to_bytes())).unwrap();
        let got = resolve_signer_fingerprint(pub_path.to_str().unwrap()).unwrap();
        assert_eq!(got, compute_fingerprint(&vk.to_bytes()));

        assert!(resolve_signer_fingerprint("not-a-fingerprint").is_err());
        assert!(resolve_signer_fingerprint(&"ZZ".repeat(32)).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_workflow_and_inspect_pubenc_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_wf_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ks_dir = dir.join("keystore");
        let input = dir.join("doc.txt");
        std::fs::write(&input, b"workflow payload").unwrap();

        let pw = "workflow-pass-1234";
        let enc_out =
            encrypt_workflow_with_new_keys(&ks_dir, &input, Some(pw), None, false).unwrap();
        assert!(enc_out.encrypted_file.exists());

        let info = inspect_pubenc_file(&enc_out.encrypted_file).unwrap();
        assert!(info.has_signature);
        assert_eq!(info.signer_fingerprint.as_deref(), Some(enc_out.keys.fingerprint.as_str()));

        let dec_path = dir.join("doc_out.txt");
        let dec_out = decrypt_workflow_with_password(
            &enc_out.encrypted_file,
            &enc_out.keys.x25519_enc_path,
            pw,
            Some(&dec_path),
            None,
            true,
            false,
        )
        .unwrap();
        assert_eq!(dec_out.decrypted_file, dec_path);
        assert_eq!(dec_out.verified_signer_fingerprint, Some(enc_out.keys.fingerprint));
        assert_eq!(std::fs::read(&dec_path).unwrap(), b"workflow payload");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
