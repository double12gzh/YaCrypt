/// 工作流模块
use crate::constants::{
    MAGIC, MAGIC_V2, PUBENC_FLAG_HAS_SIGNATURE, PUBENC_MAGIC, PUBENC_V2_MAGIC, SALT_LEN, XNONCE_LEN,
};
use crate::crypto::{
    build_pubenc_v2_sig_transcript, derive_pubenc_v2_symmetric_key,
    derive_symmetric_key_from_shared_secret, unpack_pubenc_blob, unpack_pubenc_v2_blob,
    unpack_pubenc_v2_inner_payload, PubencSignature, UnpackedPubenc,
};
use crate::error::CryptError;
use crate::file_ops::encrypt_file_with_key_in_dir;
use crate::keystore::{
    generate_and_store_keys_with_label, resolve_keystore_dir, scan_keystore, set_key_label,
    GeneratedKeys,
};
use crate::utils::{
    companion_instructions_path, compute_fingerprint, default_decrypt_output_path,
    default_pubenc_output_path, open_regular_file_nonblocking, parse_aad_map,
    preflight_check_input_file, preflight_check_output_path, write_file_strict_with_options,
};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use std::{
    fs::File,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// 免密解析 `.pubenc` (`SCFv1` / `SCFv2`) 文件头部所得的元信息
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubencInfo {
    pub format_version: u8,
    /// 外层可见签名状态：`SCFv1` 返回 `Some(true/false)`；`SCFv2` 签名隐藏于 AEAD 密文内层，返回 `None`
    pub has_signature: Option<bool>,
    pub signer_fingerprint: Option<String>,
    pub ephemeral_pub_hex: String,
    pub ciphertext_len: usize,
    pub padding_enabled: bool,
}

/// 免密解析 `SGPGv1` / `SGPGv2`（对称加密文件 `.enc` 或加密私钥备份 `.asc.enc`）头部所得的元信息
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgpgInfo {
    pub format_version: u8,
    pub blob_type: Option<String>,
    pub fingerprint: Option<String>,
    pub mem_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub ciphertext_len: usize,
    pub padding_enabled: bool,
}

/// 通用文件免密自检结果（支持 `SCFv1` / `SCFv2` 与 `SGPGv1` / `SGPGv2`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectedFile {
    Pubenc(PubencInfo),
    Sgpg(SgpgInfo),
}

/// 复用已有公钥加密的工作流返回结果
pub struct ExistingKeyEncryptOutcome {
    pub encrypted_file: PathBuf,
    pub instructions_file: PathBuf,
    pub instructions_written: bool,
    pub instructions_skipped: bool,
    pub signed_fingerprint: Option<String>,
}

/// 生成新密钥对并加密的工作流返回结果
pub struct NewKeyEncryptOutcome {
    pub encrypted_file: PathBuf,
    pub instructions_file: PathBuf,
    pub instructions_written: bool,
    pub instructions_skipped: bool,
    pub keys: GeneratedKeys,
}

/// 解密与验签工作流返回结果
#[derive(Debug)]
pub struct DecryptOutcome {
    pub decrypted_file: PathBuf,
    pub verified_signer_fingerprint: Option<String>,
}

fn read_exact_or_format<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    eof_msg: &'static str,
) -> Result<(), CryptError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Err(CryptError::Format(eof_msg.into())),
        Err(e) => Err(CryptError::Io(e)),
    }
}

/// 流式解析 `SCFv1` 头部（已读出前 5 字节 `PUBENC_MAGIC`），不读取密文载荷
fn inspect_pubenc_stream_after_magic(
    f: &mut File,
    file_len: u64,
) -> Result<PubencInfo, CryptError> {
    let mut header_len: u64 = PUBENC_MAGIC.len() as u64;

    let mut flags_buf = [0u8; 1];
    read_exact_or_format(f, &mut flags_buf, "missing flags byte")?;
    header_len += 1;
    let flags = flags_buf[0];
    if flags & !PUBENC_FLAG_HAS_SIGNATURE != 0 {
        return Err(CryptError::Format(format!("unsupported pubenc flags: 0x{:02x}", flags)));
    }

    let (sig_vk, signer_fingerprint) = if flags & PUBENC_FLAG_HAS_SIGNATURE != 0 {
        let mut sig_buf = [0u8; 32 + 64];
        read_exact_or_format(f, &mut sig_buf, "missing signature data")?;
        header_len += 96;
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&sig_buf[..32]);
        let fp = compute_fingerprint(&vk);
        (Some(vk), Some(fp))
    } else {
        (None, None)
    };

    let mut eph_buf = [0u8; 32];
    read_exact_or_format(f, &mut eph_buf, "missing ephemeral public key")?;
    header_len += 32;

    let mut nonce_buf = [0u8; 24];
    read_exact_or_format(f, &mut nonce_buf, "missing nonce")?;
    header_len += 24;

    let mut aad_len_buf = [0u8; 2];
    read_exact_or_format(f, &mut aad_len_buf, "missing AAD length")?;
    header_len += 2;
    let aad_len = u16::from_be_bytes(aad_len_buf) as usize;

    let mut aad = vec![0u8; aad_len];
    read_exact_or_format(f, &mut aad, "missing AAD bytes")?;
    header_len += aad_len as u64;

    let mut ct_len_buf = [0u8; 8];
    read_exact_or_format(f, &mut ct_len_buf, "missing ciphertext length")?;
    header_len += 8;
    let ct_len_u64 = u64::from_be_bytes(ct_len_buf);
    let ciphertext_len = usize::try_from(ct_len_u64)
        .map_err(|_| CryptError::Format("ciphertext length overflow".into()))?;
    if ct_len_u64 < 16 {
        return Err(CryptError::Format("ciphertext shorter than 16-byte Poly1305 tag".into()));
    }

    let expected_total = header_len
        .checked_add(ct_len_u64)
        .ok_or_else(|| CryptError::Format("ciphertext length overflow".into()))?;
    if file_len < expected_total {
        return Err(CryptError::Format("missing ciphertext bytes".into()));
    }
    if file_len > expected_total {
        return Err(CryptError::Format("unexpected trailing bytes in pubenc blob".into()));
    }

    // 免密阶段同步校验 AAD 完整性与签名块一致性，提前拦截 M-1 签名剥离与头部篡改
    let aad_map = parse_aad_map(&aad)
        .map_err(|e| CryptError::Format(format!("Invalid pubenc AAD format: {}", e)))?;
    let expected_eph_hex = hex::encode(eph_buf);
    match aad_map.get("ephemeral_pub") {
        Some(eph) if eph.eq_ignore_ascii_case(&expected_eph_hex) => {}
        _ => {
            return Err(CryptError::Format(
                "❌ Header integrity check FAILED — AAD ephemeral_pub mismatch".into(),
            ));
        }
    }
    if let Some(vk_bytes) = sig_vk {
        if let Some(fl) = aad_map.get("flags") {
            if fl != "01" {
                return Err(CryptError::Format(
                    "❌ Header integrity check FAILED — AAD flags mismatch for signed file".into(),
                ));
            }
        }
        let expected_vk_hex = hex::encode(vk_bytes);
        match aad_map.get("sig_vk") {
            Some(vk_hex) if vk_hex.eq_ignore_ascii_case(&expected_vk_hex) => {}
            _ => {
                return Err(CryptError::Format(
                    "❌ Header integrity check FAILED — AAD sig_vk missing or mismatched".into(),
                ));
            }
        }
    } else if aad_map.contains_key("sig_vk")
        || aad_map.get("flags").map(String::as_str) == Some("01")
    {
        return Err(CryptError::Format(
            "❌ Signature stripped — AAD indicates file was signed, but signature block is missing!"
                .into(),
        ));
    }

    Ok(PubencInfo {
        format_version: 1,
        has_signature: Some(signer_fingerprint.is_some()),
        signer_fingerprint,
        ephemeral_pub_hex: expected_eph_hex,
        ciphertext_len,
        padding_enabled: false,
    })
}

/// 流式解析 `SCFv2` 头部（已读出前 5 字节 `PUBENC_V2_MAGIC`），不读取密文载荷
fn inspect_pubenc_v2_stream_after_magic(
    f: &mut File,
    file_len: u64,
) -> Result<PubencInfo, CryptError> {
    let mut header_len: u64 = PUBENC_V2_MAGIC.len() as u64;

    let mut flags_buf = [0u8; 1];
    read_exact_or_format(f, &mut flags_buf, "missing flags byte")?;
    header_len += 1;
    let flags = flags_buf[0];
    if flags != 0x00 {
        return Err(CryptError::Format(format!("unsupported SCFv2 flags: 0x{:02x}", flags)));
    }

    let mut eph_buf = [0u8; 32];
    read_exact_or_format(f, &mut eph_buf, "missing ephemeral public key")?;
    header_len += 32;

    let mut nonce_buf = [0u8; 24];
    read_exact_or_format(f, &mut nonce_buf, "missing nonce")?;
    header_len += 24;

    let mut aad_len_buf = [0u8; 2];
    read_exact_or_format(f, &mut aad_len_buf, "missing AAD length")?;
    header_len += 2;
    let aad_len = u16::from_be_bytes(aad_len_buf) as usize;

    let mut aad = vec![0u8; aad_len];
    read_exact_or_format(f, &mut aad, "missing AAD bytes")?;
    header_len += aad_len as u64;

    let mut ct_len_buf = [0u8; 8];
    read_exact_or_format(f, &mut ct_len_buf, "missing ciphertext length")?;
    header_len += 8;
    let ct_len_u64 = u64::from_be_bytes(ct_len_buf);
    let ciphertext_len = usize::try_from(ct_len_u64)
        .map_err(|_| CryptError::Format("ciphertext length overflow".into()))?;
    if ct_len_u64 < 16 {
        return Err(CryptError::Format("ciphertext shorter than 16-byte Poly1305 tag".into()));
    }

    let expected_total = header_len
        .checked_add(ct_len_u64)
        .ok_or_else(|| CryptError::Format("ciphertext length overflow".into()))?;
    if file_len < expected_total {
        return Err(CryptError::Format("missing ciphertext bytes".into()));
    }
    if file_len > expected_total {
        return Err(CryptError::Format("unexpected trailing bytes in pubenc blob".into()));
    }

    let aad_map = parse_aad_map(&aad)
        .map_err(|e| CryptError::Format(format!("Invalid SCFv2 AAD format: {}", e)))?;
    if aad_map.get("v").map(String::as_str) != Some("2") {
        return Err(CryptError::Format(
            "❌ Header integrity check FAILED — missing or invalid SCFv2 AAD version".into(),
        ));
    }
    let expected_eph_hex = hex::encode(eph_buf);
    match aad_map.get("ephemeral_pub") {
        Some(eph) if eph.eq_ignore_ascii_case(&expected_eph_hex) => {}
        _ => {
            return Err(CryptError::Format(
                "❌ Header integrity check FAILED — AAD ephemeral_pub mismatch".into(),
            ));
        }
    }
    if aad_map.contains_key("sig_vk") || aad_map.contains_key("flags") {
        return Err(CryptError::Format(
            "❌ Header integrity check FAILED — unexpected plaintext signature field in SCFv2 AAD"
                .into(),
        ));
    }

    Ok(PubencInfo {
        format_version: 2,
        has_signature: None,
        signer_fingerprint: None,
        ephemeral_pub_hex: expected_eph_hex,
        ciphertext_len,
        padding_enabled: true,
    })
}

/// 流式解析 `SGPGv1` / `SGPGv2` 头部（已读出前 6 字节 magic），不读取密文载荷
fn inspect_sgpg_stream_after_magic(
    f: &mut File,
    file_len: u64,
    format_version: u8,
) -> Result<SgpgInfo, CryptError> {
    let mut header_len: u64 = MAGIC.len() as u64;

    let mut params_buf = [0u8; 12];
    read_exact_or_format(f, &mut params_buf, "blob missing Argon2 params")?;
    header_len += 12;
    let mem_kib = u32::from_be_bytes([params_buf[0], params_buf[1], params_buf[2], params_buf[3]]);
    let t_cost = u32::from_be_bytes([params_buf[4], params_buf[5], params_buf[6], params_buf[7]]);
    let p_cost = u32::from_be_bytes([params_buf[8], params_buf[9], params_buf[10], params_buf[11]]);

    let mut salt_len_buf = [0u8; 1];
    read_exact_or_format(f, &mut salt_len_buf, "missing salt length")?;
    header_len += 1;
    let salt_len = salt_len_buf[0] as usize;
    if salt_len != SALT_LEN {
        return Err(CryptError::Format(format!(
            "invalid salt length: expected {}, got {}",
            SALT_LEN, salt_len
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    read_exact_or_format(f, &mut salt, "missing salt bytes")?;
    header_len += SALT_LEN as u64;

    let mut nonce_len_buf = [0u8; 1];
    read_exact_or_format(f, &mut nonce_len_buf, "missing nonce length")?;
    header_len += 1;
    let nonce_len = nonce_len_buf[0] as usize;
    if nonce_len != XNONCE_LEN {
        return Err(CryptError::Format(format!(
            "invalid nonce length: expected {}, got {}",
            XNONCE_LEN, nonce_len
        )));
    }
    let mut nonce = [0u8; XNONCE_LEN];
    read_exact_or_format(f, &mut nonce, "missing nonce bytes")?;
    header_len += XNONCE_LEN as u64;

    let mut aad_len_buf = [0u8; 2];
    read_exact_or_format(f, &mut aad_len_buf, "missing AAD length")?;
    header_len += 2;
    let aad_len = u16::from_be_bytes(aad_len_buf) as usize;

    let mut aad = vec![0u8; aad_len];
    read_exact_or_format(f, &mut aad, "missing AAD bytes")?;
    header_len += aad_len as u64;

    let mut ct_len_buf = [0u8; 8];
    read_exact_or_format(f, &mut ct_len_buf, "missing ciphertext length")?;
    header_len += 8;
    let ct_len_u64 = u64::from_be_bytes(ct_len_buf);
    let ciphertext_len = usize::try_from(ct_len_u64)
        .map_err(|_| CryptError::Format("ciphertext length overflow".into()))?;
    if ct_len_u64 < 16 {
        return Err(CryptError::Format("ciphertext shorter than 16-byte Poly1305 tag".into()));
    }

    let expected_total = header_len
        .checked_add(ct_len_u64)
        .ok_or_else(|| CryptError::Format("ciphertext length overflow".into()))?;
    if file_len < expected_total {
        return Err(CryptError::Format("missing ciphertext bytes".into()));
    }
    if file_len > expected_total {
        return Err(CryptError::Format("unexpected trailing bytes in encrypted blob".into()));
    }

    let aad_map = parse_aad_map(&aad)
        .map_err(|e| CryptError::Format(format!("Invalid SGPGv{} AAD: {}", format_version, e)))?;
    if format_version == 2
        && (aad_map.get("type").map(String::as_str) != Some("file")
            || aad_map.get("v").map(String::as_str) != Some("2"))
    {
        return Err(CryptError::Format("Invalid SGPGv2 AAD: expected 'type=file|v=2'".into()));
    }

    Ok(SgpgInfo {
        format_version,
        blob_type: aad_map.get("type").cloned(),
        fingerprint: aad_map.get("fp").cloned(),
        mem_kib,
        t_cost,
        p_cost,
        ciphertext_len,
        padding_enabled: format_version >= 2,
    })
}

/// 免密流式读取并校验 `.pubenc` (`SCFv1` / `SCFv2`) 头部结构（不读取密文体）
pub fn inspect_pubenc_file(path: &Path) -> Result<PubencInfo, CryptError> {
    let (mut f, file_len) = open_regular_file_nonblocking(path, "Encrypted file not found")?;
    let mut magic_buf = [0u8; 5];
    read_exact_or_format(&mut f, &mut magic_buf, "pubenc blob too small")?;
    if &magic_buf == PUBENC_MAGIC {
        inspect_pubenc_stream_after_magic(&mut f, file_len)
    } else if &magic_buf == PUBENC_V2_MAGIC {
        inspect_pubenc_v2_stream_after_magic(&mut f, file_len)
    } else {
        Err(CryptError::Format("bad magic — not a valid pubenc file".into()))
    }
}

/// 通用流式免密自检：仅读取容器头部与 AAD，结合文件元数据校验截断/尾随字节，避免全量读盘
pub fn inspect_file(path: &Path) -> Result<InspectedFile, CryptError> {
    let (mut f, file_len) = open_regular_file_nonblocking(path, "File not found")?;

    let mut prefix5 = [0u8; 5];
    match f.read_exact(&mut prefix5) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            return Err(CryptError::Format(
                "Unrecognized file magic: expected SCFv1/SCFv2 (.pubenc) or SGPGv1/SGPGv2 (.enc / .asc.enc)"
                    .into(),
            ));
        }
        Err(e) => return Err(CryptError::Io(e)),
    }

    if &prefix5 == PUBENC_MAGIC {
        Ok(InspectedFile::Pubenc(inspect_pubenc_stream_after_magic(&mut f, file_len)?))
    } else if &prefix5 == PUBENC_V2_MAGIC {
        Ok(InspectedFile::Pubenc(inspect_pubenc_v2_stream_after_magic(&mut f, file_len)?))
    } else if prefix5 == MAGIC[..5] {
        let mut sixth = [0u8; 1];
        match f.read_exact(&mut sixth) {
            Ok(()) if sixth[0] == MAGIC[5] => {
                Ok(InspectedFile::Sgpg(inspect_sgpg_stream_after_magic(&mut f, file_len, 1)?))
            }
            Ok(()) if sixth[0] == MAGIC_V2[5] => {
                Ok(InspectedFile::Sgpg(inspect_sgpg_stream_after_magic(&mut f, file_len, 2)?))
            }
            Ok(()) => Err(CryptError::Format(
                "Unrecognized file magic: expected SCFv1/SCFv2 (.pubenc) or SGPGv1/SGPGv2 (.enc / .asc.enc)"
                    .into(),
            )),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => Err(CryptError::Format(
                "Unrecognized file magic: expected SCFv1/SCFv2 (.pubenc) or SGPGv1/SGPGv2 (.enc / .asc.enc)"
                    .into(),
            )),
            Err(e) => Err(CryptError::Io(e)),
        }
    } else {
        Err(CryptError::Format(
            "Unrecognized file magic: expected SCFv1/SCFv2 (.pubenc) or SGPGv1/SGPGv2 (.enc / .asc.enc)".into(),
        ))
    }
}

fn display_file_name_only(path: &Path, fallback: &str) -> String {
    path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| fallback.into())
}

// SECURITY INVARIANT (YC-010): Never emit companion .decrypt.txt plaintext hints by default.
/// 使用已有公钥（及可选的已解密签名私钥）执行文件加密（默认不写入伴生 `.decrypt.txt`）
pub fn encrypt_workflow_with_existing_key(
    input: &Path,
    key_path: &Path,
    output: Option<&Path>,
    signing_key: Option<&SigningKey>,
    force: bool,
) -> Result<ExistingKeyEncryptOutcome, CryptError> {
    encrypt_workflow_with_existing_key_opts(input, key_path, output, signing_key, false, force)
}

/// 使用已有公钥执行文件加密（可控制是否写入伴生 `.decrypt.txt` 说明文件）
pub fn encrypt_workflow_with_existing_key_opts(
    input: &Path,
    key_path: &Path,
    output: Option<&Path>,
    signing_key: Option<&SigningKey>,
    write_instructions: bool,
    force: bool,
) -> Result<ExistingKeyEncryptOutcome, CryptError> {
    encrypt_workflow_with_existing_key_in_dir(
        None,
        input,
        key_path,
        output,
        signing_key,
        write_instructions,
        force,
    )
}

/// 在指定密钥环目录上下文中使用已有公钥执行文件加密
pub fn encrypt_workflow_with_existing_key_in_dir(
    keystore_dir: Option<&Path>,
    input: &Path,
    key_path: &Path,
    output: Option<&Path>,
    signing_key: Option<&SigningKey>,
    write_instructions: bool,
    force: bool,
) -> Result<ExistingKeyEncryptOutcome, CryptError> {
    preflight_check_input_file(input, "Input file not found")?;

    let out_path =
        encrypt_file_with_key_in_dir(input, key_path, output, signing_key, force, keystore_dir)?;

    let signed_fingerprint =
        signing_key.map(|sk| compute_fingerprint(&sk.verifying_key().to_bytes()));
    let sig_note = match signed_fingerprint {
        Some(ref fp) => format!("Signed with key fingerprint: {}\n", fp),
        None => "Note: This file was encrypted without a signature.\n".to_string(),
    };

    let enc_name = display_file_name_only(&out_path, "encrypted.pubenc");
    let key_name = display_file_name_only(key_path, "x25519_public.asc");
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
        enc = enc_name,
        key = key_name,
        sig_note = sig_note,
    );
    let instr_path = companion_instructions_path(&out_path);
    let (instructions_written, instructions_skipped) = if write_instructions {
        (
            write_file_strict_with_options(&instr_path, decrypt_instructions.as_bytes(), force)
                .is_ok(),
            false,
        )
    } else {
        (false, true)
    };

    Ok(ExistingKeyEncryptOutcome {
        encrypted_file: out_path,
        instructions_file: instr_path,
        instructions_written,
        instructions_skipped,
        signed_fingerprint,
    })
}

/// 生成全新密钥对、签名并加密文件（默认不写入伴生 `.decrypt.txt`）；若步骤 2 文件加密失败则自动回滚新生成的密钥对
pub fn encrypt_workflow_with_new_keys(
    keystore_dir: &Path,
    input: &Path,
    password: Option<&str>,
    output: Option<&Path>,
    force: bool,
) -> Result<NewKeyEncryptOutcome, CryptError> {
    encrypt_workflow_with_new_keys_opts(keystore_dir, input, password, output, None, false, force)
}

/// 生成全新密钥对（含可选本地别名）、签名并加密文件；前置预检输出路径，若步骤 2 失败则回滚密钥与别名
pub fn encrypt_workflow_with_new_keys_opts(
    keystore_dir: &Path,
    input: &Path,
    password: Option<&str>,
    output: Option<&Path>,
    label: Option<&str>,
    write_instructions: bool,
    force: bool,
) -> Result<NewKeyEncryptOutcome, CryptError> {
    preflight_check_input_file(input, "Input file not found")?;

    let planned_out = match output {
        Some(p) => p.to_path_buf(),
        None => default_pubenc_output_path(input),
    };
    preflight_check_output_path(Some(input), &planned_out, force)?;

    let keys = generate_and_store_keys_with_label(keystore_dir, password, label)?;

    let out_path = match encrypt_file_with_key_in_dir(
        input,
        &keys.x25519_pub_path,
        Some(planned_out.as_path()),
        Some(&keys.signing_key),
        force,
        Some(keystore_dir),
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
            if label.is_some() {
                let _ = set_key_label(keystore_dir, &keys.fingerprint, None);
            }
            return Err(CryptError::Crypto(format!(
                "{} (the keypair generated by this run was rolled back)",
                e
            )));
        }
    };

    let enc_name = display_file_name_only(&out_path, "encrypted.pubenc");
    let priv_name = display_file_name_only(&keys.x25519_enc_path, "x25519_private.asc.enc");
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
        enc = enc_name,
        fp = keys.fingerprint,
        priv_key = priv_name,
    );
    let instr_path = companion_instructions_path(&out_path);
    let (instructions_written, instructions_skipped) = if write_instructions {
        (
            write_file_strict_with_options(&instr_path, decrypt_instructions.as_bytes(), force)
                .is_ok(),
            false,
        )
    } else {
        (false, true)
    };

    Ok(NewKeyEncryptOutcome {
        encrypted_file: out_path,
        instructions_file: instr_path,
        instructions_written,
        instructions_skipped,
        keys,
    })
}

fn reject_x25519_pubkey_passed_as_signer(
    as_path: &Path,
    key_bytes: Option<&[u8; 32]>,
    keystore_dir: &Path,
) -> Result<(), CryptError> {
    let fname_opt = as_path.file_name().and_then(|s| s.to_str());
    let parent_dir = as_path.parent().unwrap_or_else(|| Path::new("."));

    if let Some(fname) = fname_opt {
        if let Some(rest) = fname.strip_prefix("x25519_public_") {
            let fp_part = rest.strip_suffix(".asc").unwrap_or(rest);
            let suggested = parent_dir.join(format!("public_{}.asc", fp_part));
            return Err(CryptError::Key(format!(
                "Refusing to use X25519 encryption public key '{}' as --signer; provide Ed25519 signing public key '{}' instead",
                as_path.display(),
                suggested.display()
            )));
        }
        if fname.starts_with("x25519_") {
            return Err(CryptError::Key(format!(
                "Refusing to use X25519 key file '{}' as --signer; provide Ed25519 signing public key (public_<FP>.asc) instead",
                as_path.display()
            )));
        }
    }

    if let Some(bytes) = key_bytes {
        // 若文件名为 public_<64位FP>.asc，核对内容 SHA-256 必须与文件名一致（防内容被替换为 X25519 公钥）
        if let Some(fname) = fname_opt {
            if let Some(fp_part) =
                fname.strip_prefix("public_").and_then(|s| s.strip_suffix(".asc"))
            {
                if fp_part.len() == 64 && fp_part.chars().all(|c| c.is_ascii_hexdigit()) {
                    let computed = compute_fingerprint(bytes);
                    if !computed.eq_ignore_ascii_case(fp_part) {
                        return Err(CryptError::Key(format!(
                            "Public key file '{}' content fingerprint ({}) does not match filename fingerprint ({})",
                            as_path.display(),
                            computed,
                            fp_part.to_uppercase()
                        )));
                    }
                }
            }
        }

        // 比对同目录或本地 keystore 中的 x25519_public_*.asc，拦截重命名后的 X25519 公钥
        for dir_to_check in [Some(parent_dir), Some(keystore_dir)].into_iter().flatten() {
            if let Ok(entries) = scan_keystore(dir_to_check) {
                for entry in entries {
                    if let Some(ref x_path) = entry.x25519_pub_path {
                        if let Ok(x_b64) = std::fs::read_to_string(x_path) {
                            if let Ok(x_raw) = general_purpose::STANDARD.decode(x_b64.trim()) {
                                if x_raw.as_slice() == bytes.as_slice() {
                                    let suggested = entry.ed25519_pub_path.unwrap_or_else(|| {
                                        dir_to_check
                                            .join(format!("public_{}.asc", entry.fingerprint))
                                    });
                                    return Err(CryptError::Key(format!(
                                        "Refusing to use X25519 encryption public key '{}' as --signer; provide Ed25519 signing public key '{}' instead",
                                        as_path.display(),
                                        suggested.display()
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// 解析用户传入的 `--signer` 参数（支持完整 64 位十六进制指纹、Ed25519 公钥 `.asc` 路径或本地别名；拒绝短 hex 前缀与 `x25519_public_*.asc`）
pub fn resolve_signer_fingerprint_in_dir(
    signer_arg: &str,
    keystore_dir: &Path,
) -> Result<String, CryptError> {
    // 先按完整 64 位十六进制指纹解析，避免工作目录中同名文件遮蔽显式信任锚
    let trimmed = signer_arg.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(trimmed.to_uppercase());
    }

    let as_path = Path::new(trimmed);
    match open_regular_file_nonblocking(as_path, "Signer key file not found") {
        Ok((f, _)) => {
            reject_x25519_pubkey_passed_as_signer(as_path, None, keystore_dir)?;
            const MAX_SIGNER_KEY_BYTES: u64 = 64 * 1024;
            let mut content = String::new();
            f.take(MAX_SIGNER_KEY_BYTES + 1).read_to_string(&mut content).map_err(|e| {
                CryptError::Key(format!("Failed to read signer public key file: {}", e))
            })?;
            if content.len() as u64 > MAX_SIGNER_KEY_BYTES {
                return Err(CryptError::Key(format!(
                    "Signer public key file '{}' exceeds 64 KiB size limit",
                    as_path.display()
                )));
            }
            let content_trimmed = content.trim();
            if content_trimmed.starts_with("-----BEGIN YACRYPT PUBLIC KEY BUNDLE") {
                return Err(CryptError::Key(format!(
                    "'{}' is a combined public key bundle; import it first via 'yacrypt key-import {}' or pass its Ed25519 public_<FP>.asc / local label",
                    as_path.display(),
                    as_path.display()
                )));
            }
            let bytes = general_purpose::STANDARD.decode(content_trimmed).map_err(|e| {
                CryptError::Key(format!("Failed to decode signer public key file: {}", e))
            })?;
            let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                CryptError::Key("Invalid Ed25519 public key length (expected 32 bytes)".into())
            })?;
            reject_x25519_pubkey_passed_as_signer(as_path, Some(&key_bytes), keystore_dir)?;
            let vk = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|e| CryptError::Key(format!("Invalid Ed25519 public key: {}", e)))?;
            if vk.is_weak() {
                return Err(CryptError::Key(
                    "Refusing weak / small-order Ed25519 verifying key as --signer".into(),
                ));
            }
            return Ok(compute_fingerprint(&vk.to_bytes()));
        }
        Err(CryptError::Crypto(_)) => {}
        Err(e) => return Err(e),
    }

    // 精确匹配当前活跃本地 keystore 条目的别名（严禁使用无对应密钥文件的孤儿 label，且严禁对 --signer 启用短 hex 前缀匹配）
    if let Ok(entries) = scan_keystore(keystore_dir) {
        if let Some(entry) = entries.into_iter().find(|e| {
            e.label.as_deref().map(|lbl| lbl.eq_ignore_ascii_case(trimmed)).unwrap_or(false)
        }) {
            return Ok(entry.fingerprint);
        }
    }

    Err(CryptError::Key(format!(
        "Invalid --signer value '{}': must be a full 64-character hex fingerprint, a local key label, or a path to an Ed25519 public key file (public_<FP>.asc)",
        signer_arg
    )))
}

/// 解析用户传入的 `--signer` 参数（使用默认解析的本地 keystore 目录）
pub fn resolve_signer_fingerprint(signer_arg: &str) -> Result<String, CryptError> {
    let ks_dir = resolve_keystore_dir(None);
    resolve_signer_fingerprint_in_dir(signer_arg, &ks_dir)
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

/// 在 AEAD 解密之后、明文落盘之前验证 SCFv2 内层 Ed25519 签名与信任锚指纹
fn verify_pubenc_v2_signature(
    signature_opt: Option<&PubencSignature>,
    ephemeral_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
    plaintext: &[u8],
    trusted_fp: Option<&str>,
    require_signature: bool,
) -> Result<Option<String>, String> {
    if let Some(sig_data) = signature_opt {
        let verifying_key = VerifyingKey::from_bytes(&sig_data.verifying_key)
            .map_err(|e| format!("Invalid Ed25519 verifying key in SCFv2 payload: {}", e))?;
        if verifying_key.is_weak() {
            return Err(
                "❌ Signature verification FAILED — weak Ed25519 verifying key in file. Decrypted content NOT written to disk."
                    .into(),
            );
        }
        let signature = Signature::from_bytes(&sig_data.signature);
        let transcript = build_pubenc_v2_sig_transcript(ephemeral_pub, recipient_pub, plaintext);
        if verifying_key.verify_strict(&*transcript, &signature).is_err() {
            return Err(
                "❌ Signature verification FAILED — file may have been tampered with. Decrypted content NOT written to disk."
                    .into(),
            );
        }

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
    let ks_dir = resolve_keystore_dir(None);
    decrypt_workflow_with_password_in_dir(
        &ks_dir,
        input,
        private_key_path,
        password,
        output,
        signer,
        require_signature,
        force,
    )
}

/// 完整的解密与验签流程（指定显式 keystore 目录以解析本地签名者别名）
#[allow(clippy::too_many_arguments)]
pub fn decrypt_workflow_with_password_in_dir(
    keystore_dir: &Path,
    input: &Path,
    private_key_path: &Path,
    password: &str,
    output: Option<&Path>,
    signer: Option<&str>,
    require_signature: bool,
    force: bool,
) -> Result<DecryptOutcome, CryptError> {
    let (mut key_file, _) =
        match open_regular_file_nonblocking(private_key_path, "Private key file not found") {
            Ok(res) => res,
            Err(CryptError::Crypto(msg)) => return Err(CryptError::Key(msg)),
            Err(e) => return Err(e),
        };

    // 前置流式校验密文头与 AAD 完整性（防 FIFO 阻塞、格式错误或 M-1 签名剥离白跑 Argon2id）
    inspect_pubenc_file(input)?;

    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => default_decrypt_output_path(input, "pubenc"),
    };
    preflight_check_output_path(Some(input), &out_path, force)?;
    preflight_check_output_path(Some(private_key_path), &out_path, force)?;

    let explicit_signer_fp = match signer {
        Some(s) => Some(resolve_signer_fingerprint_in_dir(s, keystore_dir)?),
        None => None,
    };

    // 读取加密的私钥文件
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

    let x25519_secret_bytes = Zeroizing::new(
        crate::crypto::decrypt_with_aad(&key, &blob.nonce, &blob.ciphertext, &blob.aad).map_err(
            |_| {
                CryptError::Key(
                    "Failed to unlock private key — wrong password or corrupted key backup".into(),
                )
            },
        )?,
    );

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
    let (mut f, _) = open_regular_file_nonblocking(input, "Encrypted file not found")?;
    let mut enc_blob = Vec::new();
    f.read_to_end(&mut enc_blob)?;

    let trusted_fp = explicit_signer_fp.as_deref().or(key_owner_fp.as_deref());
    let must_have_sig = require_signature || explicit_signer_fp.is_some();

    if enc_blob.starts_with(PUBENC_V2_MAGIC) {
        let pubenc2 = unpack_pubenc_v2_blob(&enc_blob)
            .map_err(|s| CryptError::Format(format!("Invalid SCFv2 pubenc file format: {}", s)))?;

        let aad_map = parse_aad_map(&pubenc2.aad)
            .map_err(|e| CryptError::Format(format!("Invalid SCFv2 AAD format: {}", e)))?;
        if aad_map.get("v").map(String::as_str) != Some("2") {
            return Err(CryptError::Format(
                "❌ Header integrity check FAILED — missing or invalid SCFv2 AAD version. Decrypted content NOT written to disk."
                    .into(),
            ));
        }
        let expected_eph_hex = hex::encode(pubenc2.ephemeral_pub);
        match aad_map.get("ephemeral_pub") {
            Some(eph) if eph.eq_ignore_ascii_case(&expected_eph_hex) => {}
            _ => {
                return Err(CryptError::Format(
                    "❌ Header integrity check FAILED — AAD ephemeral_pub mismatch. Decrypted content NOT written to disk."
                        .into(),
                ));
            }
        }
        if aad_map.contains_key("sig_vk") || aad_map.contains_key("flags") {
            return Err(CryptError::Format(
                "❌ Header integrity check FAILED — unexpected plaintext signature field in SCFv2 AAD. Decrypted content NOT written to disk."
                    .into(),
            ));
        }

        let ephemeral_public = X25519PublicKey::from(pubenc2.ephemeral_pub);
        let recipient_public_bytes = X25519PublicKey::from(&static_secret).to_bytes();

        let shared_secret = static_secret.diffie_hellman(&ephemeral_public);
        if !shared_secret.was_contributory() {
            return Err(CryptError::Crypto(
                "Invalid ephemeral X25519 public key in file (non-contributory / low-order point)"
                    .into(),
            ));
        }
        let shared_secret_bytes = Zeroizing::new(*shared_secret.as_bytes());

        let sym_key_array = Zeroizing::new(derive_pubenc_v2_symmetric_key(
            &shared_secret_bytes,
            &pubenc2.ephemeral_pub,
            &recipient_public_bytes,
        ));

        let mut inner_payload = Zeroizing::new(crate::crypto::decrypt_with_aad(
            &sym_key_array,
            &pubenc2.nonce,
            &pubenc2.ciphertext,
            &pubenc2.aad,
        )?);

        drop(shared_secret_bytes);
        drop(sym_key_array);

        let verified_signer_fingerprint = {
            let (plaintext_slice, inner_sig) = unpack_pubenc_v2_inner_payload(&inner_payload)?;
            match verify_pubenc_v2_signature(
                inner_sig.as_ref(),
                &pubenc2.ephemeral_pub,
                &recipient_public_bytes,
                plaintext_slice,
                trusted_fp,
                must_have_sig,
            ) {
                Ok(fp_opt) => {
                    // 仅在签名与信任锚验证全部通过后才将明文落盘
                    write_file_strict_with_options(&out_path, plaintext_slice, force)?;
                    fp_opt
                }
                Err(err_msg) => {
                    inner_payload.zeroize();
                    return Err(CryptError::Crypto(err_msg));
                }
            }
        };
        inner_payload.zeroize();

        Ok(DecryptOutcome { decrypted_file: out_path, verified_signer_fingerprint })
    } else {
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

        let verified_signer_fingerprint =
            match verify_pubenc_aad_and_signature(&pubenc, &plaintext, trusted_fp, must_have_sig) {
                Ok(fp_opt) => fp_opt,
                Err(err_msg) => {
                    plaintext.zeroize();
                    return Err(CryptError::Crypto(err_msg));
                }
            };

        write_file_strict_with_options(&out_path, &plaintext, force)?;
        plaintext.zeroize();

        Ok(DecryptOutcome { decrypted_file: out_path, verified_signer_fingerprint })
    }
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

        // Short hex prefix MUST be rejected for --signer
        assert!(resolve_signer_fingerprint(&"AB".repeat(8)).is_err());
        assert!(resolve_signer_fingerprint("not-a-fingerprint").is_err());
        assert!(resolve_signer_fingerprint(&"ZZ".repeat(32)).is_err());

        // Passing x25519_public_<FP>.asc (or a renamed copy of it) to --signer MUST be rejected
        let ks_dir = dir.join("keystore");
        let keys = crate::keystore::generate_and_store_keys_with_label(
            &ks_dir,
            Some("signer-guard-pass-12"),
            Some("trusted-bob"),
        )
        .unwrap();
        let err_x =
            resolve_signer_fingerprint_in_dir(keys.x25519_pub_path.to_str().unwrap(), &ks_dir)
                .unwrap_err();
        assert!(err_x.to_string().contains("X25519"));

        let renamed_x = dir.join("renamed_sender.asc");
        std::fs::copy(&keys.x25519_pub_path, &renamed_x).unwrap();
        let err_renamed_x =
            resolve_signer_fingerprint_in_dir(renamed_x.to_str().unwrap(), &ks_dir).unwrap_err();
        assert!(err_renamed_x.to_string().contains("X25519"));

        // Local petname resolves cleanly in that keystore, while 16-char hex prefix is still rejected
        assert_eq!(
            resolve_signer_fingerprint_in_dir("trusted-bob", &ks_dir).unwrap(),
            keys.fingerprint
        );
        assert!(resolve_signer_fingerprint_in_dir(&keys.fingerprint[..16], &ks_dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_workflow_and_inspect_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("yacrypt_wf_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ks_dir = dir.join("keystore");
        let input = dir.join("doc.txt");
        std::fs::write(&input, b"workflow payload").unwrap();

        let pw = "workflow-pass-1234";
        let enc_out =
            encrypt_workflow_with_new_keys(&ks_dir, &input, Some(pw), None, false).unwrap();
        assert_eq!(enc_out.encrypted_file.parent(), Some(dir.as_path()));
        assert_eq!(enc_out.encrypted_file.extension().and_then(|s| s.to_str()), Some("pubenc"));
        let enc_fname = enc_out.encrypted_file.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            !enc_fname.contains("doc.txt"),
            "default encrypted file name must be anonymous: {}",
            enc_fname
        );
        assert!(enc_out.encrypted_file.exists());
        assert!(!enc_out.instructions_written);
        assert!(enc_out.instructions_skipped);
        assert!(!enc_out.instructions_file.exists());

        // Explicit write_instructions = true writes .decrypt.txt recording only file_name(), NOT local parent directory path
        let with_instr_out = encrypt_workflow_with_existing_key_opts(
            &input,
            &enc_out.keys.x25519_pub_path,
            Some(&dir.join("with_instr_cipher.pubenc")),
            None,
            true,
            false,
        )
        .unwrap();
        assert!(with_instr_out.instructions_written);
        assert!(!with_instr_out.instructions_skipped);
        let instr_text = std::fs::read_to_string(&with_instr_out.instructions_file).unwrap();
        assert!(instr_text.contains("with_instr_cipher.pubenc"));
        assert!(!instr_text.contains(dir.to_str().unwrap()));

        // Inspect SCFv2 .pubenc (streaming header check — signature & signer FP MUST be concealed)
        let pub_info = match inspect_file(&enc_out.encrypted_file).unwrap() {
            InspectedFile::Pubenc(info) => {
                assert_eq!(info.format_version, 2);
                assert_eq!(info.has_signature, None);
                assert_eq!(info.signer_fingerprint, None);
                assert!(info.padding_enabled);
                info
            }
            other => panic!("Expected Pubenc, got {:?}", other),
        };
        assert_eq!(inspect_pubenc_file(&enc_out.encrypted_file).unwrap(), pub_info);

        // Privacy guarantee: outer SCFv2 file MUST NOT leak signer fingerprint, Ed25519 vk, or exact plaintext length
        let raw_pubenc = std::fs::read(&enc_out.encrypted_file).unwrap();
        assert!(raw_pubenc.starts_with(PUBENC_V2_MAGIC));
        assert_eq!(raw_pubenc[5], 0x00);
        assert!(raw_pubenc.len() > 1024);
        assert!(!String::from_utf8_lossy(&raw_pubenc).contains(&enc_out.keys.fingerprint));
        let vk_raw_b64 = std::fs::read_to_string(&enc_out.keys.pub_path).unwrap();
        let vk_bytes = base64::engine::general_purpose::STANDARD.decode(vk_raw_b64.trim()).unwrap();
        assert!(!raw_pubenc.windows(32).any(|w| w == vk_bytes.as_slice()));

        // Mutating outer SCFv2 flags to non-zero is immediately caught by passwordless inspect_file
        let mut bad_flags_blob = raw_pubenc.clone();
        bad_flags_blob[5] = 0x01;
        let bad_flags_path = dir.join("bad_flags.pubenc");
        std::fs::write(&bad_flags_path, &bad_flags_blob).unwrap();
        assert!(inspect_file(&bad_flags_path).is_err());

        // Streaming inspect detects truncated and trailing bytes
        let trunc_path = dir.join("trunc.pubenc");
        std::fs::write(&trunc_path, &raw_pubenc[..raw_pubenc.len() - 1]).unwrap();
        assert!(inspect_file(&trunc_path).is_err());

        let mut trailing_bytes = raw_pubenc.clone();
        trailing_bytes.push(0xAA);
        let trail_path = dir.join("trail.pubenc");
        std::fs::write(&trail_path, &trailing_bytes).unwrap();
        assert!(inspect_file(&trail_path).is_err());

        // Inspect SGPGv1 .asc.enc key backup
        match inspect_file(&enc_out.keys.x25519_enc_path).unwrap() {
            InspectedFile::Sgpg(info) => {
                assert_eq!(info.format_version, 1);
                assert!(!info.padding_enabled);
                assert_eq!(info.blob_type.as_deref(), Some("x25519"));
                assert_eq!(info.fingerprint.as_deref(), Some(enc_out.keys.fingerprint.as_str()));
            }
            other => panic!("Expected Sgpg, got {:?}", other),
        }

        // Inspect SGPGv2 .enc symmetric file
        let sym_enc_path = dir.join("doc_sym.enc");
        crate::file_ops::encrypt_file_symmetric(&input, pw, Some(&sym_enc_path), false).unwrap();
        match inspect_file(&sym_enc_path).unwrap() {
            InspectedFile::Sgpg(info) => {
                assert_eq!(info.format_version, 2);
                assert!(info.padding_enabled);
                assert_eq!(info.blob_type.as_deref(), Some("file"));
                assert_eq!(info.fingerprint, None);
            }
            other => panic!("Expected Sgpg v2, got {:?}", other),
        }

        // Default decrypt strips .pubenc -> restores doc.txt and verifies inner SCFv2 signature before disk write
        let sub = dir.join("restore_sub");
        std::fs::create_dir_all(&sub).unwrap();
        let copied_pubenc = sub.join("doc.txt.pubenc");
        std::fs::copy(&enc_out.encrypted_file, &copied_pubenc).unwrap();

        let dec_out = decrypt_workflow_with_password_in_dir(
            &ks_dir,
            &copied_pubenc,
            &enc_out.keys.x25519_enc_path,
            pw,
            None,
            None,
            true,
            false,
        )
        .unwrap();
        assert_eq!(dec_out.decrypted_file, sub.join("doc.txt"));
        assert_eq!(dec_out.verified_signer_fingerprint, Some(enc_out.keys.fingerprint.clone()));
        assert_eq!(std::fs::read(sub.join("doc.txt")).unwrap(), b"workflow payload");

        // Unsigned SCFv2 rejects --require-signature before writing any output
        let unsigned_path = dir.join("unsigned_v2.pubenc");
        crate::file_ops::encrypt_file_with_key_in_dir(
            &input,
            &enc_out.keys.x25519_pub_path,
            Some(&unsigned_path),
            None,
            false,
            Some(&ks_dir),
        )
        .unwrap();
        let unsigned_dec_out = dir.join("should_not_exist.txt");
        let err_req_sig = decrypt_workflow_with_password_in_dir(
            &ks_dir,
            &unsigned_path,
            &enc_out.keys.x25519_enc_path,
            pw,
            Some(&unsigned_dec_out),
            None,
            true,
            false,
        )
        .unwrap_err();
        assert!(err_req_sig.to_string().contains("no embedded signature"));
        assert!(!unsigned_dec_out.exists());

        // Unsigned SCFv2 succeeds when require_signature == false and no explicit --signer
        decrypt_workflow_with_password_in_dir(
            &ks_dir,
            &unsigned_path,
            &enc_out.keys.x25519_enc_path,
            pw,
            Some(&unsigned_dec_out),
            None,
            false,
            false,
        )
        .unwrap();
        assert_eq!(std::fs::read(&unsigned_dec_out).unwrap(), b"workflow payload");

        // --no-instructions skips creating .decrypt.txt
        let no_instr_out = encrypt_workflow_with_existing_key_opts(
            &input,
            &enc_out.keys.x25519_pub_path,
            Some(&dir.join("no_instr_cipher")),
            None,
            false,
            false,
        )
        .unwrap();
        assert!(!no_instr_out.instructions_written);
        assert!(no_instr_out.instructions_skipped);
        assert!(!dir.join("no_instr_cipher.decrypt.txt").exists());

        // Legacy SCFv1 backward compatibility + M-1 stripped signature caught by inspect_file
        let xpub_b64 = std::fs::read_to_string(&enc_out.keys.x25519_pub_path).unwrap();
        let xpub_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(xpub_b64.trim())
            .unwrap()
            .try_into()
            .unwrap();
        let ed_sk =
            crate::keystore::load_signing_key_with_password(&enc_out.keys.enc_path, pw).unwrap();
        let eph_secret =
            x25519_dalek::EphemeralSecret::random_from_rng(chacha20poly1305::aead::OsRng);
        let eph_pub_bytes = X25519PublicKey::from(&eph_secret).to_bytes();
        let shared = eph_secret.diffie_hellman(&X25519PublicKey::from(xpub_bytes));
        let sym = derive_symmetric_key_from_shared_secret(
            shared.as_bytes(),
            &eph_pub_bytes,
            b"yacrypt-file-encryption-v1",
        );
        let mut legacy_nonce = [0u8; XNONCE_LEN];
        rand::RngCore::fill_bytes(&mut chacha20poly1305::aead::OsRng, &mut legacy_nonce);
        let legacy_sig = ed_sk.sign(b"legacy v1 payload");
        let legacy_vk = ed_sk.verifying_key().to_bytes();
        let legacy_aad = format!(
            "flags=01|ephemeral_pub={}|sig_vk={}",
            hex::encode(eph_pub_bytes),
            hex::encode(legacy_vk)
        );
        let legacy_ct = crate::crypto::encrypt_with_aad(
            &sym,
            &legacy_nonce,
            b"legacy v1 payload",
            legacy_aad.as_bytes(),
        )
        .unwrap();
        let legacy_v1_blob = crate::crypto::pack_pubenc_blob(
            &eph_pub_bytes,
            &legacy_nonce,
            legacy_aad.as_bytes(),
            &legacy_ct,
            Some(&PubencSignature { verifying_key: legacy_vk, signature: legacy_sig.to_bytes() }),
        )
        .unwrap();
        let legacy_v1_path = dir.join("legacy_v1.pubenc");
        std::fs::write(&legacy_v1_path, &legacy_v1_blob).unwrap();

        match inspect_file(&legacy_v1_path).unwrap() {
            InspectedFile::Pubenc(info) => {
                assert_eq!(info.format_version, 1);
                assert_eq!(info.has_signature, Some(true));
                assert_eq!(
                    info.signer_fingerprint.as_deref(),
                    Some(enc_out.keys.fingerprint.as_str())
                );
                assert!(!info.padding_enabled);
            }
            other => panic!("Expected legacy SCFv1 Pubenc, got {:?}", other),
        }
        let legacy_v1_dec = dir.join("legacy_v1_out.txt");
        let dec_v1 = decrypt_workflow_with_password_in_dir(
            &ks_dir,
            &legacy_v1_path,
            &enc_out.keys.x25519_enc_path,
            pw,
            Some(&legacy_v1_dec),
            None,
            true,
            false,
        )
        .unwrap();
        assert_eq!(dec_v1.verified_signer_fingerprint, Some(enc_out.keys.fingerprint.clone()));
        assert_eq!(std::fs::read(&legacy_v1_dec).unwrap(), b"legacy v1 payload");

        let mut stripped_bytes = Vec::new();
        stripped_bytes.extend_from_slice(b"SCFv1\x00");
        stripped_bytes.extend_from_slice(&legacy_v1_blob[6 + 96..]);
        let stripped_path = dir.join("stripped.pubenc");
        std::fs::write(&stripped_path, &stripped_bytes).unwrap();
        let err_strip = inspect_file(&stripped_path).unwrap_err();
        assert!(err_strip.to_string().contains("Signature stripped"));

        // SCFv2 inner signature tampering / recipient-retargeting / wrong trust-anchor MUST write zero bytes
        let attacker_keys =
            crate::keystore::generate_and_store_keys_in_dir(&ks_dir, Some(pw)).unwrap();
        let attacker_sk =
            crate::keystore::load_signing_key_with_password(&attacker_keys.enc_path, pw).unwrap();
        let mut forged_eph = [0u8; 32];
        rand::RngCore::fill_bytes(&mut chacha20poly1305::aead::OsRng, &mut forged_eph);
        let forged_eph_secret =
            x25519_dalek::EphemeralSecret::random_from_rng(chacha20poly1305::aead::OsRng);
        let forged_eph_pub = X25519PublicKey::from(&forged_eph_secret).to_bytes();
        let forged_shared = forged_eph_secret.diffie_hellman(&X25519PublicKey::from(xpub_bytes));
        let forged_sym =
            derive_pubenc_v2_symmetric_key(forged_shared.as_bytes(), &forged_eph_pub, &xpub_bytes);
        // Sign transcript bound to a DIFFERENT recipient public key (retargeting attack)
        let bad_transcript =
            build_pubenc_v2_sig_transcript(&forged_eph_pub, &[0x77u8; 32], b"retargeted!");
        let bad_sig = attacker_sk.sign(&*bad_transcript);
        let forged_inner = crate::crypto::pack_pubenc_v2_inner_payload(
            b"retargeted!",
            Some(&PubencSignature {
                verifying_key: attacker_sk.verifying_key().to_bytes(),
                signature: bad_sig.to_bytes(),
            }),
        )
        .unwrap();
        let forged_aad = format!("v=2|ephemeral_pub={}", hex::encode(forged_eph_pub));
        let forged_ct = crate::crypto::encrypt_with_aad(
            &forged_sym,
            &legacy_nonce,
            &forged_inner,
            forged_aad.as_bytes(),
        )
        .unwrap();
        let forged_blob = crate::crypto::pack_pubenc_v2_blob(
            &forged_eph_pub,
            &legacy_nonce,
            forged_aad.as_bytes(),
            &forged_ct,
        )
        .unwrap();
        let forged_path = dir.join("retargeted_v2.pubenc");
        let forged_out = dir.join("retargeted_out.txt");
        std::fs::write(&forged_path, &forged_blob).unwrap();
        let err_retarget = decrypt_workflow_with_password_in_dir(
            &ks_dir,
            &forged_path,
            &enc_out.keys.x25519_enc_path,
            pw,
            Some(&forged_out),
            Some(&attacker_keys.fingerprint),
            true,
            false,
        )
        .unwrap_err();
        assert!(err_retarget.to_string().contains("Signature verification FAILED"));
        assert!(!forged_out.exists());

        // Cross-sender trust anchor mismatch on valid SCFv2 signature also writes zero output
        let cross_path = dir.join("cross_sender.pubenc");
        let cross_out = dir.join("cross_out.txt");
        crate::file_ops::encrypt_file_with_key_in_dir(
            &input,
            &enc_out.keys.x25519_pub_path,
            Some(&cross_path),
            Some(&attacker_sk),
            false,
            Some(&ks_dir),
        )
        .unwrap();
        let err_trust = decrypt_workflow_with_password_in_dir(
            &ks_dir,
            &cross_path,
            &enc_out.keys.x25519_enc_path,
            pw,
            Some(&cross_out),
            None,
            true,
            false,
        )
        .unwrap_err();
        assert!(err_trust.to_string().contains("untrusted signer fingerprint"));
        assert!(!cross_out.exists());
        // With explicit --signer attacker_fp it succeeds
        let ok_cross = decrypt_workflow_with_password_in_dir(
            &ks_dir,
            &cross_path,
            &enc_out.keys.x25519_enc_path,
            pw,
            Some(&cross_out),
            Some(&attacker_keys.fingerprint),
            true,
            false,
        )
        .unwrap();
        assert_eq!(ok_cross.verified_signer_fingerprint, Some(attacker_keys.fingerprint));
        assert_eq!(std::fs::read(&cross_out).unwrap(), b"workflow payload");

        // Directory and writerless FIFO MUST fail immediately without blocking or lying about magic
        let err_dir = inspect_file(&ks_dir).unwrap_err();
        assert!(err_dir.to_string().contains("non-regular file"));
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let fifo = dir.join("writerless.pipe");
            let c_fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
            let err_fifo = inspect_file(&fifo).unwrap_err();
            assert!(err_fifo.to_string().contains("non-regular file"));
        }

        // Unimported bundle passed to --signer suggests key-import; deleted key's orphan label is rejected
        let bundle_path = dir.join("peer_bundle.asc");
        crate::keystore::export_public_key_bundle(
            &ks_dir,
            &enc_out.keys.fingerprint,
            pw,
            Some(&bundle_path),
            false,
        )
        .unwrap();
        let err_bundle_signer =
            resolve_signer_fingerprint_in_dir(bundle_path.to_str().unwrap(), &ks_dir).unwrap_err();
        assert!(err_bundle_signer.to_string().contains("key-import"));

        set_key_label(&ks_dir, &enc_out.keys.fingerprint, Some("temp-sender")).unwrap();
        assert_eq!(
            resolve_signer_fingerprint_in_dir("temp-sender", &ks_dir).unwrap(),
            enc_out.keys.fingerprint
        );
        for p in [
            &enc_out.keys.pub_path,
            &enc_out.keys.x25519_pub_path,
            &enc_out.keys.enc_path,
            &enc_out.keys.x25519_enc_path,
            &enc_out.keys.instr_path,
        ] {
            std::fs::remove_file(p).unwrap();
        }
        assert!(resolve_signer_fingerprint_in_dir("temp-sender", &ks_dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
