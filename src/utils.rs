/// 工具函数模块
use crate::constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH};
use dialoguer::Password;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::Path,
};

/// 尝试锁定内存，防止敏感数据被交换到磁盘
pub fn try_mlockall() {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let rc = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
            if rc != 0 {
                eprintln!("⚠️  mlockall failed (perms?). Secrets may be swapped to disk.");
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS 不支持 mlockall，mlock() 可用但需要逐页调用。
        // 对于 CLI 工具，zeroize 已提供足够的内存保护。
        // 不打印任何提示 — 用户无法操作此信息。
    }
}

/// 以严格权限写入文件（0o600）
pub fn write_file_strict(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    // 在创建文件时就设置权限，避免 TOCTOU 竞态
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?; // 确保数据写入磁盘
    Ok(())
}

/// 计算公钥指纹（使用完整 SHA256，提高安全性）
pub fn compute_fingerprint(pubkey_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    let digest = hasher.finalize();

    hex::encode(digest.as_slice()).to_uppercase()
}

/// 转义 AAD 字段中的特殊字符
pub fn escape_aad_field(field: &str) -> String {
    field.replace(['|', '\n', '\r', '\0'], "_")
}

/// 提示用户输入并确认密码，验证长度
pub fn prompt_password_confirm(prompt: &str) -> Option<String> {
    loop {
        let p = Password::new()
            .with_prompt(prompt)
            .with_confirmation("Confirm password", "Passwords mismatched")
            .interact()
            .ok()?;

        if p.len() < MIN_PASSWORD_LENGTH {
            eprintln!("Password too short; must be >= {} chars", MIN_PASSWORD_LENGTH);
            continue;
        }
        if p.len() > MAX_PASSWORD_LENGTH {
            eprintln!("Password too long; must be <= {} chars", MAX_PASSWORD_LENGTH);
            continue;
        }
        return Some(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_deterministic() {
        let fp1 = compute_fingerprint(&[0xFFu8; 32]);
        let fp2 = compute_fingerprint(&[0xFFu8; 32]);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_different_input() {
        let fp1 = compute_fingerprint(&[0x00u8; 32]);
        let fp2 = compute_fingerprint(&[0x01u8; 32]);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn escape_aad_field_removes_special() {
        assert_eq!(escape_aad_field("hello|world"), "hello_world");
        assert_eq!(escape_aad_field("line\nbreak"), "line_break");
        assert_eq!(escape_aad_field("cr\rchar"), "cr_char");
        assert_eq!(escape_aad_field("null\0byte"), "null_byte");
        assert_eq!(escape_aad_field("normal text"), "normal text");
    }

    #[test]
    fn escape_aad_field_empty() {
        assert_eq!(escape_aad_field(""), "");
    }
}
