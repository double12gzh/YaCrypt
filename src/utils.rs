/// 工具函数模块
use crate::constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH};
use dialoguer::Password;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io, io::Write, path::Path};

/// 尝试锁定当前进程内存页，防止敏感数据被交换到磁盘。
/// 注意：仅使用 MCL_CURRENT 而不使用 MCL_FUTURE，避免在 Linux 默认 RLIMIT_MEMLOCK (8~64 MiB)
/// 下导致后续 Argon2id 64 MiB 工作内存分配触发 ENOMEM / SIGABRT (H-2)。
pub fn try_mlockall() {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let rc = libc::mlockall(libc::MCL_CURRENT);
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

/// 默认以严格权限安全创建并写入文件（0o600，拒绝覆盖已有文件与符号链接）
pub fn write_file_strict(path: &Path, data: &[u8]) -> io::Result<()> {
    write_file_strict_with_options(path, data, false)
}

/// 以严格权限写入文件（0o600）：
/// - 始终拒绝符号链接（检查 symlink_metadata + O_NOFOLLOW）与目录
/// - `force = false` 时使用 `create_new(true)` 防止静默覆盖既有文件
/// - `force = true` 时允许覆盖普通文件，但写入前先对 fd 执行 `fchmod(0o600)` 收紧既有权限
pub fn write_file_strict_with_options(path: &Path, data: &[u8], force: bool) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refusing to write to symlink: {}", path.display()),
            ));
        }
        if meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Target path is a directory: {}", path.display()),
            ));
        }
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }

    let mut f = opts.open(path)?;
    // 对已打开的文件描述符显式执行 fchmod(0o600)，确保覆盖既有 0644 文件时权限也被收紧为 0600
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
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

/// 对敏感元数据（如文件名、姓名、邮箱）计算 SHA-256 摘要，用于 AAD 绑定而不泄漏明文 (M-3)
pub fn hash_metadata_field(field: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(field.as_bytes());
    hex::encode(hasher.finalize().as_slice())
}

/// 解析形如 `k1=v1|k2=v2` 的 AAD 键值映射
pub fn parse_aad_map(aad: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let s = std::str::from_utf8(aad).map_err(|_| "AAD is not valid UTF-8".to_string())?;
    let mut map = BTreeMap::new();
    if s.is_empty() {
        return Ok(map);
    }
    for part in s.split('|') {
        let (k, v) =
            part.split_once('=').ok_or_else(|| format!("malformed AAD entry: {}", part))?;
        if k.is_empty() {
            return Err("empty AAD key".into());
        }
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
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
    use std::os::unix::fs::PermissionsExt;

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

    #[test]
    fn parse_aad_map_valid_and_invalid() {
        let map = parse_aad_map(b"fp=ABCD|type=x25519").unwrap();
        assert_eq!(map.get("fp").map(String::as_str), Some("ABCD"));
        assert_eq!(map.get("type").map(String::as_str), Some("x25519"));
        assert!(parse_aad_map(b"invalid_entry_without_equals").is_err());
    }

    #[test]
    fn write_file_strict_enforces_no_overwrite_and_0600_and_no_symlink() {
        let dir = std::env::temp_dir().join(format!("yacrypt_utils_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("secret.bin");

        // 1. 新建文件权限为 0600
        write_file_strict(&file_path, b"first").unwrap();
        let mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // 2. 默认拒绝覆盖既有文件
        assert!(write_file_strict(&file_path, b"second").is_err());
        assert_eq!(fs::read(&file_path).unwrap(), b"first");

        // 3. 即使原文件权限是 0644，force=true 覆盖后权限也必须收紧为 0600
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();
        write_file_strict_with_options(&file_path, b"forced", true).unwrap();
        let mode_after = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_after, 0o600);
        assert_eq!(fs::read(&file_path).unwrap(), b"forced");

        // 4. 拒绝跟随符号链接（无论 force=false 还是 force=true）
        let link_path = dir.join("symlink.bin");
        std::os::unix::fs::symlink(&file_path, &link_path).unwrap();
        assert!(write_file_strict(&link_path, b"hacked").is_err());
        assert!(write_file_strict_with_options(&link_path, b"hacked", true).is_err());
        assert_eq!(fs::read(&file_path).unwrap(), b"forced");

        let _ = fs::remove_dir_all(&dir);
    }
}
