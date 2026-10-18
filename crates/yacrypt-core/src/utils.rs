/// 工具函数模块
use crate::constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH};
use crate::error::CryptError;
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
/// - 始终拒绝符号链接（前置检查 + O_NOFOLLOW）与非普通文件（目录、FIFO、设备等）
/// - `force = false` 时使用 `create_new(true)` 防止静默覆盖既有文件
/// - `force = true` 时允许覆盖普通文件：先对 fd 执行 `fchmod(0o600)` 收紧权限，再截断写入
pub fn write_file_strict_with_options(path: &Path, data: &[u8], force: bool) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Ok(meta) = fs::symlink_metadata(path) {
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refusing to write to symlink: {}", path.display()),
            ));
        }
        if !ft.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refusing to write to non-regular file: {}", path.display()),
            ));
        }
    }

    let mut opts = fs::OpenOptions::new();
    // O_NOFOLLOW 阻断符号链接；O_NONBLOCK 保证万一检查与 open 之间路径被替换为 FIFO，
    // open 也不会永久阻塞，随后还会基于已打开的 fd 复核文件类型。
    opts.write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if force {
        opts.create(true);
    } else {
        opts.create_new(true);
    }

    let mut f = opts.open(path)?;
    if !f.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Refusing to write to non-regular file: {}", path.display()),
        ));
    }
    // 对已打开的文件描述符显式执行 fchmod(0o600)，确保覆盖既有 0644 文件时权限也被收紧为 0600
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    if force {
        // 权限收紧之后再截断，避免旧内容与新内容在错误权限下的混写窗口
        f.set_len(0)?;
    }
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

/// 校验用户口令长度是否符合 `[MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH]`
pub fn validate_password_length(password: &str) -> Result<(), CryptError> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(CryptError::Key(format!(
            "Password too short; must be >= {} chars",
            MIN_PASSWORD_LENGTH
        )));
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(CryptError::Key(format!(
            "Password too long; must be <= {} chars",
            MAX_PASSWORD_LENGTH
        )));
    }
    Ok(())
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
    fn parse_aad_map_valid_and_invalid() {
        let map = parse_aad_map(b"fp=ABCD|type=x25519").unwrap();
        assert_eq!(map.get("fp").map(String::as_str), Some("ABCD"));
        assert_eq!(map.get("type").map(String::as_str), Some("x25519"));
        assert!(parse_aad_map(b"invalid_entry_without_equals").is_err());
    }

    #[test]
    fn validate_password_length_bounds() {
        assert!(validate_password_length("short").is_err());
        assert!(validate_password_length("valid-password-12").is_ok());
        assert!(validate_password_length(&"a".repeat(MAX_PASSWORD_LENGTH + 1)).is_err());
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

    #[test]
    fn write_file_strict_rejects_fifo_without_blocking() {
        let dir = std::env::temp_dir().join(format!("yacrypt_fifo_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("secret.pipe");

        let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600 as libc::mode_t) };
        assert_eq!(rc, 0, "mkfifo failed");

        // 前置检查与 O_NONBLOCK 双保险：两种模式都必须立即报错而不是阻塞
        assert!(write_file_strict(&fifo, b"x").is_err());
        assert!(write_file_strict_with_options(&fifo, b"x", true).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
