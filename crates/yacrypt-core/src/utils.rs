/// 工具函数模块
use crate::constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH};
use crate::error::CryptError;
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};

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

/// 以非阻塞方式打开待读取的普通文件（允许指向普通文件的符号链接，立即拒绝目录、FIFO 命名管道、设备节点与套接字）
pub fn open_regular_file_nonblocking(
    path: &Path,
    not_found_prefix: &str,
) -> Result<(fs::File, u64), CryptError> {
    use std::os::unix::fs::OpenOptionsExt;

    let f = match fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(CryptError::Crypto(format!("{}: {}", not_found_prefix, path.display())));
        }
        Err(e) => return Err(CryptError::Io(e)),
    };
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Refusing to read non-regular file: {}", path.display()),
        )
        .into());
    }
    Ok((f, meta.len()))
}

/// 前置校验输入路径必须为可读普通文件（在提示口令与 Argon2id 派生前拦截不存在路径、目录及 FIFO/设备文件）
pub fn preflight_check_input_file(path: &Path, not_found_prefix: &str) -> Result<(), CryptError> {
    open_regular_file_nonblocking(path, not_found_prefix).map(|_| ())
}

/// 前置输出冲突与同文件自覆盖预检（在提示口令与 Argon2id 派生之前执行）：
/// - 拒绝符号链接与非普通文件（目录、FIFO、设备等）
/// - 无条件比对 `input` 与 `output` 的 Unix `(dev, ino)`，即使 `force = true` 也严禁同文件/硬链接自覆盖
/// - 当 `!force && output` 已存在时提前返回 `AlreadyExists`
pub fn preflight_check_output_path(
    input: Option<&Path>,
    output: &Path,
    force: bool,
) -> Result<(), CryptError> {
    use std::os::unix::fs::MetadataExt;

    if let Ok(out_meta) = fs::symlink_metadata(output) {
        let ft = out_meta.file_type();
        if ft.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refusing to write to symlink: {}", output.display()),
            )
            .into());
        }
        if !ft.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refusing to write to non-regular file: {}", output.display()),
            )
            .into());
        }
        if let Some(in_path) = input {
            if let Ok(in_meta) = fs::metadata(in_path) {
                if in_meta.dev() == out_meta.dev() && in_meta.ino() == out_meta.ino() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Refusing to overwrite input file with output (same file inode): {}",
                            output.display()
                        ),
                    )
                    .into());
                }
            }
        }
        if !force {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Output file already exists: {} (use --force to overwrite)",
                    output.display()
                ),
            )
            .into());
        }
    }
    Ok(())
}

// SECURITY INVARIANT (YC-010): Default ciphertext filenames MUST stay random/anonymous; never derive from input filename.
/// 生成脱敏随机输出路径（`<16位小写hex>.<ext>`），放置在原文件同目录下，避免通过默认密文名泄露原文件名或扩展名
fn random_anonymous_output_path(input: &Path, ext: &str) -> PathBuf {
    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    let fname = format!("{}.{}", hex::encode(rnd), ext);
    if input.file_name().is_some() {
        input.with_file_name(fname)
    } else {
        PathBuf::from(fname)
    }
}

/// 默认公钥加密输出路径：在输入文件同目录生成随机匿名 `<16hex>.pubenc`，不泄露原文件名
pub fn default_pubenc_output_path(input: &Path) -> PathBuf {
    random_anonymous_output_path(input, "pubenc")
}

/// 默认对称加密输出路径：在输入文件同目录生成随机匿名 `<16hex>.enc`，不泄露原文件名
pub fn default_symmetric_output_path(input: &Path) -> PathBuf {
    random_anonymous_output_path(input, "enc")
}

/// 默认解密输出路径：若匹配预期扩展名（`pubenc` 或 `enc`）且剥离后仍为合法文件名则原样还原 `OsStr`，否则追加 `.decrypted`
pub fn default_decrypt_output_path(input: &Path, expected_ext: &str) -> PathBuf {
    if input.extension() == Some(OsStr::new(expected_ext)) {
        if let Some(stem) = input.file_stem() {
            if !stem.is_empty() && stem != OsStr::new(".") && stem != OsStr::new("..") {
                return input.with_file_name(stem);
            }
        }
    }
    let mut os: OsString = input.as_os_str().to_os_string();
    os.push(".decrypted");
    PathBuf::from(os)
}

/// 伴生 `.decrypt.txt` 说明文件路径：直接在输出密文路径后追加 `.decrypt.txt`（避免无扩展名时产生 `..decrypt.txt`）
pub fn companion_instructions_path(encrypted_path: &Path) -> PathBuf {
    let mut os: OsString = encrypted_path.as_os_str().to_os_string();
    os.push(".decrypt.txt");
    PathBuf::from(os)
}

/// 默认私钥导出 `.der` 路径：剥离 `.asc.enc` 或 `.enc` 后追加 `.der`（避免产生 `.asc.der`）
pub fn default_der_output_path(enc_path: &Path) -> PathBuf {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    if let Some(fname) = enc_path.file_name() {
        let bytes = fname.as_bytes();
        let stripped = bytes
            .strip_suffix(b".asc.enc")
            .or_else(|| bytes.strip_suffix(b".enc"))
            .unwrap_or(bytes);
        if !stripped.is_empty() && stripped != b"." && stripped != b".." {
            let mut out = stripped.to_vec();
            out.extend_from_slice(b".der");
            return PathBuf::from(OsString::from_vec(out));
        }
    }
    PathBuf::from("private_out.der")
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

/// 校验用户口令长度是否符合至少 `MIN_PASSWORD_LENGTH` 个字符且不超过 `MAX_PASSWORD_LENGTH` 字节
pub fn validate_password_length(password: &str) -> Result<(), CryptError> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(CryptError::Key(format!(
            "Password too short; must be >= {} chars",
            MIN_PASSWORD_LENGTH
        )));
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(CryptError::Key(format!(
            "Password too long; must be <= {} bytes",
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
        // 3 emojis = 12 UTF-8 bytes, 4 CJK chars = 12 UTF-8 bytes — both are < 12 chars and MUST be rejected
        assert!(validate_password_length("🔑🔑🔑").is_err());
        assert!(validate_password_length("我爱北京").is_err());
        assert!(validate_password_length("我爱北京天安门太阳升起啦").is_ok());
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
        // 读取端同样必须非阻塞拒绝 FIFO 与目录，同时允许指向普通文件的符号链接
        assert!(open_regular_file_nonblocking(&fifo, "File not found").is_err());
        assert!(open_regular_file_nonblocking(&dir, "File not found").is_err());
        let reg = dir.join("regular.txt");
        fs::write(&reg, b"ok").unwrap();
        let sym_reg = dir.join("sym_regular.txt");
        std::os::unix::fs::symlink(&reg, &sym_reg).unwrap();
        let (_, len) = open_regular_file_nonblocking(&sym_reg, "File not found").unwrap();
        assert_eq!(len, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn preflight_rejects_same_inode_even_with_force_and_existing_without_force() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_preflight_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let input = dir.join("source.pdf");
        let existing_out = dir.join("existing.pubenc");
        let hardlink_out = dir.join("source_hardlink.pdf");
        fs::write(&input, b"important data").unwrap();
        fs::write(&existing_out, b"old cipher").unwrap();
        fs::hard_link(&input, &hardlink_out).unwrap();

        // Same path rejected both with and without force
        assert!(preflight_check_output_path(Some(&input), &input, false).is_err());
        let err_self = preflight_check_output_path(Some(&input), &input, true).unwrap_err();
        assert!(err_self.to_string().contains("same file inode"));

        // Hardlink to input also rejected even with force=true
        let err_hl = preflight_check_output_path(Some(&input), &hardlink_out, true).unwrap_err();
        assert!(err_hl.to_string().contains("same file inode"));

        // Existing distinct file rejected when force=false, allowed when force=true
        assert!(preflight_check_output_path(Some(&input), &existing_out, false).is_err());
        assert!(preflight_check_output_path(Some(&input), &existing_out, true).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_helpers_preserve_extensions_osstr_and_avoid_double_dots() {
        use std::os::unix::ffi::OsStrExt;

        // 1. Default encrypted paths are anonymous (<16hex>.pubenc / .enc) in the same dir and never expose original filename
        let pdf = Path::new("/tmp/confidential_report.pdf");
        let pubenc_a = default_pubenc_output_path(pdf);
        let pubenc_b = default_pubenc_output_path(pdf);
        assert_ne!(pubenc_a, pubenc_b);
        assert_eq!(pubenc_a.parent(), Some(Path::new("/tmp")));
        assert_eq!(pubenc_a.extension(), Some(OsStr::new("pubenc")));
        let pubenc_name = pubenc_a.file_name().unwrap().to_string_lossy();
        assert!(!pubenc_name.contains("confidential"));
        assert!(!pubenc_name.contains("report"));
        assert!(!pubenc_name.contains("pdf"));
        assert_eq!(pubenc_name.len(), 16 + ".pubenc".len());

        let sym_a = default_symmetric_output_path(Path::new("/tmp/payroll_archive.tar.gz"));
        let sym_b = default_symmetric_output_path(Path::new("/tmp/payroll_archive.tar.gz"));
        assert_ne!(sym_a, sym_b);
        assert_eq!(sym_a.parent(), Some(Path::new("/tmp")));
        assert_eq!(sym_a.extension(), Some(OsStr::new("enc")));
        let sym_name = sym_a.file_name().unwrap().to_string_lossy();
        assert!(!sym_name.contains("payroll"));
        assert!(!sym_name.contains("tar"));
        assert_eq!(sym_name.len(), 16 + ".enc".len());

        assert_eq!(
            default_decrypt_output_path(Path::new("/tmp/report.pdf.pubenc"), "pubenc"),
            PathBuf::from("/tmp/report.pdf")
        );

        // 2. Non-UTF8 OsStr roundtrip on explicit .pubenc path
        let raw_path = Path::new(OsStr::from_bytes(b"/tmp/raw_\xff\xfe.tar.gz"));
        let mut raw_enc_os = raw_path.as_os_str().to_os_string();
        raw_enc_os.push(".pubenc");
        let raw_enc = PathBuf::from(raw_enc_os);
        let raw_dec = default_decrypt_output_path(&raw_enc, "pubenc");
        assert_eq!(raw_dec.as_os_str(), raw_path.as_os_str());

        // 3. Edge case: "..pubenc" or ".pubenc" does NOT resolve to "." or empty
        assert_eq!(
            default_decrypt_output_path(Path::new("/tmp/..pubenc"), "pubenc"),
            PathBuf::from("/tmp/..pubenc.decrypted")
        );
        assert_eq!(
            default_decrypt_output_path(Path::new("/tmp/.pubenc"), "pubenc"),
            PathBuf::from("/tmp/.pubenc.decrypted")
        );

        // 4. Companion instructions avoids "..decrypt.txt" on extensionless output
        assert_eq!(
            companion_instructions_path(Path::new("/tmp/cipher_no_ext")),
            PathBuf::from("/tmp/cipher_no_ext.decrypt.txt")
        );
        assert_eq!(
            companion_instructions_path(Path::new("/tmp/report.pdf.pubenc")),
            PathBuf::from("/tmp/report.pdf.pubenc.decrypt.txt")
        );

        // 5. DER default output strips .asc.enc cleanly without leaving .asc.der
        assert_eq!(
            default_der_output_path(Path::new("keystore/private_ABCD1234.asc.enc")),
            PathBuf::from("private_ABCD1234.der")
        );
    }
}
