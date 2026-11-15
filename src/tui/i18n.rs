//! TUI 双语（中文 / English）本地化与内置文件说明手册
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use std::path::Path;
use yacrypt_core::utils::write_file_strict_with_options;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiLang {
    En,
    Zh,
}

impl UiLang {
    pub fn pick<'a>(self, en: &'a str, zh: &'a str) -> &'a str {
        match self {
            UiLang::En => en,
            UiLang::Zh => zh,
        }
    }

    pub fn toggle(self) -> Self {
        match self {
            UiLang::En => UiLang::Zh,
            UiLang::Zh => UiLang::En,
        }
    }

    /// 按优先级检测初始界面语言：
    /// 1. `<keystore_dir>/ui_lang` 普通文件（拒绝符号链接与 FIFO 等非普通文件）
    /// 2. `YACRYPT_LANG` 环境变量
    /// 3. `LC_ALL` / `LC_MESSAGES` / `LANG` 环境变量（以 `zh` 开头则启用中文，否则英文）
    pub fn detect_initial(keystore_dir: &Path) -> Self {
        Self::detect_initial_with_env(keystore_dir, |k| std::env::var(k).ok())
    }

    pub fn detect_initial_with_env<F>(keystore_dir: &Path, mut get_env: F) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        if let Some(file_lang) = read_ui_lang_file(&keystore_dir.join("ui_lang")) {
            return file_lang;
        }

        if let Some(val) = get_env("YACRYPT_LANG") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                if let Some(lang) = parse_lang_code(trimmed) {
                    return lang;
                }
                return if trimmed.to_ascii_lowercase().starts_with("zh") {
                    UiLang::Zh
                } else {
                    UiLang::En
                };
            }
        }

        for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Some(val) = get_env(var) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    return if trimmed.to_ascii_lowercase().starts_with("zh") {
                        UiLang::Zh
                    } else {
                        UiLang::En
                    };
                }
            }
        }

        UiLang::En
    }

    /// 仅当 `keystore_dir` 已真实存在（且非符号链接）时持久化语言偏好，绝不凭空创建空密钥目录
    pub fn persist_if_keystore_exists(self, keystore_dir: &Path) {
        let Ok(meta) = std::fs::symlink_metadata(keystore_dir) else {
            return;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return;
        }
        let content: &[u8] = match self {
            UiLang::En => b"en\n",
            UiLang::Zh => b"zh\n",
        };
        let _ = write_file_strict_with_options(&keystore_dir.join("ui_lang"), content, true);
    }
}

fn parse_lang_code(raw: &str) -> Option<UiLang> {
    let norm = raw.trim().to_ascii_lowercase();
    if norm.starts_with("zh") {
        Some(UiLang::Zh)
    } else if norm.starts_with("en") {
        Some(UiLang::En)
    } else {
        None
    }
}

fn read_ui_lang_file(path: &Path) -> Option<UiLang> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let meta = std::fs::symlink_metadata(path).ok()?;
    let ft = meta.file_type();
    if ft.is_symlink() || !ft.is_file() {
        return None;
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.file_type().is_file() {
        return None;
    }

    let mut buf = String::new();
    file.take(64).read_to_string(&mut buf).ok()?;
    parse_lang_code(&buf)
}

/// 生成 `[?] / [F1]` 内置文件作用、受众/用途、保密级别与跨电脑使用指南文本行
pub fn help_guide_lines(lang: UiLang, keystore_dir: &Path) -> Vec<Line<'static>> {
    let sec_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let key_style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let warn_style = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    let ok_style = Style::default().fg(Color::Green).add_modifier(Modifier::BOLD);
    let dim_style = Style::default().fg(Color::Gray);

    match lang {
        UiLang::Zh => vec![
            Line::from(Span::styled("一、业务/工作目录中的文件（加密、解密产物）", sec_style)),
            Line::from(""),
            Line::from(Span::styled("  1. <原文件>  (例如: 备忘录.txt)", key_style)),
            Line::from("     • 含义与用途：您的原始明文文件。"),
            Line::from(Span::styled(
                "     • 保密要求：⚠️ 明文机密！YaCrypt 不会自动删除原文件。",
                warn_style,
            )),
            Line::from("     • 处置建议：确认密文能正常解密后，保密场景请手动删除原文件。"),
            Line::from(""),
            Line::from(Span::styled("  2. <随机名>.pubenc  (SCFv2 公钥混合加密·内层防比对签名容器)", key_style)),
            Line::from("     • 含义与用途：X25519+AEAD 加密（支持签名内嵌加密与长度混淆填充，兼容解密 SCFv1）。"),
            Line::from(Span::styled(
                "     • 保密要求：✅ 已强加密，可放心上传网盘、发邮件或异机保存。",
                ok_style,
            )),
            Line::from(
                "     • 跨电脑解密：需同时携带 [.pubenc 密文 + 对应 x25519_private 私钥 + 口令]。",
            ),
            Line::from(""),
            Line::from(Span::styled("  3. <随机名>.enc  (SGPGv2 纯口令对称·长度混淆加密容器)", key_style)),
            Line::from("     • 含义与用途：不依赖公私钥体系，Argon2id+AEAD 加密并隐藏原文件精确字节数（兼容 SGPGv1）。"),
            Line::from(Span::styled(
                "     • 保密要求：✅ 已强加密，最适合跨多台电脑“只带一个文件凭密码解密”。",
                ok_style,
            )),
            Line::from("     • 适用模式：在 [2] Encrypt 第 3 项切换到 Symmetric Password Only 即可生成。"),
            Line::from(""),
            Line::from(Span::styled("  4. <输出>.decrypt.txt  (伴生解密备忘单 · 默认不生成)", key_style)),
            Line::from("     • 含义与用途：可选记录密钥指纹与 CLI 解密命令（不含口令或私钥）。"),
            Line::from("     • 默认与保密：默认跳过以防关联指纹；取消勾选或 --instructions 才生成。"),
            Line::from(""),
            Line::from(Span::styled("  5. <解密还原文件>  (默认剥离 .pubenc / .enc 还原，权限 0600)", key_style)),
            Line::from("     • 含义与用途：验签通过后写回磁盘的明文文件（仅当前账号可读写）。"),
            Line::from(Span::styled(
                "     • 保密要求：⚠️ 明文机密！用完后请及时清理或重新加密保存。",
                warn_style,
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("二、本地密钥环目录（当前: {}）", keystore_dir.display()),
                sec_style,
            )),
            Line::from("  注：私钥备份已用口令经 Argon2id + XChaCha20-Poly1305 强加密，并非裸露明文。"),
            Line::from(""),
            Line::from(Span::styled("  1. x25519_private_<FP>.asc.enc  (X25519 解密私钥备份)", key_style)),
            Line::from("     • 适用对象：您本人用于解密收到的或自己加密的 .pubenc 文件。"),
            Line::from(Span::styled(
                "     • 保密与备份：🔐 绝密关键资产！勿外泄，且务必异地备份（丢则永久不可解）！",
                warn_style,
            )),
            Line::from(""),
            Line::from(Span::styled("  2. private_<FP>.asc.enc  (Ed25519 签名私钥备份)", key_style)),
            Line::from("     • 适用对象：您本人用于给发出文件签名防伪、以及导出公钥包时自签名绑定。"),
            Line::from("     • 保密与备份：🔐 私人机密，需口令解锁，请随密钥环一并妥善备份、勿外泄。"),
            Line::from(""),
            Line::from(Span::styled("  3. x25519_public_<FP>.asc  (X25519 加密公钥)", key_style)),
            Line::from("     • 适用对象：发给想给你传密件的人，或自己重复加密新文件时选用。"),
            Line::from(Span::styled("     • 保密与备份：🌐 公开非机密，可放心分享；仅用于加密，不能解密。", ok_style)),
            Line::from(""),
            Line::from(Span::styled("  4. public_<FP>.asc  (Ed25519 验签公钥)", key_style)),
            Line::from("     • 适用对象：发给接收方用于固定您的签名信任锚，防止中间人伪造身份。"),
            Line::from(Span::styled("     • 保密与备份：🌐 公开非机密，可放心分享。", ok_style)),
            Line::from(""),
            Line::from(Span::styled("  5. recovery_instructions_<FP>.txt  (密钥恢复指引)", key_style)),
            Line::from("     • 含义与保密：📄 无机密，仅记录 CLI 解密示例命令，删掉不影响加解密。"),
            Line::from(""),
            Line::from(Span::styled("  6. labels.tsv / ui_lang  (本地辅助索引)", key_style)),
            Line::from("     • labels.tsv (0600)：本机密钥别名备注表，严守 M-3 绝不写入任何密文或公钥包。"),
            Line::from("     • ui_lang    (0600)：本机 TUI 界面语言偏好（zh / en），可随时删或用 Shift+L 切换。"),
            Line::from(""),
            Line::from(Span::styled("三、跨电脑迁移与常用命令速查", sec_style)),
            Line::from("  • 公钥模式跨电脑解密：带走 .pubenc + 整个 ~/.yacrypt/keystore（或 x25519_private）+ 口令。"),
            Line::from("  • 对称模式跨电脑解密：只带一个 .enc 文件 + 口令即可。"),
            Line::from("  • 交换公钥给他人：CLI 运行 `yacrypt key-export <别名>`；导入他人：`yacrypt key-import <包> --label <名>`。"),
            Line::from(Span::styled("  • 临时电脑用完提醒：拷贝走私钥备份后，记得清理该机 keystore 与明文文件。", dim_style)),
        ],
        UiLang::En => vec![
            Line::from(Span::styled("1. Working Directory Files (Ciphertexts & Outputs)", sec_style)),
            Line::from(""),
            Line::from(Span::styled("  1. <original_file>  (e.g. memo.txt)", key_style)),
            Line::from("     • Meaning / Purpose: Your original unencrypted plaintext file."),
            Line::from(Span::styled(
                "     • Secrecy Level: ⚠️ SENSITIVE PLAINTEXT! YaCrypt never auto-deletes inputs.",
                warn_style,
            )),
            Line::from("     • Action: Once decryption is verified, delete the plaintext manually if needed."),
            Line::from(""),
            Line::from(Span::styled("  2. <random>.pubenc  (SCFv2 Hybrid Public-Key · Encrypted-Signature Container)", key_style)),
            Line::from("     • Meaning / Purpose: X25519+AEAD with AEAD-concealed Ed25519 sig & length padding (decrypts SCFv1 too)."),
            Line::from(Span::styled(
                "     • Secrecy Level: ✅ STRONGLY ENCRYPTED. Safe for cloud storage, email, or USB.",
                ok_style,
            )),
            Line::from(
                "     • Cross-Machine: Needs [.pubenc + matching x25519_private_*.asc.enc + password].",
            ),
            Line::from(""),
            Line::from(Span::styled("  3. <random>.enc  (SGPGv2 Symmetric Password-Only · Padded Container)", key_style)),
            Line::from("     • Meaning / Purpose: Portable Argon2id+AEAD password encryption with length hiding (reads SGPGv1 too)."),
            Line::from(Span::styled(
                "     • Secrecy Level: ✅ STRONGLY ENCRYPTED. Single-file portable across any machine.",
                ok_style,
            )),
            Line::from("     • How to create: Select Symmetric Password Only in [2] Encrypt field 3."),
            Line::from(""),
            Line::from(Span::styled("  4. <output>.decrypt.txt  (Companion Memo · Skipped by Default)", key_style)),
            Line::from("     • Purpose: Optional fingerprint & CLI memo (no passwords/keys)."),
            Line::from("     • Default: Skipped (hides link); toggle Skip or --instructions."),
            Line::from(""),
            Line::from(Span::styled("  5. <decrypted_output>  (Restored Plaintext, 0600 permissions)", key_style)),
            Line::from("     • Meaning / Purpose: Verified plaintext output written with owner-only 0600 mode."),
            Line::from(Span::styled(
                "     • Secrecy Level: ⚠️ SENSITIVE PLAINTEXT! Clean up or re-encrypt after use.",
                warn_style,
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("2. Keystore Files (Active: {})", keystore_dir.display()),
                sec_style,
            )),
            Line::from("  Note: Private key backups (*.asc.enc) are encrypted via Argon2id + XChaCha20-Poly1305."),
            Line::from(""),
            Line::from(Span::styled("  1. x25519_private_<FP>.asc.enc  (Encrypted Decryption Private Key)", key_style)),
            Line::from("     • User / Role: Used by YOU (+ password) to decrypt .pubenc files."),
            Line::from(Span::styled(
                "     • Secrecy / Backup: 🔐 CRITICAL SECRET! Keep private AND back up safely (irrecoverable if lost)!",
                warn_style,
            )),
            Line::from(""),
            Line::from(Span::styled("  2. private_<FP>.asc.enc  (Encrypted Ed25519 Signing Private Key)", key_style)),
            Line::from("     • User / Role: Used by YOU (+ password) to sign files or export key bundles."),
            Line::from("     • Secrecy / Backup: 🔐 SECRET. Back up alongside your keystore; never share."),
            Line::from(""),
            Line::from(Span::styled("  3. x25519_public_<FP>.asc  (X25519 Encryption Public Key)", key_style)),
            Line::from("     • User / Role: Shared with senders (or reused by you) to encrypt .pubenc files."),
            Line::from(Span::styled("     • Secrecy / Backup: 🌐 PUBLIC. Safe to share openly; cannot decrypt files.", ok_style)),
            Line::from(""),
            Line::from(Span::styled("  4. public_<FP>.asc  (Ed25519 Verification Public Key)", key_style)),
            Line::from("     • User / Role: Shared with recipients to pin your trusted signer fingerprint."),
            Line::from(Span::styled("     • Secrecy / Backup: 🌐 PUBLIC. Safe to share openly.", ok_style)),
            Line::from(""),
            Line::from(Span::styled("  5. recovery_instructions_<FP>.txt  (Keypair Recovery Memo)", key_style)),
            Line::from("     • Meaning / Secrecy: 📄 Not secret. Example CLI decrypt command; safe to delete."),
            Line::from(""),
            Line::from(Span::styled("  6. labels.tsv / ui_lang  (Local-Only Keyring Metadata)", key_style)),
            Line::from("     • labels.tsv (0600): Local petname/alias map; never leaked into ciphertexts (M-3)."),
            Line::from("     • ui_lang    (0600): Local TUI language pref (zh / en); toggle with Shift+L / F2."),
            Line::from(""),
            Line::from(Span::styled("3. Cross-Machine & Key Exchange Cheat Sheet", sec_style)),
            Line::from("  • Pubkey mode (.pubenc): Copy .pubenc + keystore (or x25519_private) + remember password."),
            Line::from("  • Symmetric mode (.enc): Copy the single .enc file + remember password (no keystore needed)."),
            Line::from("  • Exchange keys with peers: CLI `yacrypt key-export <label>` / `yacrypt key-import <file>`."),
            Line::from(Span::styled("  • Shared machines: After copying keys out, wipe plaintext & local keystore.", dim_style)),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static TEST_ID: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), id));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detect_initial_precedence_and_no_empty_keystore_creation() {
        let root = temp_dir("yacrypt_i18n_test");
        let missing_ks = root.join("missing_keystore");

        // 1. Toggling / persisting on a non-existent keystore dir MUST NOT create it
        UiLang::Zh.persist_if_keystore_exists(&missing_ks);
        assert!(!missing_ks.exists());

        // 2. Locale env fallback: LC_ALL > LC_MESSAGES > LANG, overridden by YACRYPT_LANG
        let env_zh: HashMap<&str, &str> = [("LANG", "zh_CN.UTF-8")].into_iter().collect();
        assert_eq!(
            UiLang::detect_initial_with_env(&missing_ks, |k| env_zh.get(k).map(|v| (*v).into())),
            UiLang::Zh
        );

        let env_lc_all_en: HashMap<&str, &str> =
            [("LC_ALL", "en_US.UTF-8"), ("LANG", "zh_CN.UTF-8")].into_iter().collect();
        assert_eq!(
            UiLang::detect_initial_with_env(&missing_ks, |k| {
                env_lc_all_en.get(k).map(|v| (*v).into())
            }),
            UiLang::En
        );

        let env_override: HashMap<&str, &str> =
            [("YACRYPT_LANG", "zh"), ("LC_ALL", "C")].into_iter().collect();
        assert_eq!(
            UiLang::detect_initial_with_env(&missing_ks, |k| {
                env_override.get(k).map(|v| (*v).into())
            }),
            UiLang::Zh
        );

        // 3. Existing keystore dir persists ui_lang with 0600 and overrides env vars
        let real_ks = root.join("keystore");
        fs::create_dir_all(&real_ks).unwrap();
        UiLang::En.persist_if_keystore_exists(&real_ks);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(real_ks.join("ui_lang")).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(
            UiLang::detect_initial_with_env(&real_ks, |k| env_override.get(k).map(|v| (*v).into())),
            UiLang::En
        );

        // 4. Symlinked ui_lang file MUST be ignored (safety)
        #[cfg(unix)]
        {
            let target = root.join("fake_zh");
            fs::write(&target, "zh\n").unwrap();
            let ui_lang_path = real_ks.join("ui_lang");
            fs::remove_file(&ui_lang_path).unwrap();
            std::os::unix::fs::symlink(&target, &ui_lang_path).unwrap();
            // Falls back to En from empty env rather than reading symlink target
            assert_eq!(UiLang::detect_initial_with_env(&real_ks, |_| None), UiLang::En);
        }

        let _ = fs::remove_dir_all(&root);
    }
}
