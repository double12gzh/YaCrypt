/// Ratatui 界面渲染模块
use crate::tui::app::{
    ActiveTab, CompanionInstrStatus, ModalState, StatusKind, SummaryKind, TuiApp,
};
use crate::tui::i18n::{help_guide_lines, UiLang};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Tabs, Wrap},
    Frame,
};
use yacrypt_core::workflow::InspectedFile;

pub fn render(frame: &mut Frame, app: &TuiApp) {
    // 无边框纯文本复制视图：整屏清空且不绘制任何 `│` 边框字符，杜绝窄屏复制混入边框符
    if let ModalState::GeneratedPasswordDisplay {
        ref fingerprint,
        confirmed_saved,
        plain_copy_mode: true,
    } = app.modal
    {
        render_plain_copy_backup_password(frame, app, fingerprint, confirmed_saved);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(12), Constraint::Length(3)])
        .split(frame.area());

    render_header(frame, app, chunks[0]);

    match app.active_tab {
        ActiveTab::Keyring => render_keyring_tab(frame, app, chunks[1]),
        ActiveTab::Encrypt => render_encrypt_tab(frame, app, chunks[1]),
        ActiveTab::Decrypt => render_decrypt_tab(frame, app, chunks[1]),
        ActiveTab::Password => render_password_tab(frame, app, chunks[1]),
    }

    render_footer(frame, app, chunks[2]);

    if app.modal != ModalState::None {
        render_modal(frame, app);
    }

    if let Some(ref busy_msg) = app.busy_message {
        render_busy_overlay(frame, app.lang, busy_msg);
    }
}

fn pad_display_width(text: &str, target_cols: usize) -> String {
    let w = Line::from(text).width();
    if w >= target_cols {
        text.to_string()
    } else {
        format!("{}{}", text, " ".repeat(target_cols - w))
    }
}

fn render_plain_copy_backup_password(
    frame: &mut Frame,
    app: &TuiApp,
    fingerprint: &str,
    confirmed_saved: bool,
) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let pw_str = app.one_time_backup_pass.as_ref().map(|s| s.as_str()).unwrap_or("");
    let mut lines = vec![
        Line::from(Span::styled(
            app.lang.pick(
                "PLAIN-TEXT COPY VIEW (Borderless — select/drag or triple-click the password line below):",
                "纯文本无边框复制视图（鼠标划选或三击下方口令行即可完整复制）：",
            ),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            pw_str,
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "{} {}",
            app.lang.pick("Key Fingerprint:", "密钥指纹:"),
            fingerprint
        )),
        Line::from(""),
        Line::from(format!(
            "{} {}",
            if confirmed_saved { "[x]" } else { "[ ]" },
            app.lang.pick(
                "Saved confirmation checkbox (press [Space] to toggle)",
                "已保存确认勾选框（按 [空格] 切换）",
            ),
        )),
        Line::from(app.lang.pick(
            "Press [p] or [Esc] to return to bordered dialog, or [Enter] (once checked) to wipe & close.",
            "按 [p] 或 [Esc] 返回带边框弹窗；勾选后按 [Enter] 清零内存并关闭。",
        )),
    ];
    if let Some(ref enc_file) = app.backup_modal_encrypted_file {
        lines.push(Line::from(format!(
            "{} {}",
            app.lang.pick("Encrypted Output:", "加密输出文件:"),
            enc_file.display()
        )));
    }
    if let Some(ref err) = app.modal_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err.as_str(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn render_busy_overlay(frame: &mut Frame, lang: UiLang, msg: &str) {
    let area = centered_rect(64, 24, frame.area());
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", msg),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(lang.pick(
            "  Memory-hard Argon2id KDF in progress — queued keystrokes will be safely drained.",
            "  正在执行高内存耗时 Argon2id 密钥派生，期间按键输入将被安全排空。",
        )),
    ];
    let block = Paragraph::new(lines)
        .block(
            Block::default().borders(Borders::ALL).style(Style::default().fg(Color::Yellow)).title(
                lang.pick(" ⏳ Cryptographic Operation In Progress ", " ⏳ 正在执行密码学运算 "),
            ),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(block, area);
}

fn render_header(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let raw_titles = match app.lang {
        UiLang::En => {
            ["[1] 🔑 Keyring", "[2] 🔒 Encrypt", "[3] 🔓 Decrypt & Verify", "[4] 🎲 Password Gen"]
        }
        UiLang::Zh => {
            ["[1] 🔑 密钥环", "[2] 🔒 文件加密", "[3] 🔓 解密与验签", "[4] 🎲 强口令生成"]
        }
    };
    let titles = raw_titles
        .iter()
        .map(|t| Line::from(Span::styled(*t, Style::default().fg(Color::Cyan))))
        .collect::<Vec<_>>();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(app.lang.pick(
            " YaCrypt Security Workbench (Tab/1-4 | ?: Guide | Shift+L: 中文 | q: Quit) ",
            " YaCrypt 安全工作台 (Tab/1-4 | ?: 文件说明 | Shift+L: EN | q: 退出) ",
        )))
        .select(app.active_tab.index())
        .highlight_style(
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        );

    frame.render_widget(tabs, area);
}

fn render_keyring_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
        .split(area);

    let list_title = match app.lang {
        UiLang::En => format!(
            " Local Keyring ({}) (↑/↓ | Enter: Use Key | n: New | l: Label | p: Passwd | r: Refresh) ",
            app.keyring.len()
        ),
        UiLang::Zh => format!(
            " 本地密钥环 ({}) (↑/↓ | Enter: 选用此钥 | n: 新建 | l: 别名 | p: 改密 | r: 刷新) ",
            app.keyring.len()
        ),
    };
    let list_block = Block::default().borders(Borders::ALL).title(list_title);
    let inner_list_area = list_block.inner(cols[0]);
    frame.render_widget(list_block, cols[0]);

    let sel_idx = app.selected_key_idx.min(app.keyring.len().saturating_sub(1));

    if inner_list_area.width > 0 && inner_list_area.height > 0 {
        let visible_count = usize::from(inner_list_area.height);
        let available_width = usize::from(inner_list_area.width);
        let start = sel_idx.saturating_add(1).saturating_sub(visible_count);
        let end = start.saturating_add(visible_count).min(app.keyring.len());

        let items: Vec<ListItem> = if app.keyring.is_empty() {
            vec![ListItem::new(app.lang.pick(
                "  (No keypairs in keystore — press 'n' to generate)",
                "  (本地密钥库暂无密钥 — 按 'n' 生成新密钥对)",
            ))]
        } else {
            app.keyring
                .iter()
                .enumerate()
                .take(end)
                .skip(start)
                .map(|(i, k)| {
                    let is_sel = i == sel_idx;
                    let cursor = if is_sel { "▶ " } else { "  " };
                    let role_icon = if k.x25519_enc_path.is_some() { "🔑 " } else { "👤 " };
                    let label_text = file_browser_single_line(&k.display_name());
                    let full_prefix = format!("{}{}", cursor, role_icon);
                    let prefix = if Line::from(full_prefix.as_str())
                        .width()
                        .saturating_add(Line::from(label_text.as_str()).width())
                        <= available_width
                    {
                        full_prefix
                    } else if inner_list_area.width >= 4 {
                        cursor.to_string()
                    } else {
                        String::new()
                    };
                    let style = if is_sel {
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    ListItem::new(Line::from(Span::styled(
                        format!("{}{}", prefix, label_text),
                        style,
                    )))
                })
                .collect()
        };
        frame.render_widget(List::new(items), inner_list_area);
    }

    let detail_lines = if let Some(entry) = app.keyring.get(sel_idx) {
        let fmt_path = |opt: &Option<std::path::PathBuf>| match opt {
            Some(p) => format!("✅ {}", p.display()),
            None => app.lang.pick("❌ Missing", "❌ 缺失").to_string(),
        };
        let label_desc = match entry.label {
            Some(ref lbl) => match app.lang {
                UiLang::En => format!("[{}] (local 0600 index only — never in ciphertexts)", lbl),
                UiLang::Zh => format!("[{}] (仅保存在本机 0600 索引中，绝不写入密文)", lbl),
            },
            None => app
                .lang
                .pick(
                    "<None — press 'l' to assign a local alias>",
                    "<未设置 — 按 'l' 绑定本机别名>",
                )
                .to_string(),
        };
        let mut lines = vec![
            Line::from(Span::styled(
                app.lang.pick("Local Petname / Alias:", "本机别名 (Petname):"),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("  {}", label_desc)),
            Line::from(""),
            Line::from(Span::styled(
                app.lang
                    .pick("Ed25519 Identity Fingerprint (SHA-256):", "Ed25519 身份指纹 (SHA-256):"),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("  {}", entry.fingerprint)),
            Line::from(""),
            Line::from(Span::styled(
                app.lang.pick(
                    "Associated Keystore Files (Role & Secrecy):",
                    "关联密钥库文件（用途、受众与保密级别）:",
                ),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
        ];
        match app.lang {
            UiLang::En => {
                lines.push(Line::from(format!(
                    "  • Ed25519 Public  [Public · Verify Your Sigs]:  {}",
                    fmt_path(&entry.ed25519_pub_path)
                )));
                lines.push(Line::from(format!(
                    "  • Ed25519 Private [SECRET · Sign · Backup]:     {}",
                    fmt_path(&entry.ed25519_enc_path)
                )));
                lines.push(Line::from(format!(
                    "  • X25519 Public   [Public · Share to Recv]:     {}",
                    fmt_path(&entry.x25519_pub_path)
                )));
                lines.push(Line::from(format!(
                    "  • X25519 Private  [SECRET · Decrypt · Backup!]: {}",
                    fmt_path(&entry.x25519_enc_path)
                )));
                lines.push(Line::from(format!(
                    "  • Recovery Note   [Local Ref Only · Low Sec]:   {}",
                    fmt_path(&entry.instr_path)
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Cross-Machine: .asc.enc (+ password) decrypts .pubenc on another PC; never expose .asc.enc publicly.",
                    Style::default().fg(Color::Yellow),
                )));
                lines.push(Line::from(
                    "Press [?] or [F1] for the complete file guide (meaning, secrecy, cross-machine rules).",
                ));
            }
            UiLang::Zh => {
                lines.push(Line::from(format!(
                    "  • Ed25519 公钥 [可公开 · 他人验证你签名]:     {}",
                    fmt_path(&entry.ed25519_pub_path)
                )));
                lines.push(Line::from(format!(
                    "  • Ed25519 私钥 [绝密 · 签名身份 · 务必备份]:  {}",
                    fmt_path(&entry.ed25519_enc_path)
                )));
                lines.push(Line::from(format!(
                    "  • X25519 公钥  [可公开 · 发给他人给你加密]:   {}",
                    fmt_path(&entry.x25519_pub_path)
                )));
                lines.push(Line::from(format!(
                    "  • X25519 私钥  [绝密核心 · 解密唯一凭证!]:   {}",
                    fmt_path(&entry.x25519_enc_path)
                )));
                lines.push(Line::from(format!(
                    "  • 恢复说明卡   [仅本机参考 · 非核心秘密]:     {}",
                    fmt_path(&entry.instr_path)
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "跨机解密要点：带走 x25519_private*.asc.enc + 口令即可在另一台电脑解密 .pubenc；切勿上传 .asc.enc。",
                    Style::default().fg(Color::Yellow),
                )));
                lines.push(Line::from(
                    "按 [?] 或 [F1] 打开完整文件指南（含 .pubenc / .enc / .decrypt.txt 的用途与保密要求）。",
                ));
            }
        }
        lines.push(Line::from(format!(
            "{} {}",
            app.lang.pick("Keystore Directory:", "密钥库目录:"),
            app.keystore_dir.display()
        )));
        lines
    } else {
        vec![
            Line::from(app.lang.pick("No keypair selected.", "未选中任何密钥对。")),
            Line::from(""),
            Line::from(app.lang.pick(
                "Press 'n' or Enter to generate a new password-protected Ed25519 + X25519 keypair.",
                "按 'n' 或 Enter 生成受口令保护的 Ed25519 + X25519 密钥对。",
            )),
            Line::from(app.lang.pick(
                "Press [?] or [F1] to read what each file means, who uses it, and secrecy rules.",
                "按 [?] 或 [F1] 查看各文件用途、受众及保密要求说明。",
            )),
            Line::from(format!(
                "{} {}",
                app.lang.pick("Active Keystore Directory:", "当前密钥库目录:"),
                app.keystore_dir.display()
            )),
        ]
    };

    let details = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.lang.pick(" Keypair Details & File Roles ", " 密钥详情与文件说明 ")),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(details, cols[1]);
}

fn render_encrypt_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let recipients = app.recipient_keyring_entries();
    let ext_idx = app.external_recipient_choice_idx();
    let own_signers = app.own_signing_keys();

    let recipient_label = if app.enc_key_choice == 0 {
        app.lang
            .pick(
                "<✨ Generate Fresh Ed25519 + X25519 Keypair>",
                "<✨ 新建 Ed25519 + X25519 密钥对>",
            )
            .to_string()
    } else if app.enc_key_choice == 1 {
        app.lang
            .pick(
                "<🔐 Symmetric Password Only (.enc / SGPGv2)>",
                "<🔐 纯口令对称加密 (.enc / SGPGv2，跨机单文件)>",
            )
            .to_string()
    } else if app.enc_key_choice >= 2 && app.enc_key_choice < ext_idx {
        if let Some(k) = recipients.get(app.enc_key_choice - 2) {
            let tag = if k.x25519_enc_path.is_some() {
                app.lang.pick("Own Key", "本机自有")
            } else {
                app.lang.pick("Peer Key", "对端公钥")
            };
            format!("🔑 {} ({}): {}", k.display_name(), tag, &k.fingerprint[..12])
        } else {
            app.lang.pick("<None>", "<无>").to_string()
        }
    } else {
        app.lang
            .pick(
                "<📄 External X25519 Public Key (.asc file)>",
                "<📄 外部接收方 X25519 公钥 (.asc 文件)>",
            )
            .to_string()
    };

    let ext_key_value = if app.enc_key_choice == ext_idx {
        if app.enc_external_pub_path.is_empty() {
            app.lang
                .pick(
                    "<Enter to type, or press 'f' / Ctrl+O to select x25519_public_*.asc>",
                    "<按 Enter 输入路径，或按 'f' / Ctrl+O 浏览选择 x25519_public_*.asc>",
                )
                .to_string()
        } else {
            app.enc_external_pub_path.clone()
        }
    } else if app.enc_external_pub_path.is_empty() {
        app.lang
            .pick(
                "<N/A — press Enter or 'f' here to switch to external .asc file>",
                "<当前未启用 — 在此按 Enter 或 'f' 可切换为外部 .asc 公钥文件>",
            )
            .to_string()
    } else {
        match app.lang {
            UiLang::En => {
                format!("{} (inactive — select External mode above)", app.enc_external_pub_path)
            }
            UiLang::Zh => {
                format!("{} (未生效 — 需在上方选择外部公钥模式)", app.enc_external_pub_path)
            }
        }
    };

    let sig_desc = if app.enc_key_choice == 1 {
        app.lang
            .pick(
                "N/A (Symmetric Argon2id + XChaCha20-Poly1305 AEAD)",
                "不适用（纯口令对称加密 Argon2id + XChaCha20-Poly1305）",
            )
            .to_string()
    } else if app.enc_key_choice == 0 {
        app.lang
            .pick(
                "[x] Auto (Sign with newly generated Ed25519 key)",
                "[x] 自动签名（使用本次新生成的 Ed25519 私钥）",
            )
            .to_string()
    } else if !app.enc_sign_file {
        app.lang
            .pick(
                "[ ] Unsigned (X25519 AEAD only — ←/→ or Space to sign)",
                "[ ] 不签名（仅 X25519 AEAD 加密 — ←/→ 或空格开启签名）",
            )
            .to_string()
    } else if let Some(sk) = own_signers.get(app.enc_sign_key_idx) {
        match app.lang {
            UiLang::En => format!("[x] Sign with Own Key: {}", sk.display_name()),
            UiLang::Zh => format!("[x] 使用本机私钥签名: {}", sk.display_name()),
        }
    } else {
        app.lang
            .pick(
                "⚠️ No own Ed25519 signing key in keystore (press Space for Unsigned)",
                "⚠️ 本机暂无可用于签名的 Ed25519 私钥（按空格切回不签名）",
            )
            .to_string()
    };

    let instr_desc = if app.enc_key_choice == 1 {
        app.lang.pick("N/A (Symmetric mode)", "不适用（纯口令对称模式）").to_string()
    } else if app.enc_no_instructions {
        app.lang
            .pick(
                "[x] Skip .decrypt.txt (default, privacy-safe)",
                "[x] 跳过伴随指引 .decrypt.txt（默认防泄密）",
            )
            .to_string()
    } else {
        app.lang
            .pick(
                "[ ] Skip .decrypt.txt (currently WRITING <output>.decrypt.txt)",
                "[ ] 跳过伴随指引（当前将写入 <输出>.decrypt.txt）",
            )
            .to_string()
    };

    let field_line = |idx: usize, label: &str, value: String| -> Line {
        let active = app.enc_focus == idx;
        let editing = active && app.enc_editing && matches!(idx, 0 | 1 | 3);
        let marker = if editing {
            "✎ "
        } else if active {
            "▶ "
        } else {
            "  "
        };
        let style = if editing {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else if active {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        Line::from(Span::styled(
            format!("{}{} {}", marker, pad_display_width(label, 28), value),
            style,
        ))
    };

    let lines = vec![
        Line::from(app.lang.pick(
            "↑/↓: Navigate | Enter: Edit/Toggle | 'f' / Ctrl+O: File Browser | Ctrl+U: Clear",
            "↑/↓: 切换字段 | Enter: 编辑/切换 | 'f' / Ctrl+O: 浏览文件 | Ctrl+U: 清空 | ?: 说明",
        )),
        Line::from(""),
        field_line(
            0,
            app.lang.pick("1. Input File:", "1. 待加密文件:"),
            if app.enc_input_path.is_empty() {
                app.lang
                    .pick(
                        "<Enter to type, or press 'f' / Ctrl+O to browse files>",
                        "<按 Enter 输入路径，或按 'f' / Ctrl+O 打开文件浏览器>",
                    )
                    .into()
            } else {
                app.enc_input_path.clone()
            },
        ),
        field_line(
            1,
            app.lang.pick("2. Output File (optional):", "2. 输出路径 (可选):"),
            if app.enc_output_path.is_empty() {
                if app.enc_key_choice == 1 {
                    app.lang
                        .pick(
                            "<default: anonymous <random>.enc>",
                            "<默认: 匿名随机名 <random>.enc>",
                        )
                        .into()
                } else {
                    app.lang
                        .pick(
                            "<default: anonymous <random>.pubenc>",
                            "<默认: 匿名随机名 <random>.pubenc>",
                        )
                        .into()
                }
            } else {
                app.enc_output_path.clone()
            },
        ),
        field_line(
            2,
            app.lang.pick("3. Recipient / Mode (←/→):", "3. 接收方 / 模式 (←/→):"),
            recipient_label,
        ),
        field_line(
            3,
            app.lang.pick("4. External PubKey (.asc):", "4. 外部公钥 (.asc):"),
            ext_key_value,
        ),
        field_line(
            4,
            app.lang.pick("5. Signing Key (←/→/Space):", "5. 签名私钥 (←/→/空格):"),
            sig_desc,
        ),
        field_line(
            5,
            app.lang.pick("6. Companion .decrypt.txt:", "6. 伴随解密指引文件:"),
            instr_desc,
        ),
        field_line(
            6,
            app.lang.pick("7. Overwrite (--force):", "7. 覆盖已有输出 (--force):"),
            if app.enc_force {
                app.lang.pick("[x] Yes", "[x] 允许覆盖").into()
            } else {
                app.lang.pick("[ ] No (Safe create_new)", "[ ] 否（安全禁止覆盖）").into()
            },
        ),
        Line::from(""),
        field_line(
            7,
            app.lang.pick("Action:", "执行操作:"),
            app.lang
                .pick("[ 🚀 Execute Encryption (Press Enter) ]", "[ 🚀 开始加密 (按 Enter 执行) ]")
                .into(),
        ),
    ];

    let panel = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(app.lang.pick(
            " File Encryption (Decoupled Recipient & Own Signing Key | Symmetric SGPGv2) ",
            " 文件加密（非对称公钥 .pubenc 可分离签名 | 纯口令对称 .enc） ",
        )))
        .wrap(Wrap { trim: false });
    frame.render_widget(panel, area);
}

fn render_decrypt_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let own_dec_keys = app.own_decrypt_keys();
    let is_sym_file = matches!(
        app.dec_inspected,
        Some(Ok(InspectedFile::Sgpg(ref s))) if s.blob_type.as_deref() == Some("file")
    );
    let has_explicit_signer = app.dec_signer_choice > 0 || !app.dec_signer_arg.trim().is_empty();

    let key_label = if is_sym_file {
        app.lang.pick("<N/A — Symmetric (Password Only)>", "<不适用 — 纯口令对称文件>").to_string()
    } else if let Some(k) = own_dec_keys.get(app.dec_key_idx) {
        format!("🔑 {}", k.display_name())
    } else {
        app.lang
            .pick("<No Own X25519 Private Key in keystore>", "<本机密钥库无 X25519 解密私钥>")
            .to_string()
    };

    let signer_label = if !app.dec_signer_arg.trim().is_empty() {
        app.dec_signer_arg.clone()
    } else if app.dec_signer_choice > 0 {
        if let Some(peer) = app.keyring.get(app.dec_signer_choice - 1) {
            format!("👤 {}: {}", app.lang.pick("Keyring", "密钥环"), peer.display_name())
        } else {
            app.lang.pick("<Self: Decryption Key Owner>", "<自身：与解密密钥同属主>").to_string()
        }
    } else if is_sym_file {
        app.lang.pick("<N/A — Symmetric (Unsigned)>", "<不适用 — 纯口令对称（无签名）>").to_string()
    } else {
        app.lang.pick("<Self: Decryption Key Owner>", "<自身：与解密密钥同属主>").to_string()
    };

    let require_sig_label = if is_sym_file {
        app.lang.pick("<N/A — Symmetric (Unsigned)>", "<不适用 — 纯口令对称（无签名）>").to_string()
    } else if app.dec_require_sig {
        app.lang.pick("[x] Yes", "[x] 是（必须验签）").to_string()
    } else {
        app.lang.pick("[ ] Optional", "[ ] 可选（允许无签名）").to_string()
    };

    let field_line = |idx: usize, label: &str, value: String| -> Line {
        let active = app.dec_focus == idx;
        let editing = active && app.dec_editing && (idx == 0 || idx == 1 || idx == 3);
        let marker = if editing {
            "✎ "
        } else if active {
            "▶ "
        } else {
            "  "
        };
        let style = if editing {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else if active {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        Line::from(Span::styled(
            format!("{}{} {}", marker, pad_display_width(label, 26), value),
            style,
        ))
    };

    let form_lines = vec![
        Line::from(app.lang.pick(
            "↑/↓: Move | ←/→: Cycle Key/Signer | Enter: Edit/Run | 'f'/Ctrl+O: Browse",
            "↑/↓: 切换字段 | ←/→: 切换密钥/签名方 | Enter: 编辑/解密 | 'f'/Ctrl+O: 浏览",
        )),
        Line::from(""),
        field_line(
            0,
            app.lang.pick("1. Encrypted File:", "1. 待解密文件:"),
            if app.dec_input_path.is_empty() {
                app.lang
                    .pick(
                        "<Enter to type, or press 'f' / Ctrl+O to browse .pubenc/.enc>",
                        "<按 Enter 输入路径，或按 'f' / Ctrl+O 浏览 .pubenc/.enc 文件>",
                    )
                    .into()
            } else {
                app.dec_input_path.clone()
            },
        ),
        field_line(
            1,
            app.lang.pick("2. Output File (opt):", "2. 输出路径 (可选):"),
            if app.dec_output_path.is_empty() {
                app.lang
                    .pick("<default: strip .pubenc / .enc>", "<默认: 去除 .pubenc / .enc 后缀>")
                    .into()
            } else {
                app.dec_output_path.clone()
            },
        ),
        field_line(2, app.lang.pick("3. Private Key (←/→):", "3. 解密私钥 (←/→):"), key_label),
        field_line(
            3,
            app.lang.pick("4. Expected Signer (←/→):", "4. 期望签名方 (←/→):"),
            signer_label,
        ),
        field_line(4, app.lang.pick("5. Require Signature:", "5. 强制验签:"), require_sig_label),
        field_line(
            5,
            app.lang.pick("6. Overwrite (--force):", "6. 覆盖输出 (--force):"),
            if app.dec_force {
                app.lang.pick("[x] Yes", "[x] 允许覆盖").into()
            } else {
                app.lang.pick("[ ] No", "[ ] 否").into()
            },
        ),
        Line::from(""),
        field_line(
            6,
            app.lang.pick("Action:", "执行操作:"),
            app.lang.pick("[ 🔓 Decrypt & Verify ]", "[ 🔓 解密并验签 ]").into(),
        ),
    ];

    let form =
        Paragraph::new(form_lines)
            .block(Block::default().borders(Borders::ALL).title(
                app.lang.pick(
                    " Decrypt & Verify (Verify-Before-Write) ",
                    " 解密与验签（先验签后落盘） ",
                ),
            ))
            .wrap(Wrap { trim: false });
    frame.render_widget(form, cols[0]);

    let mut inspect_lines = vec![Line::from(Span::styled(
        app.lang.pick("Streaming File Header Inspector:", "免口令流式密文头透视:"),
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ))];
    match &app.dec_inspected {
        None => {
            inspect_lines.push(Line::from(app.lang.pick(
                "  Enter a .pubenc or .enc file path on the left to inspect its header without a password.",
                "  在左侧输入或选择 .pubenc / .enc 文件路径，即可免口令透视密文头与签名状态。",
            )));
        }
        Some(Ok(InspectedFile::Pubenc(info))) => {
            inspect_lines.push(Line::from(match (info.format_version, app.lang) {
                (2, UiLang::En) => "  • Container Format:   SCFv2 (Hybrid · Hidden Sig/Len)",
                (2, UiLang::Zh) => {
                    "  • 容器格式:           SCFv2 (公钥混合加密 · 内层防比对签名与长度填充)"
                }
                (_, UiLang::En) => "  • Container Format:   SCFv1 (Hybrid Public-Key)",
                (_, UiLang::Zh) => "  • 容器格式:           SCFv1 (X25519 公钥混合加密)",
            }));
            inspect_lines.push(Line::from(format!(
                "  • {} {}",
                app.lang.pick("Embedded Signature:", "内嵌签名:"),
                match info.has_signature {
                    None => app
                        .lang
                        .pick("🔒 Concealed in AEAD", "🔒 已随密文内层加密（解密时先验签后落盘）",),
                    Some(true) => app.lang.pick("✅ Present (Ed25519)", "✅ 已包含 (Ed25519)"),
                    Some(false) => app.lang.pick("⚠️ None (Unsigned)", "⚠️ 无签名 (Unsigned)"),
                }
            )));
            inspect_lines.push(Line::from(format!(
                "  • {} {}",
                app.lang.pick("Length Padding:    ", "长度混淆填充:    "),
                if info.padding_enabled {
                    app.lang.pick("Enabled (Random+Padme)", "已开启（随机扰动 + Padme 对齐）")
                } else {
                    app.lang.pick("None (Legacy SCFv1)", "未开启（遗留 SCFv1）")
                }
            )));
            if let Some(ref fp) = info.signer_fingerprint {
                let known_label = app
                    .keyring
                    .iter()
                    .find(|k| k.fingerprint.eq_ignore_ascii_case(fp))
                    .map(|k| k.display_name());
                inspect_lines.push(Line::from(format!(
                    "  • {} {}",
                    app.lang.pick("Claimed Signer FP: ", "声称签名指纹:"),
                    fp
                )));
                if let Some(lbl) = known_label {
                    inspect_lines.push(Line::from(format!(
                        "  • {} {}",
                        app.lang.pick("Local Keyring:     ", "本机密钥环:  "),
                        lbl
                    )));
                } else {
                    inspect_lines.push(Line::from(app.lang.pick(
                        "  • Local Keyring:      (Unknown external key)",
                        "  • 本机密钥环:         (未知外部签名公钥)",
                    )));
                }
            }
            inspect_lines.push(Line::from(format!(
                "  • {} {}…",
                app.lang.pick("Ephemeral X25519:  ", "临时 X25519 公钥:"),
                &info.ephemeral_pub_hex[..24]
            )));
            inspect_lines.push(Line::from(format!(
                "  • {} {} {}",
                app.lang.pick("Ciphertext Size:   ", "密文载荷大小:    "),
                info.ciphertext_len,
                app.lang.pick("bytes", "字节")
            )));

            // H-1 安全预警：当未认证密文头声称的签名者与当前显式选定的 Expected Signer 不一致时标黄提示
            if let (Some(ref header_fp), Some(expected_fp)) =
                (&info.signer_fingerprint, app.effective_expected_signer_fp())
            {
                if !header_fp.eq_ignore_ascii_case(&expected_fp) {
                    inspect_lines.push(Line::from(""));
                    inspect_lines.push(Line::from(Span::styled(
                        app.lang.pick(
                            "  ⚠️ Header Signer != Expected Signer!",
                            "  ⚠️ 密文头声称的签名方 != 当前期望签名方！",
                        ),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )));
                    inspect_lines.push(Line::from(Span::styled(
                        app.lang.pick(
                            "     Decryption will REJECT unless '4. Expected Signer' matches.",
                            "     除非在字段 4 中切换为该发送方公钥，否则解密将拒绝输出。",
                        ),
                        Style::default().fg(Color::Yellow),
                    )));
                    inspect_lines.push(Line::from(Span::styled(
                        app.lang.pick(
                            "     Switch field 4 with ←/→ ONLY if you trust this sender.",
                            "     仅在您确认信任该发送方身份时，用 ←/→ 切换字段 4。",
                        ),
                        Style::default().fg(Color::Yellow),
                    )));
                }
            } else if info.has_signature == Some(false)
                && (app.dec_require_sig || has_explicit_signer)
            {
                inspect_lines.push(Line::from(""));
                inspect_lines.push(Line::from(Span::styled(
                    app.lang.pick(
                        "  ⚠️ File Is Unsigned, but Signature Verification Is Enabled!",
                        "  ⚠️ 该文件无签名，但当前已开启强制验签！",
                    ),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )));
                inspect_lines.push(Line::from(Span::styled(
                    app.lang.pick(
                        "     Decryption will REJECT unless signature requirement is disabled.",
                        "     除非关闭字段 5“强制验签”并清空字段 4，否则解密将被拒绝。",
                    ),
                    Style::default().fg(Color::Yellow),
                )));
            }
        }
        Some(Ok(InspectedFile::Sgpg(info))) => {
            inspect_lines.push(Line::from(match (info.format_version, app.lang) {
                (2, UiLang::En) => "  • Container Format:   SGPGv2 (Symmetric · Length-Hiding)",
                (2, UiLang::Zh) => {
                    "  • 容器格式:           SGPGv2 (Argon2id 口令保护 · 长度混淆填充)"
                }
                (_, UiLang::En) => "  • Container Format:   SGPGv1 (Password-Protected)",
                (_, UiLang::Zh) => "  • 容器格式:           SGPGv1 (Argon2id 口令保护容器)",
            }));
            inspect_lines.push(Line::from(format!(
                "  • {} {}",
                app.lang.pick("Length Padding:    ", "长度混淆填充:    "),
                if info.padding_enabled {
                    app.lang.pick("Enabled (Random+Padme)", "已开启（随机扰动 + Padme 对齐）")
                } else {
                    app.lang.pick("None (Legacy SGPGv1)", "未开启（遗留 SGPGv1）")
                }
            )));
            if info.blob_type.as_deref() == Some("file") {
                inspect_lines.push(Line::from(app.lang.pick(
                    "  • Embedded Signature: ⚠️ None (Symmetric password-only container)",
                    "  • 内嵌签名:           ⚠️ 无（纯口令对称文件无数字签名）",
                )));
            }
            inspect_lines.push(Line::from(format!(
                "  • {} {}",
                app.lang.pick("Payload Type:      ", "载荷类型 (AAD):  "),
                info.blob_type.as_deref().unwrap_or("unknown")
            )));
            inspect_lines.push(Line::from(format!(
                "  • {} {} MiB, t={}, p={}",
                app.lang.pick("Argon2id Params:   ", "Argon2id 参数:   "),
                info.mem_kib / 1024,
                info.t_cost,
                info.p_cost
            )));
            if let Some(ref fp) = info.fingerprint {
                inspect_lines.push(Line::from(format!(
                    "  • {} {}",
                    app.lang.pick("Bound Fingerprint: ", "绑定密钥指纹:    "),
                    fp
                )));
            }
            inspect_lines.push(Line::from(format!(
                "  • {} {} {}",
                app.lang.pick("Ciphertext Size:   ", "密文载荷大小:    "),
                info.ciphertext_len,
                app.lang.pick("bytes", "字节")
            )));

            if info.blob_type.as_deref() != Some("file") {
                inspect_lines.push(Line::from(""));
                inspect_lines.push(Line::from(Span::styled(
                    app.lang.pick(
                        "  ⚠️ Private Key Backup File (NOT an encrypted data file)!",
                        "  ⚠️ 这是私钥备份文件（不是普通加密数据文件）！",
                    ),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )));
                inspect_lines.push(Line::from(Span::styled(
                    app.lang.pick(
                        "     Select a .pubenc or symmetric .enc data file instead.",
                        "     请选择 .pubenc 公钥密文或纯口令对称 .enc 数据文件。",
                    ),
                    Style::default().fg(Color::Yellow),
                )));
            } else if has_explicit_signer {
                inspect_lines.push(Line::from(""));
                inspect_lines.push(Line::from(Span::styled(
                    app.lang.pick(
                        "  ⚠️ Explicit Expected Signer Set on Unsigned Symmetric File!",
                        "  ⚠️ 对无签名的纯口令对称文件设置了“期望签名方”！",
                    ),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )));
                inspect_lines.push(Line::from(Span::styled(
                    app.lang.pick(
                        "     Decryption will REJECT unless '4. Expected Signer' is reset.",
                        "     请重置字段 4 后再解密。",
                    ),
                    Style::default().fg(Color::Yellow),
                )));
            }
        }
        Some(Err(err)) => {
            inspect_lines.push(Line::from(Span::styled(
                format!("  ❌ {}", err),
                Style::default().fg(Color::Red),
            )));
        }
    }

    if let Some(ref verified) = app.dec_last_verified_fp {
        inspect_lines.push(Line::from(""));
        inspect_lines.push(Line::from(Span::styled(
            format!(
                "✅ {} {}",
                app.lang.pick("Last Verified Signer:", "最近一次已验签发送方:"),
                verified
            ),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )));
    }

    let inspector =
        Paragraph::new(inspect_lines)
            .block(Block::default().borders(Borders::ALL).title(
                app.lang.pick(" Live Header & Trust Inspector ", " 实时密文头透视与信任检查 "),
            ))
            .wrap(Wrap { trim: false });
    frame.render_widget(inspector, cols[1]);
}

fn render_password_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let pw_display = match &app.generated_password {
        None => app
            .lang
            .pick(
                "<Press Enter or 'g' to generate high-entropy password>",
                "<按 Enter 或 'g' 生成无模偏差高熵随机口令>",
            )
            .to_string(),
        Some(pw) if app.pw_reveal => pw.as_str().to_string(),
        Some(pw) => "•".repeat(pw.chars().count()),
    };

    let lines = vec![
        Line::from(app.lang.pick(
            "Rejection-sampled CSPRNG (OsRng) password generator:",
            "基于系统 CSPRNG (OsRng) 拒绝采样的高熵强口令生成器:",
        )),
        Line::from(""),
        Line::from(Span::styled(
            match app.lang {
                UiLang::En => format!("  Length (←/→ or -/+):   {} characters", app.pw_length),
                UiLang::Zh => format!("  口令长度 (←/→ 或 -/+): {} 位字符", app.pw_length),
            },
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "  {} {}",
            app.lang.pick("Visibility ('v'):     ", "显示模式 ('v'):       "),
            if app.pw_reveal {
                app.lang.pick("👁️  Plaintext Revealed", "👁️  明文可见")
            } else {
                app.lang.pick("🙈 Masked (Shoulder-Surf Safe)", "🙈 星号遮蔽（防窥视）")
            }
        )),
        Line::from(""),
        Line::from(Span::styled(
            app.lang.pick(
                "  Generated Password (Zeroized on tab switch / exit):",
                "  已生成口令（切换标签页或退出时自动清零内存）:",
            ),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            format!("  {}", pw_display),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(app.lang.pick(
            "  Shortcuts: [Enter / g] Generate New  |  [v] Toggle Mask  |  [c] Clear Memory",
            "  快捷键: [Enter / g] 生成新口令  |  [v] 明文/遮蔽切换  |  [c] 立即擦除内存",
        )),
    ];

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.lang.pick(" Strong Password Generator ", " 强口令生成器 ")),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(panel, area);
}

fn render_footer(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let color = match app.status_kind {
        StatusKind::Info => Color::Cyan,
        StatusKind::Success => Color::Green,
        StatusKind::Warning => Color::Yellow,
        StatusKind::Error => Color::Red,
    };

    let status = Paragraph::new(Line::from(Span::styled(
        format!(" {}", app.status_msg),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )))
    .block(Block::default().borders(Borders::ALL).title(app.lang.pick(" Status ", " 状态 ")));
    frame.render_widget(status, area);
}

fn push_modal_error(lines: &mut Vec<Line<'static>>, modal_error: &Option<String>) {
    if let Some(ref err) = modal_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", err),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
}

fn render_modal(frame: &mut Frame, app: &TuiApp) {
    let area = centered_rect(68, 56, frame.area());
    frame.render_widget(Clear, area);

    match &app.modal {
        ModalState::None => {}
        ModalState::PasswordPrompt { title, .. } => {
            let masked = "*".repeat(app.password_buf.chars().count());
            let mut lines = vec![
                Line::from(""),
                Line::from(app.lang.pick(
                    "  Enter password (Zeroizing buffer; Ctrl+U clears, Esc cancels):",
                    "  请输入口令（Zeroizing 安全缓冲；Ctrl+U 清空，Esc 取消）：",
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!("  > {}_", masked),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(app.lang.pick(
                    "  Press [Enter] to confirm, [Ctrl+U] to wipe input, or [Esc] to cancel.",
                    "  按 [Enter] 确认，[Ctrl+U] 清空输入，[Esc] 取消操作。",
                )),
            ];
            push_modal_error(&mut lines, &app.modal_error);
            let block = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::Cyan))
                        .title(format!(" 🔐 {} ", title)),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(block, area);
        }
        ModalState::SymmetricPassword { focus_field } => {
            let pw_mask = "*".repeat(app.password_buf.chars().count());
            let cf_mask = "*".repeat(app.confirm_buf.chars().count());
            let style_for = |idx: usize| {
                if *focus_field == idx {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                }
            };
            let mut lines = vec![
                Line::from(app.lang.pick(
                    "  Symmetric SGPGv2 Encryption (↑/↓/Tab to move, Ctrl+U to clear, Esc to cancel):",
                    "  纯口令对称加密 SGPGv2（↑/↓/Tab 切换，Ctrl+U 清空，Esc 取消）：",
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  {} {} {}",
                        if *focus_field == 0 { "▶" } else { " " },
                        pad_display_width(
                            app.lang.pick(
                                "Encryption Password (>=12 chars):",
                                "加密口令（至少 12 位字符）:",
                            ),
                            34
                        ),
                        pw_mask
                    ),
                    style_for(0),
                )),
                Line::from(Span::styled(
                    format!(
                        "  {} {} {}",
                        if *focus_field == 1 { "▶" } else { " " },
                        pad_display_width(
                            app.lang.pick("Confirm Password:", "确认加密口令:"),
                            34
                        ),
                        cf_mask
                    ),
                    style_for(1),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  {} {}",
                        if *focus_field == 2 { "▶" } else { " " },
                        app.lang.pick(
                            "[ 🔐 Derive Argon2id Key & Encrypt (.enc) ]",
                            "[ 🔐 派生 Argon2id 密钥并执行对称加密 (.enc) ]",
                        ),
                    ),
                    style_for(2),
                )),
            ];
            push_modal_error(&mut lines, &app.modal_error);
            let block = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::Cyan))
                        .title(app.lang.pick(
                            " 🔐 Confirm Symmetric Encryption Password ",
                            " 🔐 设置纯口令对称加密口令 ",
                        )),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(block, area);
        }
        ModalState::NewKeypair { for_encrypt, auto_generate, focus_field } => {
            let title = if *for_encrypt {
                app.lang.pick("Generate Keypair & Encrypt File", "生成新密钥对并加密文件")
            } else {
                app.lang.pick(
                    "Generate New Protected Keypair (Ed25519 + X25519)",
                    "新建受口令保护的密钥对 (Ed25519 + X25519)",
                )
            };
            let pw_mask = "*".repeat(app.password_buf.chars().count());
            let cf_mask = "*".repeat(app.confirm_buf.chars().count());

            let style_for = |idx: usize| {
                if *focus_field == idx {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                }
            };

            let auto_placeholder = app.lang.pick("<auto-generated>", "<自动高熵生成>");
            let mut lines = vec![
                Line::from(app.lang.pick(
                    "  ↑/↓/Tab: Move | Space: Toggle Auto-Gen | Ctrl+U: Clear | Esc: Cancel",
                    "  ↑/↓/Tab 切换 | 空格 切换自动生成强口令 | Ctrl+U 清空 | Esc 取消",
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  {} {}: {}",
                        if *focus_field == 0 { "▶" } else { " " },
                        app.lang.pick(
                            "Auto-generate 48-byte random backup password",
                            "自动生成 48 字节高熵随机私钥备份口令",
                        ),
                        if *auto_generate {
                            app.lang.pick("[x] Yes", "[x] 是（推荐）")
                        } else {
                            app.lang
                                .pick("[ ] No (User-defined password)", "[ ] 否（手动输入口令）")
                        }
                    ),
                    style_for(0),
                )),
                Line::from(Span::styled(
                    format!(
                        "  {} {} {}",
                        if *focus_field == 1 { "▶" } else { " " },
                        pad_display_width(
                            app.lang.pick(
                                "Backup Password (>=12 chars):",
                                "私钥备份口令（>=12 字符）:",
                            ),
                            31
                        ),
                        if *auto_generate { auto_placeholder } else { &pw_mask }
                    ),
                    style_for(1),
                )),
                Line::from(Span::styled(
                    format!(
                        "  {} {} {}",
                        if *focus_field == 2 { "▶" } else { " " },
                        pad_display_width(app.lang.pick("Confirm Password:", "确认备份口令:"), 31),
                        if *auto_generate { auto_placeholder } else { &cf_mask }
                    ),
                    style_for(2),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  {} {}",
                        if *focus_field == 3 { "▶" } else { " " },
                        app.lang.pick(
                            "[ 🔐 Generate & Encrypt Keys (Argon2id 64 MiB) ]",
                            "[ 🔐 生成并加密存储密钥对 (Argon2id 64 MiB) ]",
                        ),
                    ),
                    style_for(3),
                )),
            ];
            push_modal_error(&mut lines, &app.modal_error);

            let block = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::Cyan))
                        .title(format!(" {} ", title)),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(block, area);
        }
        ModalState::ChangeKeyPassword { display_name, focus_field, .. } => {
            let old_mask = "*".repeat(app.old_password_buf.chars().count());
            let new_mask = "*".repeat(app.password_buf.chars().count());
            let cf_mask = "*".repeat(app.confirm_buf.chars().count());
            let style_for = |idx: usize| {
                if *focus_field == idx {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                }
            };
            let mut lines = vec![
                Line::from(match app.lang {
                    UiLang::En => {
                        format!("  Rotate Ed25519 + X25519 Backup Password for {}:", display_name)
                    }
                    UiLang::Zh => {
                        format!("  同步轮换 {} 的 Ed25519 + X25519 私钥备份口令：", display_name)
                    }
                }),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  {} {} {}",
                        if *focus_field == 0 { "▶" } else { " " },
                        pad_display_width(app.lang.pick("Current Password:", "当前备份口令:"), 30),
                        old_mask
                    ),
                    style_for(0),
                )),
                Line::from(Span::styled(
                    format!(
                        "  {} {} {}",
                        if *focus_field == 1 { "▶" } else { " " },
                        pad_display_width(
                            app.lang.pick("New Password (>=12 chars):", "新口令（至少 12 位）:"),
                            30
                        ),
                        new_mask
                    ),
                    style_for(1),
                )),
                Line::from(Span::styled(
                    format!(
                        "  {} {} {}",
                        if *focus_field == 2 { "▶" } else { " " },
                        pad_display_width(
                            app.lang.pick("Confirm New Password:", "确认新口令:"),
                            30
                        ),
                        cf_mask
                    ),
                    style_for(2),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  {} {}",
                        if *focus_field == 3 { "▶" } else { " " },
                        app.lang.pick(
                            "[ 🔄 Re-Encrypt Both Private Keys ]",
                            "[ 🔄 重新加密两份私钥备份 ]",
                        ),
                    ),
                    style_for(3),
                )),
            ];
            push_modal_error(&mut lines, &app.modal_error);
            let block =
                Paragraph::new(lines)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .style(Style::default().fg(Color::Cyan))
                            .title(app.lang.pick(
                                " 🔄 Rotate Keypair Backup Password ",
                                " 🔄 轮换私钥备份口令 ",
                            )),
                    )
                    .wrap(Wrap { trim: false });
            frame.render_widget(block, area);
        }
        ModalState::SetKeyLabel { display_name, .. } => {
            let mut lines = vec![
                Line::from(match app.lang {
                    UiLang::En => format!("  Assign local petname/alias for {}:", display_name),
                    UiLang::Zh => format!("  为密钥 {} 设置本机识别别名：", display_name),
                }),
                Line::from(app.lang.pick(
                    "  (Stored ONLY in local 0600 labels.tsv — never written to ciphertexts)",
                    "  (仅保存在本机 0600 labels.tsv 中 — 绝不写入任何加密密文)",
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!("  > {}_", app.label_input_buf),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(app.lang.pick(
                    "  Leave empty and press [Enter] to clear label, or [Esc] to cancel.",
                    "  留空按 [Enter] 可清除现有别名，按 [Esc] 取消。",
                )),
            ];
            push_modal_error(&mut lines, &app.modal_error);
            let block = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::Cyan))
                        .title(app.lang.pick(" 🏷️  Local Key Label ", " 🏷️  本机密钥别名 ")),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(block, area);
        }
        ModalState::GeneratedPasswordDisplay { fingerprint, confirmed_saved, .. } => {
            let pw_area = centered_rect_min(82, 78, 68, 18, frame.area());
            frame.render_widget(Clear, pw_area);
            let pw_str = app.one_time_backup_pass.as_ref().map(|s| s.as_str()).unwrap_or("");
            let mut lines = vec![
                Line::from(Span::styled(
                    app.lang.pick(
                        "⚠️ SAVE THIS BACKUP PASSWORD NOW! It wipes on close:",
                        "⚠️ 请立即保存此备份口令！关闭弹窗后将立即清零：",
                    ),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    app.lang.pick(
                        "Purpose: Unlocks your new .asc.enc private key to decrypt later",
                        "用途：用于解锁刚生成的 .asc.enc 私钥，日后解密文件必须凭此口令",
                    ),
                    Style::default().fg(Color::Cyan),
                )),
                Line::from(format!(
                    "{} {}",
                    app.lang.pick("Key Fingerprint:", "密钥指纹:"),
                    fingerprint
                )),
            ];
            if let Some(ref enc_file) = app.backup_modal_encrypted_file {
                lines.push(Line::from(Span::styled(
                    format!(
                        "{} {}",
                        app.lang.pick("✅ Encrypted Output:", "✅ 加密完成，输出文件:"),
                        enc_file.display()
                    ),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )));
            }
            lines.extend([
                Line::from(app.lang.pick(
                    "Backup Password (standalone line below):",
                    "私钥备份口令（下方独立整行，便于复制）：",
                )),
                Line::from(Span::styled(
                    pw_str.to_string(),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "{} {}",
                        if *confirmed_saved { "[x]" } else { "[ ]" },
                        app.lang.pick(
                            "I have saved this backup password securely ([Space] to check)",
                            "我已安全抄录/保存该备份口令（按 [空格] 勾选确认）",
                        ),
                    ),
                    Style::default()
                        .fg(if *confirmed_saved { Color::Green } else { Color::Yellow })
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(if app.pending_post_backup_summary.is_some() {
                    app.lang.pick(
                        "[p] Plain Copy View (no borders) | [Enter] Wipe & View Summary",
                        "[p] 纯文本无边框复制视图 | [Enter] 清零并查看加密结果",
                    )
                } else {
                    app.lang.pick(
                        "[p] Plain Copy View (no borders) | [Enter] Wipe & Close",
                        "[p] 纯文本无边框复制视图 | [Enter] 清零并关闭",
                    )
                }),
            ]);
            push_modal_error(&mut lines, &app.modal_error);
            let block = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::Yellow))
                        .title(app.lang.pick(
                            " 🔐 One-Time Backup Password (Confirmation Lock Active) ",
                            " 🔐 一次性私钥备份口令（防误关锁定中） ",
                        )),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(block, pw_area);
        }
        ModalState::OperationSummary {
            kind,
            output_path,
            key_fingerprint,
            verified_signer_fp,
            companion_instr,
        } => {
            let sum_area = centered_rect_min(78, 72, 68, 17, frame.area());
            frame.render_widget(Clear, sum_area);

            let (title, mode_desc) = match (kind, app.lang) {
                (SummaryKind::EncryptNewKeypair, UiLang::En) => (
                    " ✅ Encryption Completed ",
                    "Hybrid Public-Key + Ed25519 Signature (Fresh Keypair)",
                ),
                (SummaryKind::EncryptNewKeypair, UiLang::Zh) => (
                    " ✅ 加密已完成 ",
                    "SCFv2 非对称公钥混合加密 + 内层加密 Ed25519 签名（新建密钥对）",
                ),
                (SummaryKind::EncryptExistingSigned, UiLang::En) => (
                    " ✅ Encryption Completed ",
                    "Hybrid Public-Key + Encrypted Ed25519 Signature (SCFv2)",
                ),
                (SummaryKind::EncryptExistingSigned, UiLang::Zh) => {
                    (" ✅ 加密已完成 ", "SCFv2 非对称公钥混合加密 + 内层加密 Ed25519 签名")
                }
                (SummaryKind::EncryptExistingUnsigned, UiLang::En) => {
                    (" ✅ Encryption Completed ", "Hybrid Public-Key Only — Unsigned (SCFv2)")
                }
                (SummaryKind::EncryptExistingUnsigned, UiLang::Zh) => {
                    (" ✅ 加密已完成 ", "SCFv2 非对称公钥混合加密（无签名，长度混淆填充）")
                }
                (SummaryKind::EncryptSymmetric, UiLang::En) => {
                    (" ✅ Encryption Completed ", "Symmetric Password-Only Encryption (SGPGv2)")
                }
                (SummaryKind::EncryptSymmetric, UiLang::Zh) => {
                    (" ✅ 加密已完成 ", "SGPGv2 纯口令对称加密（无需私钥，含长度混淆填充）")
                }
                (SummaryKind::DecryptPubenc, UiLang::En) => (
                    " ✅ Decryption & Verification Completed ",
                    "Hybrid Public-Key Decryption (SCFv1/SCFv2, Verified Before Write)",
                ),
                (SummaryKind::DecryptPubenc, UiLang::Zh) => {
                    (" ✅ 解密与验签已完成 ", "SCFv1/SCFv2 非对称公钥解密（已先验签后落盘）")
                }
                (SummaryKind::DecryptSymmetric, UiLang::En) => (
                    " ✅ Decryption Completed ",
                    "Symmetric Password-Only Decryption (SGPGv1/SGPGv2)",
                ),
                (SummaryKind::DecryptSymmetric, UiLang::Zh) => {
                    (" ✅ 解密已完成 ", "SGPGv1/SGPGv2 纯口令对称解密")
                }
            };

            let mut lines = vec![
                Line::from(Span::styled(
                    format!("  {} {}", app.lang.pick("Mode:  ", "模式："), mode_desc),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    format!("  {} {}", app.lang.pick("Output:", "产物："), output_path.display()),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )),
            ];

            if let Some(ref fp) = key_fingerprint {
                let lbl = match (kind, app.lang) {
                    (SummaryKind::DecryptPubenc, UiLang::En) => "Decryption Key FP:",
                    (SummaryKind::DecryptPubenc, UiLang::Zh) => "解密密钥指纹：",
                    (_, UiLang::En) => "Key Fingerprint:  ",
                    (_, UiLang::Zh) => "加密密钥指纹：",
                };
                lines.push(Line::from(format!("  {} {}", lbl, fp)));
            }

            let sig_line = match (kind, verified_signer_fp.as_deref(), app.lang) {
                (SummaryKind::EncryptNewKeypair, _, UiLang::En)
                | (SummaryKind::EncryptExistingSigned, _, UiLang::En) => {
                    Some(Line::from("  Signature:          ✅ Embedded Ed25519 signature"))
                }
                (SummaryKind::EncryptNewKeypair, _, UiLang::Zh)
                | (SummaryKind::EncryptExistingSigned, _, UiLang::Zh) => {
                    Some(Line::from("  数字签名：          ✅ 已内嵌 Ed25519 防篡改签名"))
                }
                (SummaryKind::EncryptExistingUnsigned, _, UiLang::En) => {
                    Some(Line::from(Span::styled(
                        "  Signature:          ⚠️ Unsigned (confidentiality only)",
                        Style::default().fg(Color::Yellow),
                    )))
                }
                (SummaryKind::EncryptExistingUnsigned, _, UiLang::Zh) => {
                    Some(Line::from(Span::styled(
                        "  数字签名：          ⚠️ 无签名（仅保密加密）",
                        Style::default().fg(Color::Yellow),
                    )))
                }
                (SummaryKind::DecryptPubenc, Some(fp), UiLang::En) => {
                    Some(Line::from(Span::styled(
                        format!("  Verified Signer:    ✅ {}", fp),
                        Style::default().fg(Color::Green),
                    )))
                }
                (SummaryKind::DecryptPubenc, Some(fp), UiLang::Zh) => {
                    Some(Line::from(Span::styled(
                        format!("  已验证签名方：      ✅ {}", fp),
                        Style::default().fg(Color::Green),
                    )))
                }
                (SummaryKind::DecryptPubenc, None, UiLang::En) => Some(Line::from(Span::styled(
                    "  Signature Status:   ⚠️ No Ed25519 signature present (unsigned accepted)",
                    Style::default().fg(Color::Yellow),
                ))),
                (SummaryKind::DecryptPubenc, None, UiLang::Zh) => Some(Line::from(Span::styled(
                    "  签名状态：          ⚠️ 原密文无 Ed25519 签名（已按设置允许无签名解密）",
                    Style::default().fg(Color::Yellow),
                ))),
                (SummaryKind::EncryptSymmetric | SummaryKind::DecryptSymmetric, _, _) => None,
            };
            if let Some(l) = sig_line {
                lines.push(l);
            }

            match (companion_instr, app.lang) {
                (CompanionInstrStatus::Written(p), UiLang::En) => {
                    lines.push(Line::from(format!(
                        "  Companion Guide:    {} (filename-only note)",
                        p.display()
                    )));
                }
                (CompanionInstrStatus::Written(p), UiLang::Zh) => {
                    lines.push(Line::from(format!(
                        "  伴随解密指引：      {}（仅文件名参考，不含密码）",
                        p.display()
                    )));
                }
                (CompanionInstrStatus::Skipped, UiLang::En) => {
                    lines.push(Line::from("  Companion Guide:    Skipped (privacy default)"));
                }
                (CompanionInstrStatus::Skipped, UiLang::Zh) => {
                    lines.push(Line::from("  伴随解密指引：      已跳过生成（默认防泄密）"));
                }
                (CompanionInstrStatus::NotOverwritten(p), UiLang::En) => {
                    lines.push(Line::from(format!(
                        "  Companion Guide:    Existing file preserved ({})",
                        p.display()
                    )));
                }
                (CompanionInstrStatus::NotOverwritten(p), UiLang::Zh) => {
                    lines.push(Line::from(format!(
                        "  伴随解密指引：      保留已有同名文件未覆盖 ({})",
                        p.display()
                    )));
                }
                (CompanionInstrStatus::None, _) => {}
            }

            lines.push(Line::from(""));
            match (kind, app.lang) {
                (SummaryKind::EncryptSymmetric, UiLang::En) => {
                    lines.push(Line::from(
                        "  • Safe to cloud/USB: .enc is strongly encrypted; original plaintext was NOT deleted.",
                    ));
                    lines.push(Line::from(
                        "  • Cross-Machine: Carry ONLY this .enc file + your password (no keystore files needed).",
                    ));
                }
                (SummaryKind::EncryptSymmetric, UiLang::Zh) => {
                    lines.push(Line::from(
                        "  • 文件安全：.enc 已强加密可网盘保存/拷走；原明文未删除，涉密请清理。",
                    ));
                    lines.push(Line::from(
                        "  • 跨电脑解密：只需携带这一个 .enc 文件 + 您刚才设置的口令，无需本机密钥文件！",
                    ));
                }
                (
                    SummaryKind::EncryptNewKeypair
                    | SummaryKind::EncryptExistingSigned
                    | SummaryKind::EncryptExistingUnsigned,
                    UiLang::En,
                ) => {
                    lines.push(Line::from(
                        "  • Safe to cloud/email: .pubenc is encrypted; original plaintext was NOT deleted.",
                    ));
                    lines.push(Line::from(
                        "  • Cross-Machine: Needs .pubenc + recipient x25519_private_*.asc.enc + backup password.",
                    ));
                    lines.push(Line::from(Span::styled(
                        "  • WARNING: Keep .asc.enc private files SEPARATE from .pubenc on cloud storage!",
                        Style::default().fg(Color::Yellow),
                    )));
                }
                (
                    SummaryKind::EncryptNewKeypair
                    | SummaryKind::EncryptExistingSigned
                    | SummaryKind::EncryptExistingUnsigned,
                    UiLang::Zh,
                ) => {
                    lines.push(Line::from(
                        "  • 文件安全：.pubenc 已强加密可网盘保存/发送；原明文未删除，涉密请清理。",
                    ));
                    lines.push(Line::from(
                        "  • 跨电脑解密：需携带 .pubenc + 接收方 x25519_private_*.asc.enc + 私钥口令。",
                    ));
                    lines.push(Line::from(Span::styled(
                        "  • 保密红线：严禁把 .asc.enc 私钥备份和 .pubenc 密文一起打包上传网盘！",
                        Style::default().fg(Color::Yellow),
                    )));
                }
                (SummaryKind::DecryptPubenc | SummaryKind::DecryptSymmetric, UiLang::En) => {
                    lines.push(Line::from(
                        "  • Plaintext written with strict 0600 permissions; protect or wipe after reading.",
                    ));
                }
                (SummaryKind::DecryptPubenc | SummaryKind::DecryptSymmetric, UiLang::Zh) => {
                    lines.push(Line::from(
                        "  • 明文已按严格 0600 权限落盘；阅后如需继续保密请勿遗留未加密明文在公共目录。",
                    ));
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                app.lang.pick(
                    "  [Enter / Esc] Close  |  [?] Full File & Secrecy Guide  |  [Shift+L] 中文",
                    "  [Enter / Esc] 关闭  |  [?] 打开完整文件与保密说明手册  |  [Shift+L] EN",
                ),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));

            let block = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::Green))
                        .title(title),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(block, sum_area);
        }
        ModalState::HelpGuide { scroll } => {
            let help_area = centered_rect_min(86, 84, 72, 18, frame.area());
            frame.render_widget(Clear, help_area);

            let lines = help_guide_lines(app.lang, &app.keystore_dir);
            let max_scroll = lines.len().saturating_sub(1).min(u16::MAX as usize) as u16;
            let clamped_scroll = (*scroll).min(max_scroll);

            let guide = Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).style(Style::default().fg(Color::Cyan)).title(
                    app.lang.pick(
                        " 📖 YaCrypt File Guide — Roles, Secrecy & Cross-Machine (↑/↓/PgDn | Shift+L: 中文 | Esc: Close) ",
                        " 📖 YaCrypt 文件全解 — 含义/受众/保密与跨电脑指南 (↑/↓/PgDn | Shift+L: EN | Esc: 关闭) ",
                    ),
                ))
                .wrap(Wrap { trim: false })
                .scroll((clamped_scroll, 0));
            frame.render_widget(guide, help_area);
        }
        ModalState::FileBrowser { target, current_dir, entries, selected_idx, show_hidden } => {
            let fb_area = centered_rect(76, 72, frame.area());
            frame.render_widget(Clear, fb_area);

            let title_label = match (target, app.lang) {
                (crate::tui::app::FileBrowserTarget::EncryptInput, UiLang::En) => {
                    "Select File to Encrypt"
                }
                (crate::tui::app::FileBrowserTarget::EncryptInput, UiLang::Zh) => {
                    "选择待加密原文件"
                }
                (crate::tui::app::FileBrowserTarget::EncryptOutput, UiLang::En) => {
                    "Select Encryption Output Path"
                }
                (crate::tui::app::FileBrowserTarget::EncryptOutput, UiLang::Zh) => {
                    "选择加密输出路径"
                }
                (crate::tui::app::FileBrowserTarget::DecryptInput, UiLang::En) => {
                    "Select Encrypted File (.pubenc / .enc)"
                }
                (crate::tui::app::FileBrowserTarget::DecryptInput, UiLang::Zh) => {
                    "选择待解密密文 (.pubenc / .enc)"
                }
                (crate::tui::app::FileBrowserTarget::DecryptOutput, UiLang::En) => {
                    "Select Decryption Output Path"
                }
                (crate::tui::app::FileBrowserTarget::DecryptOutput, UiLang::Zh) => {
                    "选择解密输出路径"
                }
            };

            let items_word = app.lang.pick("items", "项");
            let block = Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Cyan))
                .title(format!(" 🗂️  {} ({} {}) ", title_label, entries.len(), items_word));
            let inner_area = block.inner(fb_area);
            frame.render_widget(block, fb_area);
            if inner_area.width == 0 || inner_area.height == 0 {
                return;
            }

            // Clip headers instead of wrapping them, and give up header rows before
            // the last entry row. The list's capacity is its actual inner viewport.
            let header_height = inner_area.height.saturating_sub(1).min(3);
            let header_area = Rect { height: header_height, ..inner_area };
            let list_area = Rect {
                y: inner_area.y + header_height,
                height: inner_area.height - header_height,
                ..inner_area
            };
            let hidden_label = if *show_hidden {
                app.lang.pick("ON", "开启")
            } else {
                app.lang.pick("OFF", "关闭")
            };
            let header_lines = vec![
                Line::from(Span::styled(
                    format!(
                        "  📂 {} {}",
                        app.lang.pick("Directory:", "当前目录:"),
                        file_browser_single_line(&current_dir.to_string_lossy())
                    ),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )),
                Line::from(match app.lang {
                    UiLang::En => format!(
                        "  [↑/↓] Move  [Enter] Open/Select  [Backspace/←] Parent  [.] Hidden: {}  [Esc] Cancel",
                        hidden_label
                    ),
                    UiLang::Zh => format!(
                        "  [↑/↓] 移动  [Enter] 打开/选定  [退格/←] 上级目录  [.] 隐藏文件: {}  [Esc] 取消",
                        hidden_label
                    ),
                }),
                Line::from(""),
            ];
            frame.render_widget(Paragraph::new(header_lines), header_area);

            let visible_count = usize::from(list_area.height);
            let available_width = usize::from(list_area.width);
            let start = selected_idx.saturating_add(1).saturating_sub(visible_count);
            let end = start.saturating_add(visible_count).min(entries.len());
            let mut items = Vec::new();

            if entries.is_empty() {
                items.push(ListItem::new(app.lang.pick("    (Empty directory)", "    (空目录)")));
            } else {
                for (i, entry) in entries.iter().enumerate().take(end).skip(start) {
                    let is_sel = i == *selected_idx;
                    let cursor = if is_sel { "▶ " } else { "  " };
                    let icon = if entry.is_parent {
                        "⬆️ "
                    } else if entry.is_dir {
                        "📁 "
                    } else if entry.name.ends_with(".pubenc") {
                        "🔒 "
                    } else if entry.name.ends_with(".enc") {
                        "🔐 "
                    } else {
                        "📄 "
                    };
                    let suffix = if entry.is_dir && !entry.is_parent {
                        "/".to_string()
                    } else if !entry.is_dir {
                        format!("  ({})", format_bytes(entry.size))
                    } else {
                        String::new()
                    };
                    let style = if is_sel {
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else if entry.is_dir {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default()
                    };
                    let raw_name = if app.lang == UiLang::Zh && entry.is_parent {
                        ".. (上级目录)"
                    } else {
                        entry.name.as_str()
                    };
                    let name = file_browser_single_line(raw_name);
                    let full_prefix = format!("  {}{}", cursor, icon);
                    let name_width = Line::from(name.as_str()).width();
                    let prefix_width = Line::from(full_prefix.as_str()).width();
                    let prefix = if prefix_width.saturating_add(name_width) <= available_width {
                        full_prefix
                    } else if list_area.width >= 4 {
                        cursor.to_string()
                    } else {
                        String::new()
                    };
                    items.push(ListItem::new(Line::from(Span::styled(
                        format!("{}{}{}", prefix, name, suffix),
                        style,
                    ))));
                }
            }

            frame.render_widget(List::new(items), list_area);
        }
    }
}

fn file_browser_single_line(text: &str) -> String {
    text.chars().map(|ch| if ch.is_control() { ' ' } else { ch }).collect()
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn centered_rect_min(percent_x: u16, percent_y: u16, min_w: u16, min_h: u16, r: Rect) -> Rect {
    let target_w =
        ((u32::from(r.width) * u32::from(percent_x) / 100) as u16).max(min_w).min(r.width);
    let target_h =
        ((u32::from(r.height) * u32::from(percent_y) / 100) as u16).max(min_h).min(r.height);
    let x = r.x + r.width.saturating_sub(target_w) / 2;
    let y = r.y + r.height.saturating_sub(target_h) / 2;
    Rect { x, y, width: target_w, height: target_h }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};
    use std::path::PathBuf;
    use yacrypt_core::keystore::KeyringEntry;
    use zeroize::Zeroizing;

    fn buffer_text(buf: &Buffer) -> String {
        let area = buf.area;
        let mut out = String::new();
        for y in area.y..area.bottom() {
            for x in area.x..area.right() {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn render_logical_text(terminal: &mut Terminal<TestBackend>, app: &TuiApp) -> String {
        let mut out = String::new();
        terminal
            .draw(|f| {
                render(f, app);
                let buf = f.buffer_mut();
                let area = buf.area;
                for y in area.y..area.bottom() {
                    let mut x = area.x;
                    while x < area.right() {
                        let cell = &buf[(x, y)];
                        let sym = cell.symbol();
                        if !cell.skip {
                            out.push_str(sym);
                        }
                        let advance = Line::from(sym).width().max(1) as u16;
                        x = x.saturating_add(advance);
                    }
                    out.push('\n');
                }
            })
            .unwrap();
        out
    }

    #[test]
    fn headless_render_all_tabs_and_modals_succeeds() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = TuiApp::new(PathBuf::from("non_existent_keystore_for_test"));

        for tab in [ActiveTab::Keyring, ActiveTab::Encrypt, ActiveTab::Decrypt, ActiveTab::Password]
        {
            app.switch_tab(tab);
            terminal.draw(|f| render(f, &app)).unwrap();
        }

        app.modal =
            ModalState::NewKeypair { for_encrypt: false, auto_generate: false, focus_field: 1 };
        terminal.draw(|f| render(f, &app)).unwrap();

        app.modal = ModalState::SymmetricPassword { focus_field: 0 };
        terminal.draw(|f| render(f, &app)).unwrap();

        app.busy_message = Some("Testing busy overlay".into());
        terminal.draw(|f| render(f, &app)).unwrap();
        app.busy_message = None;

        app.open_file_browser(crate::tui::app::FileBrowserTarget::EncryptInput);
        terminal.draw(|f| render(f, &app)).unwrap();
    }

    #[test]
    fn keyring_viewport_scrolling_keeps_bottom_selection_visible_and_plain_copy_has_no_borders() {
        let mut terminal = Terminal::new(TestBackend::new(72, 12)).unwrap();
        let mut app = TuiApp::new(PathBuf::from("non_existent_keystore_for_test"));

        app.keyring = (0..18)
            .map(|idx| KeyringEntry {
                fingerprint: format!("{:064X}", idx + 1),
                label: Some(format!("peer_{idx:02}")),
                ed25519_pub_path: None,
                ed25519_enc_path: None,
                x25519_pub_path: None,
                x25519_enc_path: None,
                instr_path: None,
            })
            .collect();
        app.selected_key_idx = 17;
        terminal.draw(|f| render(f, &app)).unwrap();
        let rendered = buffer_text(terminal.backend().buffer());
        assert!(
            rendered.contains("peer_17"),
            "bottom keyring selection peer_17 scrolled off-screen:\n{}",
            rendered
        );

        // Borderless plain-copy view for 64-char backup password on 72-col viewport
        let pw64 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWxYz";
        assert_eq!(pw64.len(), 64);
        app.one_time_backup_pass = Some(Zeroizing::new(pw64.to_string()));
        app.modal = ModalState::GeneratedPasswordDisplay {
            fingerprint: "A".repeat(64),
            confirmed_saved: false,
            plain_copy_mode: true,
        };
        terminal.draw(|f| render(f, &app)).unwrap();
        let plain_rendered = buffer_text(terminal.backend().buffer());
        assert!(plain_rendered.contains(pw64), "64-char password missing:\n{}", plain_rendered);
        assert!(
            !plain_rendered.contains('│'),
            "plain copy view must not contain box border '│':\n{}",
            plain_rendered
        );
    }

    #[test]
    fn utf8_password_mask_counts_chars_not_bytes() {
        let mut terminal = Terminal::new(TestBackend::new(90, 24)).unwrap();
        let mut app = TuiApp::new(PathBuf::from("non_existent_keystore_for_test"));
        app.password_buf = Zeroizing::new("密码🔑".into()); // 3 Unicode scalar values, 10 UTF-8 bytes
        app.modal = ModalState::PasswordPrompt {
            title: "UTF-8 Mask Test".into(),
            action: crate::tui::app::PasswordAction::DecryptSymmetricFile,
        };
        terminal.draw(|f| render(f, &app)).unwrap();
        let rendered = buffer_text(terminal.backend().buffer());
        assert!(rendered.contains("> ***_"), "expected 3 asterisks for 3 chars:\n{}", rendered);
        assert!(!rendered.contains("****_"));
    }

    #[test]
    fn backup_password_renders_single_line_on_80x24_and_wraps_without_truncation_on_50x20_plain_copy(
    ) {
        let pw64 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWxYz";
        assert_eq!(pw64.len(), 64);

        // 1. Standard 80x24 bordered modal must keep the entire 64-char password on one line
        let mut term80 = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut app = TuiApp::new(PathBuf::from("non_existent_keystore_for_test"));
        app.one_time_backup_pass = Some(Zeroizing::new(pw64.to_string()));
        app.modal = ModalState::GeneratedPasswordDisplay {
            fingerprint: "B".repeat(64),
            confirmed_saved: false,
            plain_copy_mode: false,
        };
        term80.draw(|f| render(f, &app)).unwrap();
        let bordered_80 = buffer_text(term80.backend().buffer());
        assert!(
            bordered_80.lines().any(|line| line.contains(pw64)),
            "expected unbroken 64-char password on a single line in 80x24 bordered dialog:\n{}",
            bordered_80
        );

        // 2. Narrow 50x20 plain-copy view must wrap without clipping tail chars and without '│'
        let mut term50 = Terminal::new(TestBackend::new(50, 20)).unwrap();
        app.modal = ModalState::GeneratedPasswordDisplay {
            fingerprint: "B".repeat(64),
            confirmed_saved: false,
            plain_copy_mode: true,
        };
        term50.draw(|f| render(f, &app)).unwrap();
        let plain_50 = buffer_text(term50.backend().buffer());
        assert!(
            !plain_50.contains('│'),
            "50x20 plain copy view must not contain '│' borders:\n{}",
            plain_50
        );
        let flattened: String = plain_50.lines().map(|l| l.trim_end()).collect::<Vec<_>>().join("");
        assert!(
            flattened.contains(pw64),
            "50x20 plain copy view truncated 64-char password:\n{}",
            plain_50
        );
    }

    #[test]
    fn decrypt_tab_symmetric_file_shows_unsigned_na_instead_of_require_sig_yes() {
        let mut terminal = Terminal::new(TestBackend::new(110, 28)).unwrap();
        let mut app = TuiApp::new(PathBuf::from("non_existent_keystore_for_test"));
        app.switch_tab(ActiveTab::Decrypt);
        app.dec_input_path = "secret.txt.enc".into();
        app.dec_inspected = Some(Ok(yacrypt_core::workflow::InspectedFile::Sgpg(
            yacrypt_core::workflow::SgpgInfo {
                format_version: 1,
                blob_type: Some("file".into()),
                fingerprint: None,
                mem_kib: 65536,
                t_cost: 3,
                p_cost: 4,
                ciphertext_len: 128,
                padding_enabled: false,
            },
        )));
        terminal.draw(|f| render(f, &app)).unwrap();
        let rendered = buffer_text(terminal.backend().buffer());
        assert!(
            rendered.contains("<N/A — Symmetric (Unsigned)>"),
            "expected symmetric unsigned N/A indicator:\n{}",
            rendered
        );
        assert!(
            !rendered.contains("5. Require Signature:      [x] Yes"),
            "must not mislead user that signature verification is active on SGPGv1:\n{}",
            rendered
        );

        // SCFv2 inspector must indicate concealed AEAD signature and length padding, without false unsigned warning
        app.dec_input_path = "secret.txt.pubenc".into();
        app.dec_require_sig = true;
        app.dec_inspected = Some(Ok(yacrypt_core::workflow::InspectedFile::Pubenc(
            yacrypt_core::workflow::PubencInfo {
                format_version: 2,
                has_signature: None,
                signer_fingerprint: None,
                ephemeral_pub_hex: "ab".repeat(32),
                ciphertext_len: 1536,
                padding_enabled: true,
            },
        )));
        let rendered_v2 = render_logical_text(&mut terminal, &app);
        assert!(rendered_v2.contains("SCFv2"), "expected SCFv2 label:\n{}", rendered_v2);
        assert!(
            rendered_v2.contains("Concealed in AEAD"),
            "expected concealed signature info:\n{}",
            rendered_v2
        );
        assert!(
            rendered_v2.contains("Enabled (Random+Padme)"),
            "expected padding info:\n{}",
            rendered_v2
        );
        assert!(
            !rendered_v2.contains("File Is Unsigned"),
            "must not falsely claim SCFv2 file is unsigned:\n{}",
            rendered_v2
        );
    }

    #[test]
    fn chinese_locale_renders_tabs_modals_and_preserves_password_and_file_browser_invariants() {
        let mut terminal = Terminal::new(TestBackend::new(112, 32)).unwrap();
        let mut app =
            TuiApp::new_with_lang(PathBuf::from("non_existent_keystore_for_test"), UiLang::Zh);
        app.keyring = vec![KeyringEntry {
            fingerprint: "A".repeat(64),
            label: Some("alice".into()),
            ed25519_pub_path: Some(PathBuf::from("/tmp/public_A.asc")),
            ed25519_enc_path: Some(PathBuf::from("/tmp/private_A.asc.enc")),
            x25519_pub_path: Some(PathBuf::from("/tmp/x25519_public_A.asc")),
            x25519_enc_path: Some(PathBuf::from("/tmp/x25519_private_A.asc.enc")),
            instr_path: Some(PathBuf::from("/tmp/recovery_instructions_A.txt")),
        }];

        // 1. Keyring tab shows Chinese tabs + inline role & secrecy tags
        let keyring_zh = render_logical_text(&mut terminal, &app);
        assert!(keyring_zh.contains("密钥环"), "missing Chinese tab title:\n{}", keyring_zh);
        assert!(keyring_zh.contains("绝密核心"), "missing Keyring secrecy tag:\n{}", keyring_zh);

        for tab in [ActiveTab::Encrypt, ActiveTab::Decrypt, ActiveTab::Password] {
            app.switch_tab(tab);
            terminal.draw(|f| render(f, &app)).unwrap();
        }

        // 2. OperationSummary in En & Zh
        app.modal = ModalState::OperationSummary {
            kind: SummaryKind::EncryptExistingSigned,
            output_path: PathBuf::from("/tmp/memo.txt.pubenc"),
            key_fingerprint: Some("B".repeat(64)),
            verified_signer_fp: None,
            companion_instr: CompanionInstrStatus::Written(PathBuf::from(
                "/tmp/memo.txt.pubenc.decrypt.txt",
            )),
        };
        let sum_zh = render_logical_text(&mut terminal, &app);
        assert!(sum_zh.contains("加密已完成"), "missing Zh summary title:\n{}", sum_zh);
        app.lang = UiLang::En;
        let sum_en = render_logical_text(&mut terminal, &app);
        assert!(sum_en.contains("Encryption Completed"), "missing En summary title:\n{}", sum_en);

        // 3. HelpGuide scrollable render in En & Zh
        app.modal = ModalState::HelpGuide { scroll: 0 };
        terminal.draw(|f| render(f, &app)).unwrap();
        app.lang = UiLang::Zh;
        app.modal = ModalState::HelpGuide { scroll: 8 };
        let help_zh = render_logical_text(&mut terminal, &app);
        assert!(help_zh.contains("文件全解"), "missing Zh HelpGuide title:\n{}", help_zh);

        // 4. 80x24 Zh GeneratedPasswordDisplay with backup_modal_encrypted_file keeps 64-char password unbroken on 1 line
        let pw64 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWxYz";
        let mut term80 = Terminal::new(TestBackend::new(80, 24)).unwrap();
        app.one_time_backup_pass = Some(Zeroizing::new(pw64.to_string()));
        app.backup_modal_encrypted_file = Some(PathBuf::from("/tmp/secret.txt.pubenc"));
        app.pending_post_backup_summary = Some(ModalState::OperationSummary {
            kind: SummaryKind::EncryptNewKeypair,
            output_path: PathBuf::from("/tmp/secret.txt.pubenc"),
            key_fingerprint: Some("C".repeat(64)),
            verified_signer_fp: Some("C".repeat(64)),
            companion_instr: CompanionInstrStatus::None,
        });
        app.modal = ModalState::GeneratedPasswordDisplay {
            fingerprint: "C".repeat(64),
            confirmed_saved: false,
            plain_copy_mode: false,
        };
        let pw_zh_80 = render_logical_text(&mut term80, &app);
        assert!(
            pw_zh_80.lines().any(|line| line.contains(pw64)),
            "Zh 80x24 GeneratedPasswordDisplay broke 64-char password:\n{}",
            pw_zh_80
        );
        assert!(
            pw_zh_80.contains("secret.txt.pubenc"),
            "Zh GeneratedPasswordDisplay missing encrypted output path:\n{}",
            pw_zh_80
        );
        assert!(
            pw_zh_80.contains("用途：用于解锁刚生成的"),
            "Zh GeneratedPasswordDisplay missing purpose explanation:\n{}",
            pw_zh_80
        );
        assert!(
            pw_zh_80.contains("清零并查看加密结果"),
            "Zh GeneratedPasswordDisplay missing View Summary Enter hint:\n{}",
            pw_zh_80
        );

        // 5. FileBrowser in Zh on 80x12 keeps parent entry visible
        let fb_dir = std::env::temp_dir().join(format!("yacrypt_ui_zh_fb_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fb_dir);
        std::fs::create_dir_all(&fb_dir).unwrap();
        std::fs::write(fb_dir.join("note.txt"), b"hi").unwrap();
        app.one_time_backup_pass = None;
        app.backup_modal_encrypted_file = None;
        app.open_file_browser_in_dir(
            crate::tui::app::FileBrowserTarget::EncryptInput,
            fb_dir.clone(),
            false,
        );
        let mut term_fb = Terminal::new(TestBackend::new(80, 12)).unwrap();
        let fb_zh = render_logical_text(&mut term_fb, &app);
        assert!(fb_zh.contains(".. (上级目录)"), "expected Zh parent entry on 80x12:\n{}", fb_zh);
        let _ = std::fs::remove_dir_all(&fb_dir);
    }
}
