/// Ratatui 界面渲染模块
use crate::tui::app::{ActiveTab, ModalState, StatusKind, TuiApp};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Tabs, Wrap},
    Frame,
};
use yacrypt_core::workflow::InspectedFile;

pub fn render(frame: &mut Frame, app: &TuiApp) {
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
}

fn render_header(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let titles =
        ["[1] 🔑 Keyring", "[2] 🔒 Encrypt", "[3] 🔓 Decrypt & Verify", "[4] 🎲 Password Gen"]
            .iter()
            .map(|t| Line::from(Span::styled(*t, Style::default().fg(Color::Cyan))))
            .collect::<Vec<_>>();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" YaCrypt Security Workbench (Tab/1-4: Switch | q: Quit) "),
        )
        .select(app.active_tab.index())
        .highlight_style(
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        );

    frame.render_widget(tabs, area);
}

fn render_keyring_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    let items: Vec<ListItem> = if app.keyring.is_empty() {
        vec![ListItem::new("  (No keypairs in keystore/ — press 'n' to generate)")]
    } else {
        app.keyring
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let prefix = if i == app.selected_key_idx { "▶ " } else { "  " };
                let style = if i == app.selected_key_idx {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(
                    format!("{}🔑 {}", prefix, k.short_fingerprint()),
                    style,
                )))
            })
            .collect()
    };

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Local Keyring (↑/↓: Select | n: New Keypair | r: Refresh) "),
    );
    frame.render_widget(list, cols[0]);

    let detail_lines = if let Some(entry) = app.keyring.get(app.selected_key_idx) {
        let fmt_path = |opt: &Option<std::path::PathBuf>| match opt {
            Some(p) => format!("✅ {}", p.display()),
            None => "❌ Missing".to_string(),
        };
        vec![
            Line::from(Span::styled(
                "Ed25519 Identity Fingerprint (SHA-256):",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("  {}", entry.fingerprint)),
            Line::from(""),
            Line::from(Span::styled(
                "Associated Keystore Files:",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "  • Ed25519 Public (Verify):   {}",
                fmt_path(&entry.ed25519_pub_path)
            )),
            Line::from(format!(
                "  • Ed25519 Private (Sign):    {}",
                fmt_path(&entry.ed25519_enc_path)
            )),
            Line::from(format!(
                "  • X25519 Public (Encrypt):   {}",
                fmt_path(&entry.x25519_pub_path)
            )),
            Line::from(format!(
                "  • X25519 Private (Decrypt):  {}",
                fmt_path(&entry.x25519_enc_path)
            )),
            Line::from(format!("  • Recovery Instructions:     {}", fmt_path(&entry.instr_path))),
        ]
    } else {
        vec![
            Line::from("No keypair selected."),
            Line::from(""),
            Line::from(
                "Press 'n' or Enter to generate a new password-protected Ed25519 + X25519 keypair.",
            ),
        ]
    };

    let details = Paragraph::new(detail_lines)
        .block(Block::default().borders(Borders::ALL).title(" Keypair Details "))
        .wrap(Wrap { trim: false });
    frame.render_widget(details, cols[1]);
}

fn render_encrypt_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let key_label = if app.enc_key_choice == 0 {
        "<✨ Generate Fresh Ed25519 + X25519 Keypair>".to_string()
    } else if app.enc_key_choice == 1 {
        "<🔐 Symmetric Password Only (.enc / SGPGv1)>".to_string()
    } else if let Some(k) = app.keyring.get(app.enc_key_choice - 2) {
        format!("🔑 Existing Keypair: {}", k.short_fingerprint())
    } else {
        "<None>".to_string()
    };

    let field_line = |idx: usize, label: &str, value: String| -> Line {
        let active = app.enc_focus == idx;
        let editing = active && app.enc_editing && (idx == 0 || idx == 1);
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
        Line::from(Span::styled(format!("{}{:<28} {}", marker, label, value), style))
    };

    let sig_desc = if app.enc_key_choice == 1 {
        "N/A (Symmetric Argon2id + XChaCha20-Poly1305 AEAD)".to_string()
    } else if app.enc_key_choice == 0 || app.enc_sign_file {
        "[x] Yes (Authenticated & Signed)".to_string()
    } else {
        "[ ] No (X25519 AEAD only)".to_string()
    };

    let lines = vec![
        Line::from("Use ↑/↓ to navigate fields, Enter to edit/toggle/execute, ←/→ to select encryption mode:"),
        Line::from(""),
        field_line(
            0,
            "1. Input File:",
            if app.enc_input_path.is_empty() {
                "<press Enter to type path>".into()
            } else {
                app.enc_input_path.clone()
            },
        ),
        field_line(
            1,
            "2. Output File (optional):",
            if app.enc_output_path.is_empty() {
                if app.enc_key_choice == 1 {
                    "<default: input.enc>".into()
                } else {
                    "<default: input.pubenc>".into()
                }
            } else {
                app.enc_output_path.clone()
            },
        ),
        field_line(2, "3. Encryption Mode (←/→):", key_label),
        field_line(3, "4. Embed Ed25519 Signature:", sig_desc),
        field_line(
            4,
            "5. Overwrite (--force):",
            if app.enc_force { "[x] Yes".into() } else { "[ ] No (Safe create_new)".into() },
        ),
        Line::from(""),
        field_line(5, "Action:", "[ 🚀 Execute Encryption (Press Enter) ]".into()),
    ];

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" File Encryption (Hybrid X25519+Ed25519 or Symmetric Argon2id) "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(panel, area);
}

fn render_decrypt_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let key_label = if matches!(app.dec_inspected, Some(Ok(InspectedFile::Sgpg(_)))) {
        "<N/A — Symmetric SGPGv1 (Password Only)>".to_string()
    } else if let Some(k) = app.keyring.get(app.dec_key_idx) {
        format!("🔑 {}", k.short_fingerprint())
    } else {
        "<No Keypair in keystore/>".to_string()
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
        Line::from(Span::styled(format!("{}{:<26} {}", marker, label, value), style))
    };

    let form_lines = vec![
        Line::from("Use ↑/↓ to navigate, Enter to edit/execute, ←/→ to choose private key:"),
        Line::from(""),
        field_line(
            0,
            "1. Encrypted File:",
            if app.dec_input_path.is_empty() {
                "<press Enter to type .pubenc or .enc path>".into()
            } else {
                app.dec_input_path.clone()
            },
        ),
        field_line(
            1,
            "2. Output File (opt):",
            if app.dec_output_path.is_empty() {
                "<default: strip .pubenc / .enc>".into()
            } else {
                app.dec_output_path.clone()
            },
        ),
        field_line(2, "3. Private Key (←/→):", key_label),
        field_line(
            3,
            "4. Expected Signer (opt):",
            if app.dec_signer_arg.is_empty() {
                "<default: key owner fingerprint>".into()
            } else {
                app.dec_signer_arg.clone()
            },
        ),
        field_line(
            4,
            "5. Require Signature:",
            if app.dec_require_sig { "[x] Yes".into() } else { "[ ] Optional".into() },
        ),
        field_line(
            5,
            "6. Overwrite (--force):",
            if app.dec_force { "[x] Yes".into() } else { "[ ] No".into() },
        ),
        Line::from(""),
        field_line(6, "Action:", "[ 🔓 Decrypt & Verify ]".into()),
    ];

    let form = Paragraph::new(form_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Decrypt & Verify (Verify-Before-Write) "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(form, cols[0]);

    let mut inspect_lines = vec![Line::from(Span::styled(
        "Universal File Header Inspector:",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ))];
    match &app.dec_inspected {
        None => {
            inspect_lines.push(Line::from(
                "  Enter a .pubenc or .enc file path on the left to inspect its header without a password.",
            ));
        }
        Some(Ok(InspectedFile::Pubenc(info))) => {
            inspect_lines.push(Line::from("  • Container Format:   SCFv1 (Hybrid Public-Key)"));
            inspect_lines.push(Line::from(format!(
                "  • Embedded Signature: {}",
                if info.has_signature { "✅ Present (Ed25519)" } else { "⚠️ None (Unsigned)" }
            )));
            if let Some(ref fp) = info.signer_fingerprint {
                inspect_lines.push(Line::from(format!("  • Signer Fingerprint: {}", fp)));
            }
            inspect_lines.push(Line::from(format!(
                "  • Ephemeral X25519:   {}…",
                &info.ephemeral_pub_hex[..24]
            )));
            inspect_lines
                .push(Line::from(format!("  • Ciphertext Size:    {} bytes", info.ciphertext_len)));
        }
        Some(Ok(InspectedFile::Sgpg(info))) => {
            inspect_lines.push(Line::from("  • Container Format:   SGPGv1 (Password-Protected)"));
            inspect_lines.push(Line::from(format!(
                "  • Payload Type:       {}",
                info.blob_type.as_deref().unwrap_or("unknown")
            )));
            inspect_lines.push(Line::from(format!(
                "  • Argon2id Params:    {} MiB, t={}, p={}",
                info.mem_kib / 1024,
                info.t_cost,
                info.p_cost
            )));
            if let Some(ref fp) = info.fingerprint {
                inspect_lines.push(Line::from(format!("  • Bound Fingerprint:  {}", fp)));
            }
            inspect_lines
                .push(Line::from(format!("  • Ciphertext Size:    {} bytes", info.ciphertext_len)));
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
            format!("✅ Last Verified Signer: {}", verified),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )));
    }

    let inspector = Paragraph::new(inspect_lines)
        .block(Block::default().borders(Borders::ALL).title(" Live Header & Trust Inspector "))
        .wrap(Wrap { trim: false });
    frame.render_widget(inspector, cols[1]);
}

fn render_password_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let pw_display = match &app.generated_password {
        None => "<Press Enter or 'g' to generate high-entropy password>".to_string(),
        Some(pw) if app.pw_reveal => pw.as_str().to_string(),
        Some(pw) => "•".repeat(pw.len()),
    };

    let lines = vec![
        Line::from("Rejection-sampled CSPRNG (OsRng) password generator:"),
        Line::from(""),
        Line::from(Span::styled(
            format!("  Length (←/→ or -/+):   {} characters", app.pw_length),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "  Visibility ('v'):      {}",
            if app.pw_reveal {
                "👁️  Plaintext Revealed"
            } else {
                "🙈 Masked (Shoulder-Surf Safe)"
            }
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Generated Password (Zeroized on tab switch / exit):",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            format!("  {}", pw_display),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(
            "  Shortcuts: [Enter / g] Generate New  |  [v] Toggle Mask  |  [c] Clear Memory",
        ),
    ];

    let panel = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Strong Password Generator "))
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
    .block(Block::default().borders(Borders::ALL).title(" Status "));
    frame.render_widget(status, area);
}

fn render_modal(frame: &mut Frame, app: &TuiApp) {
    let area = centered_rect(65, 50, frame.area());
    frame.render_widget(Clear, area);

    match &app.modal {
        ModalState::None => {}
        ModalState::PasswordPrompt { title, .. } => {
            let masked = "*".repeat(app.password_buf.len());
            let lines = vec![
                Line::from(""),
                Line::from(
                    "Enter password (stored in Zeroizing buffer, cleared immediately after use):",
                ),
                Line::from(""),
                Line::from(Span::styled(
                    format!("  > {}_", masked),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from("Press [Enter] to confirm, or [Esc] to cancel."),
            ];
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
        ModalState::NewKeypair { for_encrypt, auto_generate, focus_field } => {
            let title = if *for_encrypt {
                "Generate Keypair & Encrypt File"
            } else {
                "Generate New Protected Keypair (Ed25519 + X25519)"
            };
            let pw_mask = "*".repeat(app.password_buf.len());
            let cf_mask = "*".repeat(app.confirm_buf.len());

            let style_for = |idx: usize| {
                if *focus_field == idx {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                }
            };

            let lines = vec![
                Line::from("Use ↑/↓/Tab to move, Space to toggle auto-generate, Enter to submit, Esc to cancel:"),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  {} Auto-generate 48-byte random backup password: {}",
                        if *focus_field == 0 { "▶" } else { " " },
                        if *auto_generate { "[x] Yes" } else { "[ ] No (User-defined password)" }
                    ),
                    style_for(0),
                )),
                Line::from(Span::styled(
                    format!(
                        "  {} Backup Password (>=12 chars): {}",
                        if *focus_field == 1 { "▶" } else { " " },
                        if *auto_generate { "<auto-generated>" } else { &pw_mask }
                    ),
                    style_for(1),
                )),
                Line::from(Span::styled(
                    format!(
                        "  {} Confirm Password:             {}",
                        if *focus_field == 2 { "▶" } else { " " },
                        if *auto_generate { "<auto-generated>" } else { &cf_mask }
                    ),
                    style_for(2),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        "  {} [ 🔐 Generate & Encrypt Keys (Argon2id 64 MiB) ]",
                        if *focus_field == 3 { "▶" } else { " " }
                    ),
                    style_for(3),
                )),
            ];

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
        ModalState::GeneratedPasswordDisplay { fingerprint } => {
            let pw_str = app.one_time_backup_pass.as_ref().map(|s| s.as_str()).unwrap_or("");
            let lines = vec![
                Line::from(Span::styled(
                    "⚠️  SAVE THIS BACKUP PASSWORD NOW! It will be zeroized when you close this dialog:",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(format!("  Key Fingerprint: {}", fingerprint)),
                Line::from(Span::styled(
                    format!("  Backup Password: {}", pw_str),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from("Press [Enter] or [Esc] once saved to wipe from memory and close."),
            ];
            let block = Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::Yellow))
                        .title(" 🔐 One-Time Backup Password "),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(block, area);
        }
    }
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
    use ratatui::{backend::TestBackend, Terminal};
    use std::path::PathBuf;

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
    }
}
