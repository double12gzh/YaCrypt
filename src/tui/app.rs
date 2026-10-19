/// TUI 核心状态机与事件处理模块
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};
use yacrypt_core::{
    constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH},
    file_ops::{decrypt_file_symmetric, encrypt_file_symmetric},
    keystore::{
        generate_and_store_keys_in_dir, load_signing_key_with_password, scan_keystore, KeyringEntry,
    },
    password::generate_strong_password,
    workflow::{
        decrypt_workflow_with_password, encrypt_workflow_with_existing_key,
        encrypt_workflow_with_new_keys, inspect_file, InspectedFile,
    },
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Keyring,
    Encrypt,
    Decrypt,
    Password,
}

impl ActiveTab {
    pub fn next(self) -> Self {
        match self {
            ActiveTab::Keyring => ActiveTab::Encrypt,
            ActiveTab::Encrypt => ActiveTab::Decrypt,
            ActiveTab::Decrypt => ActiveTab::Password,
            ActiveTab::Password => ActiveTab::Keyring,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            ActiveTab::Keyring => ActiveTab::Password,
            ActiveTab::Encrypt => ActiveTab::Keyring,
            ActiveTab::Decrypt => ActiveTab::Encrypt,
            ActiveTab::Password => ActiveTab::Decrypt,
        }
    }

    pub fn index(self) -> usize {
        match self {
            ActiveTab::Keyring => 0,
            ActiveTab::Encrypt => 1,
            ActiveTab::Decrypt => 2,
            ActiveTab::Password => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAction {
    SignAndEncrypt,
    SymmetricEncrypt,
    DecryptFile,
    DecryptSymmetricFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModalState {
    None,
    /// 生成新密钥对（或在新密钥加密流程中设置备份口令）
    NewKeypair {
        for_encrypt: bool,
        auto_generate: bool,
        focus_field: usize, // 0: auto_generate toggle, 1: password, 2: confirm, 3: submit
    },
    /// 单次口令输入弹窗（用于解密签名私钥、对称加解密或解密 .pubenc 文件）
    PasswordPrompt {
        title: String,
        action: PasswordAction,
    },
    /// 一次性展示自动生成的备份口令（关闭时立即清零）
    GeneratedPasswordDisplay {
        fingerprint: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Success,
    Warning,
    Error,
}

pub struct TuiApp {
    pub keystore_dir: PathBuf,
    pub active_tab: ActiveTab,
    pub should_quit: bool,

    // Keyring tab state
    pub keyring: Vec<KeyringEntry>,
    pub selected_key_idx: usize,

    // Encrypt tab state
    pub enc_focus: usize,
    pub enc_editing: bool,
    pub enc_input_path: String,
    pub enc_output_path: String,
    /// 0: `<Generate New Keypair>`, 1: `<Symmetric Password Only (.enc)>`, 2..: existing keyring[choice - 2]
    pub enc_key_choice: usize,
    pub enc_sign_file: bool,
    pub enc_force: bool,

    // Decrypt tab state
    pub dec_focus: usize,
    pub dec_editing: bool,
    pub dec_input_path: String,
    pub dec_output_path: String,
    pub dec_key_idx: usize,
    pub dec_signer_arg: String,
    pub dec_require_sig: bool,
    pub dec_force: bool,
    pub dec_inspected: Option<Result<InspectedFile, String>>,
    pub dec_last_verified_fp: Option<String>,

    // Password tab state
    pub pw_length: usize,
    pub pw_reveal: bool,
    pub generated_password: Option<Zeroizing<String>>,

    // Modal & sensitive buffers (all wrapped in Zeroizing)
    pub modal: ModalState,
    pub password_buf: Zeroizing<String>,
    pub confirm_buf: Zeroizing<String>,
    pub one_time_backup_pass: Option<Zeroizing<String>>,

    // Footer status message
    pub status_kind: StatusKind,
    pub status_msg: String,
}

impl TuiApp {
    pub fn new(keystore_dir: PathBuf) -> Self {
        let mut app = Self {
            keystore_dir,
            active_tab: ActiveTab::Keyring,
            should_quit: false,
            keyring: Vec::new(),
            selected_key_idx: 0,
            enc_focus: 0,
            enc_editing: false,
            enc_input_path: String::new(),
            enc_output_path: String::new(),
            enc_key_choice: 0,
            enc_sign_file: true,
            enc_force: false,
            dec_focus: 0,
            dec_editing: false,
            dec_input_path: String::new(),
            dec_output_path: String::new(),
            dec_key_idx: 0,
            dec_signer_arg: String::new(),
            dec_require_sig: true,
            dec_force: false,
            dec_inspected: None,
            dec_last_verified_fp: None,
            pw_length: 32,
            pw_reveal: false,
            generated_password: None,
            modal: ModalState::None,
            password_buf: Zeroizing::new(String::new()),
            confirm_buf: Zeroizing::new(String::new()),
            one_time_backup_pass: None,
            status_kind: StatusKind::Info,
            status_msg:
                "Welcome to YaCrypt TUI Workbench — press Tab/1-4 to switch tabs, q to quit".into(),
        };
        app.refresh_keyring();
        app
    }

    /// 显式擦除所有口令缓冲与临时敏感数据
    pub fn clear_secret_buffers(&mut self) {
        self.password_buf.zeroize();
        self.confirm_buf.zeroize();
        if let Some(ref mut p) = self.one_time_backup_pass {
            p.zeroize();
        }
        self.one_time_backup_pass = None;
    }

    pub fn clear_generated_password(&mut self) {
        if let Some(ref mut pw) = self.generated_password {
            pw.zeroize();
        }
        self.generated_password = None;
        self.pw_reveal = false;
    }

    pub fn set_status(&mut self, kind: StatusKind, msg: impl Into<String>) {
        self.status_kind = kind;
        self.status_msg = msg.into();
    }

    pub fn refresh_keyring(&mut self) {
        match scan_keystore(&self.keystore_dir) {
            Ok(list) => {
                self.keyring = list;
                if self.selected_key_idx >= self.keyring.len() && !self.keyring.is_empty() {
                    self.selected_key_idx = self.keyring.len() - 1;
                }
                if self.enc_key_choice > self.keyring.len() + 1 {
                    self.enc_key_choice = 0;
                }
                if self.dec_key_idx >= self.keyring.len() {
                    self.dec_key_idx = 0;
                }
            }
            Err(e) => {
                self.set_status(StatusKind::Error, format!("Failed to scan keystore: {}", e));
            }
        }
    }

    pub fn update_decrypt_inspection(&mut self) {
        let trimmed = self.dec_input_path.trim();
        if trimmed.is_empty() {
            self.dec_inspected = None;
            return;
        }
        let path = Path::new(trimmed);
        match inspect_file(path) {
            Ok(info) => {
                if let InspectedFile::Pubenc(ref p) = info {
                    if let Some(ref fp) = p.signer_fingerprint {
                        if let Some(pos) =
                            self.keyring.iter().position(|k| k.fingerprint.eq_ignore_ascii_case(fp))
                        {
                            self.dec_key_idx = pos;
                        }
                    }
                }
                self.dec_inspected = Some(Ok(info));
            }
            Err(e) => {
                self.dec_inspected = Some(Err(e.to_string()));
            }
        }
    }

    pub fn switch_tab(&mut self, next_tab: ActiveTab) {
        if self.active_tab == ActiveTab::Password && next_tab != ActiveTab::Password {
            self.clear_generated_password();
        }
        self.enc_editing = false;
        self.dec_editing = false;
        self.active_tab = next_tab;
    }

    pub fn handle_key_event(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.clear_secret_buffers();
            self.clear_generated_password();
            self.should_quit = true;
            return;
        }

        if self.modal != ModalState::None {
            self.handle_modal_key(key);
            return;
        }

        if self.active_tab == ActiveTab::Encrypt && self.enc_editing {
            self.handle_encrypt_edit_key(key);
            return;
        }
        if self.active_tab == ActiveTab::Decrypt && self.dec_editing {
            self.handle_decrypt_edit_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.clear_secret_buffers();
                self.clear_generated_password();
                self.should_quit = true;
                return;
            }
            KeyCode::Tab => {
                self.switch_tab(self.active_tab.next());
                return;
            }
            KeyCode::BackTab => {
                self.switch_tab(self.active_tab.prev());
                return;
            }
            KeyCode::Char('1') => {
                self.switch_tab(ActiveTab::Keyring);
                return;
            }
            KeyCode::Char('2') => {
                self.switch_tab(ActiveTab::Encrypt);
                return;
            }
            KeyCode::Char('3') => {
                self.switch_tab(ActiveTab::Decrypt);
                return;
            }
            KeyCode::Char('4') => {
                self.switch_tab(ActiveTab::Password);
                return;
            }
            _ => {}
        }

        match self.active_tab {
            ActiveTab::Keyring => self.handle_keyring_key(key),
            ActiveTab::Encrypt => self.handle_encrypt_key(key),
            ActiveTab::Decrypt => self.handle_decrypt_key(key),
            ActiveTab::Password => self.handle_password_key(key),
        }
    }

    fn handle_keyring_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_key_idx > 0 {
                    self.selected_key_idx -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_key_idx + 1 < self.keyring.len() {
                    self.selected_key_idx += 1;
                }
            }
            KeyCode::Char('r') => {
                self.refresh_keyring();
                self.set_status(
                    StatusKind::Info,
                    format!("Refreshed keystore ({} keypairs found)", self.keyring.len()),
                );
            }
            KeyCode::Char('n') | KeyCode::Enter => {
                self.clear_secret_buffers();
                self.modal = ModalState::NewKeypair {
                    for_encrypt: false,
                    auto_generate: false,
                    focus_field: 1,
                };
            }
            _ => {}
        }
    }

    fn handle_encrypt_edit_key(&mut self, key: KeyEvent) {
        let target =
            if self.enc_focus == 0 { &mut self.enc_input_path } else { &mut self.enc_output_path };
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.enc_editing = false;
            }
            KeyCode::Backspace => {
                target.pop();
            }
            KeyCode::Char(c) => {
                target.push(c);
            }
            _ => {}
        }
    }

    fn handle_encrypt_key(&mut self, key: KeyEvent) {
        const FIELD_COUNT: usize = 6;
        let total_modes = self.keyring.len() + 2;
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.enc_focus = (self.enc_focus + FIELD_COUNT - 1) % FIELD_COUNT;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.enc_focus = (self.enc_focus + 1) % FIELD_COUNT;
            }
            KeyCode::Left | KeyCode::Char('h') if self.enc_focus == 2 => {
                self.enc_key_choice = (self.enc_key_choice + total_modes - 1) % total_modes;
            }
            KeyCode::Right | KeyCode::Char('l') if self.enc_focus == 2 => {
                self.enc_key_choice = (self.enc_key_choice + 1) % total_modes;
            }
            KeyCode::Char(' ') => match self.enc_focus {
                3 => self.enc_sign_file = !self.enc_sign_file,
                4 => self.enc_force = !self.enc_force,
                _ => {}
            },
            KeyCode::Enter | KeyCode::Char('e') => match self.enc_focus {
                0 | 1 => self.enc_editing = true,
                2 => {
                    self.enc_key_choice = (self.enc_key_choice + 1) % total_modes;
                }
                3 => self.enc_sign_file = !self.enc_sign_file,
                4 => self.enc_force = !self.enc_force,
                5 => self.trigger_encrypt_action(),
                _ => {}
            },
            _ => {}
        }
    }

    fn trigger_encrypt_action(&mut self) {
        let input_trimmed = self.enc_input_path.trim();
        if input_trimmed.is_empty() {
            self.set_status(StatusKind::Error, "Please enter an Input File path to encrypt.");
            return;
        }
        let input_path = PathBuf::from(input_trimmed);
        if !input_path.exists() {
            self.set_status(
                StatusKind::Error,
                format!("Input file not found: {}", input_path.display()),
            );
            return;
        }

        if self.enc_key_choice == 0 {
            self.clear_secret_buffers();
            self.modal =
                ModalState::NewKeypair { for_encrypt: true, auto_generate: false, focus_field: 1 };
        } else if self.enc_key_choice == 1 {
            self.clear_secret_buffers();
            self.modal = ModalState::PasswordPrompt {
                title: "Enter symmetric encryption password (>=12 chars)".into(),
                action: PasswordAction::SymmetricEncrypt,
            };
        } else {
            let idx = self.enc_key_choice - 2;
            let Some(entry) = self.keyring.get(idx).cloned() else {
                self.set_status(StatusKind::Error, "Selected keypair no longer exists.");
                return;
            };
            let Some(ref x_pub) = entry.x25519_pub_path else {
                self.set_status(
                    StatusKind::Error,
                    format!("Missing X25519 public key for {}", entry.short_fingerprint()),
                );
                return;
            };

            if self.enc_sign_file {
                if entry.ed25519_enc_path.is_none() {
                    self.set_status(
                        StatusKind::Error,
                        format!(
                            "Missing Ed25519 signing key backup for {}",
                            entry.short_fingerprint()
                        ),
                    );
                    return;
                }
                self.clear_secret_buffers();
                self.modal = ModalState::PasswordPrompt {
                    title: format!(
                        "Enter password for signing key ({})",
                        entry.short_fingerprint()
                    ),
                    action: PasswordAction::SignAndEncrypt,
                };
            } else {
                let out_opt = if self.enc_output_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.enc_output_path.trim()))
                };
                match encrypt_workflow_with_existing_key(
                    &input_path,
                    x_pub,
                    out_opt.as_deref(),
                    None,
                    self.enc_force,
                ) {
                    Ok(outcome) => {
                        self.set_status(
                            StatusKind::Success,
                            format!(
                                "✅ Encrypted (unsigned) -> {}",
                                outcome.encrypted_file.display()
                            ),
                        );
                    }
                    Err(e) => {
                        self.set_status(StatusKind::Error, format!("❌ Encryption failed: {}", e));
                    }
                }
            }
        }
    }

    fn handle_decrypt_edit_key(&mut self, key: KeyEvent) {
        let target = match self.dec_focus {
            0 => &mut self.dec_input_path,
            1 => &mut self.dec_output_path,
            _ => &mut self.dec_signer_arg,
        };
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.dec_editing = false;
                if self.dec_focus == 0 {
                    self.update_decrypt_inspection();
                }
            }
            KeyCode::Backspace => {
                target.pop();
                if self.dec_focus == 0 {
                    self.update_decrypt_inspection();
                }
            }
            KeyCode::Char(c) => {
                target.push(c);
                if self.dec_focus == 0 {
                    self.update_decrypt_inspection();
                }
            }
            _ => {}
        }
    }

    fn handle_decrypt_key(&mut self, key: KeyEvent) {
        const FIELD_COUNT: usize = 7;
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.dec_focus = (self.dec_focus + FIELD_COUNT - 1) % FIELD_COUNT;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.dec_focus = (self.dec_focus + 1) % FIELD_COUNT;
            }
            KeyCode::Left | KeyCode::Char('h') if self.dec_focus == 2 => {
                if !self.keyring.is_empty() {
                    self.dec_key_idx =
                        (self.dec_key_idx + self.keyring.len() - 1) % self.keyring.len();
                }
            }
            KeyCode::Right | KeyCode::Char('l') if self.dec_focus == 2 => {
                if !self.keyring.is_empty() {
                    self.dec_key_idx = (self.dec_key_idx + 1) % self.keyring.len();
                }
            }
            KeyCode::Char(' ') => match self.dec_focus {
                4 => self.dec_require_sig = !self.dec_require_sig,
                5 => self.dec_force = !self.dec_force,
                _ => {}
            },
            KeyCode::Enter | KeyCode::Char('e') => match self.dec_focus {
                0 | 1 | 3 => self.dec_editing = true,
                2 => {
                    if !self.keyring.is_empty() {
                        self.dec_key_idx = (self.dec_key_idx + 1) % self.keyring.len();
                    }
                }
                4 => self.dec_require_sig = !self.dec_require_sig,
                5 => self.dec_force = !self.dec_force,
                6 => self.trigger_decrypt_action(),
                _ => {}
            },
            _ => {}
        }
    }

    fn trigger_decrypt_action(&mut self) {
        let input_trimmed = self.dec_input_path.trim();
        if input_trimmed.is_empty() {
            self.set_status(
                StatusKind::Error,
                "Please enter an Encrypted File (.pubenc / .enc) path.",
            );
            return;
        }
        let path = Path::new(input_trimmed);
        if !path.exists() {
            self.set_status(
                StatusKind::Error,
                format!("Encrypted file not found: {}", input_trimmed),
            );
            return;
        }

        // 若是 SGPGv1 对称加密文件，直接弹窗读取解密口令，免选私钥
        if let Ok(InspectedFile::Sgpg(_)) = inspect_file(path) {
            self.clear_secret_buffers();
            self.modal = ModalState::PasswordPrompt {
                title: "Enter password for symmetric SGPGv1 file".into(),
                action: PasswordAction::DecryptSymmetricFile,
            };
            return;
        }

        let Some(entry) = self.keyring.get(self.dec_key_idx).cloned() else {
            self.set_status(
                StatusKind::Error,
                "No keypair available in keystore — generate or import a keypair first.",
            );
            return;
        };
        if entry.x25519_enc_path.is_none() {
            self.set_status(
                StatusKind::Error,
                format!("Missing X25519 private key backup for {}", entry.short_fingerprint()),
            );
            return;
        }

        self.clear_secret_buffers();
        self.modal = ModalState::PasswordPrompt {
            title: format!("Enter password for X25519 private key ({})", entry.short_fingerprint()),
            action: PasswordAction::DecryptFile,
        };
    }

    fn handle_password_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('-') => {
                if self.pw_length > 12 {
                    self.pw_length -= 1;
                }
            }
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('+') | KeyCode::Char('=') => {
                if self.pw_length < 128 {
                    self.pw_length += 1;
                }
            }
            KeyCode::Char('v') => {
                self.pw_reveal = !self.pw_reveal;
            }
            KeyCode::Enter | KeyCode::Char('g') => match generate_strong_password(self.pw_length) {
                Ok(pw) => {
                    self.generated_password = Some(pw);
                    self.set_status(
                        StatusKind::Success,
                        format!(
                            "Generated {}-char strong password (press 'v' to toggle visibility)",
                            self.pw_length
                        ),
                    );
                }
                Err(e) => {
                    self.set_status(StatusKind::Error, format!("Password error: {}", e));
                }
            },
            KeyCode::Char('c') => {
                self.clear_generated_password();
                self.set_status(StatusKind::Info, "Cleared password buffer from memory.");
            }
            _ => {}
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.clear_secret_buffers();
            self.modal = ModalState::None;
            self.set_status(StatusKind::Info, "Cancelled modal dialog (buffers zeroized).");
            return;
        }

        match self.modal.clone() {
            ModalState::None => {}
            ModalState::GeneratedPasswordDisplay { .. } => {
                if key.code == KeyCode::Enter {
                    self.clear_secret_buffers();
                    self.modal = ModalState::None;
                }
            }
            ModalState::PasswordPrompt { action, .. } => match key.code {
                KeyCode::Backspace => {
                    self.password_buf.pop();
                }
                KeyCode::Char(c) => {
                    self.password_buf.push(c);
                }
                KeyCode::Enter => {
                    let pass_copy = self.password_buf.clone();
                    self.clear_secret_buffers();
                    self.modal = ModalState::None;
                    self.execute_password_action(action, &pass_copy);
                }
                _ => {}
            },
            ModalState::NewKeypair { for_encrypt, mut auto_generate, mut focus_field } => match key
                .code
            {
                KeyCode::Up | KeyCode::BackTab => {
                    focus_field = (focus_field + 3) % 4;
                    self.modal = ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                }
                KeyCode::Down | KeyCode::Tab => {
                    focus_field = (focus_field + 1) % 4;
                    self.modal = ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                }
                KeyCode::Char(' ') if focus_field == 0 => {
                    auto_generate = !auto_generate;
                    if auto_generate {
                        self.password_buf.zeroize();
                        self.confirm_buf.zeroize();
                    }
                    self.modal = ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                }
                KeyCode::Backspace => {
                    if !auto_generate {
                        if focus_field == 1 {
                            self.password_buf.pop();
                        } else if focus_field == 2 {
                            self.confirm_buf.pop();
                        }
                    }
                }
                KeyCode::Char(c) => {
                    if !auto_generate {
                        if focus_field == 1 {
                            self.password_buf.push(c);
                        } else if focus_field == 2 {
                            self.confirm_buf.push(c);
                        }
                    }
                }
                KeyCode::Enter => {
                    if focus_field == 0 {
                        auto_generate = !auto_generate;
                        self.modal =
                            ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                    } else if !auto_generate && focus_field == 1 {
                        focus_field = 2;
                        self.modal =
                            ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                    } else {
                        self.submit_new_keypair(for_encrypt, auto_generate);
                    }
                }
                _ => {}
            },
        }
    }

    fn submit_new_keypair(&mut self, for_encrypt: bool, auto_generate: bool) {
        let user_pw: Option<Zeroizing<String>> = if auto_generate {
            None
        } else {
            if self.password_buf.len() < MIN_PASSWORD_LENGTH {
                self.set_status(
                    StatusKind::Error,
                    format!("Password too short; must be >= {} chars", MIN_PASSWORD_LENGTH),
                );
                return;
            }
            if self.password_buf.len() > MAX_PASSWORD_LENGTH {
                self.set_status(
                    StatusKind::Error,
                    format!("Password too long; must be <= {} chars", MAX_PASSWORD_LENGTH),
                );
                return;
            }
            if *self.password_buf != *self.confirm_buf {
                self.set_status(StatusKind::Error, "Passwords mismatched! Please re-check.");
                return;
            }
            Some(self.password_buf.clone())
        };

        self.clear_secret_buffers();
        self.modal = ModalState::None;

        if for_encrypt {
            let input_path = PathBuf::from(self.enc_input_path.trim());
            let out_opt = if self.enc_output_path.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(self.enc_output_path.trim()))
            };
            match encrypt_workflow_with_new_keys(
                &self.keystore_dir,
                &input_path,
                user_pw.as_deref().map(|s| s.as_str()),
                out_opt.as_deref(),
                self.enc_force,
            ) {
                Ok(outcome) => {
                    let fp = outcome.keys.fingerprint.clone();
                    let auto_pw = outcome.keys.auto_generated_password.clone();
                    self.refresh_keyring();
                    self.set_status(
                        StatusKind::Success,
                        format!(
                            "✅ Generated keypair ({}) & signed/encrypted -> {}",
                            &fp[..12],
                            outcome.encrypted_file.display()
                        ),
                    );
                    if let Some(pw) = auto_pw {
                        self.one_time_backup_pass = Some(pw);
                        self.modal = ModalState::GeneratedPasswordDisplay { fingerprint: fp };
                    }
                }
                Err(e) => {
                    self.set_status(
                        StatusKind::Error,
                        format!("❌ Encrypt workflow failed: {}", e),
                    );
                }
            }
        } else {
            match generate_and_store_keys_in_dir(
                &self.keystore_dir,
                user_pw.as_deref().map(|s| s.as_str()),
            ) {
                Ok(keys) => {
                    let fp = keys.fingerprint.clone();
                    let auto_pw = keys.auto_generated_password.clone();
                    self.refresh_keyring();
                    if let Some(pos) = self.keyring.iter().position(|k| k.fingerprint == fp) {
                        self.selected_key_idx = pos;
                    }
                    self.set_status(StatusKind::Success, format!("✅ Keypair generated: {}", fp));
                    if let Some(pw) = auto_pw {
                        self.one_time_backup_pass = Some(pw);
                        self.modal = ModalState::GeneratedPasswordDisplay { fingerprint: fp };
                    }
                }
                Err(e) => {
                    self.set_status(StatusKind::Error, format!("❌ Key generation failed: {}", e));
                }
            }
        }
    }

    fn execute_password_action(&mut self, action: PasswordAction, password: &str) {
        match action {
            PasswordAction::SymmetricEncrypt => {
                let input_path = PathBuf::from(self.enc_input_path.trim());
                let out_opt = if self.enc_output_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.enc_output_path.trim()))
                };
                match encrypt_file_symmetric(
                    &input_path,
                    password,
                    out_opt.as_deref(),
                    self.enc_force,
                ) {
                    Ok(out_path) => {
                        self.set_status(
                            StatusKind::Success,
                            format!(
                                "✅ Symmetrically encrypted (SGPGv1) -> {}",
                                out_path.display()
                            ),
                        );
                    }
                    Err(e) => {
                        self.set_status(
                            StatusKind::Error,
                            format!("❌ Symmetric encryption failed: {}", e),
                        );
                    }
                }
            }
            PasswordAction::DecryptSymmetricFile => {
                let input_path = PathBuf::from(self.dec_input_path.trim());
                let out_opt = if self.dec_output_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.dec_output_path.trim()))
                };
                match decrypt_file_symmetric(
                    &input_path,
                    password,
                    out_opt.as_deref(),
                    self.dec_force,
                ) {
                    Ok(out_path) => {
                        self.dec_last_verified_fp = None;
                        self.set_status(
                            StatusKind::Success,
                            format!("✅ Symmetric file decrypted -> {}", out_path.display()),
                        );
                    }
                    Err(e) => {
                        self.set_status(
                            StatusKind::Error,
                            format!("❌ Symmetric decryption failed: {}", e),
                        );
                    }
                }
            }
            PasswordAction::SignAndEncrypt => {
                let idx = self.enc_key_choice.saturating_sub(2);
                let Some(entry) = self.keyring.get(idx).cloned() else {
                    self.set_status(StatusKind::Error, "Keypair not found.");
                    return;
                };
                let (Some(ref x_pub), Some(ref ed_enc)) =
                    (&entry.x25519_pub_path, &entry.ed25519_enc_path)
                else {
                    self.set_status(StatusKind::Error, "Keypair files incomplete.");
                    return;
                };

                let sk = match load_signing_key_with_password(ed_enc, password) {
                    Ok(k) => k,
                    Err(e) => {
                        self.set_status(
                            StatusKind::Error,
                            format!("❌ Failed to unlock signing key: {}", e),
                        );
                        return;
                    }
                };

                let input_path = PathBuf::from(self.enc_input_path.trim());
                let out_opt = if self.enc_output_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.enc_output_path.trim()))
                };

                match encrypt_workflow_with_existing_key(
                    &input_path,
                    x_pub,
                    out_opt.as_deref(),
                    Some(&sk),
                    self.enc_force,
                ) {
                    Ok(outcome) => {
                        self.set_status(
                            StatusKind::Success,
                            format!(
                                "✅ Signed & encrypted -> {}",
                                outcome.encrypted_file.display()
                            ),
                        );
                    }
                    Err(e) => {
                        self.set_status(StatusKind::Error, format!("❌ Encryption failed: {}", e));
                    }
                }
            }
            PasswordAction::DecryptFile => {
                let Some(entry) = self.keyring.get(self.dec_key_idx).cloned() else {
                    self.set_status(StatusKind::Error, "No private key selected.");
                    return;
                };
                let Some(ref x_enc) = entry.x25519_enc_path else {
                    self.set_status(StatusKind::Error, "Missing X25519 private key file.");
                    return;
                };

                let input_path = PathBuf::from(self.dec_input_path.trim());
                let out_opt = if self.dec_output_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.dec_output_path.trim()))
                };
                let signer_opt = if self.dec_signer_arg.trim().is_empty() {
                    None
                } else {
                    Some(self.dec_signer_arg.trim())
                };

                match decrypt_workflow_with_password(
                    &input_path,
                    x_enc,
                    password,
                    out_opt.as_deref(),
                    signer_opt,
                    self.dec_require_sig,
                    self.dec_force,
                ) {
                    Ok(outcome) => {
                        self.dec_last_verified_fp = outcome.verified_signer_fingerprint.clone();
                        match outcome.verified_signer_fingerprint {
                            Some(fp) => {
                                self.set_status(
                                    StatusKind::Success,
                                    format!(
                                        "✅ Signature verified ({}…) & decrypted -> {}",
                                        &fp[..12],
                                        outcome.decrypted_file.display()
                                    ),
                                );
                            }
                            None => {
                                self.set_status(
                                    StatusKind::Warning,
                                    format!(
                                        "ℹ️ Decrypted (no embedded signature) -> {}",
                                        outcome.decrypted_file.display()
                                    ),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        self.dec_last_verified_fp = None;
                        self.set_status(StatusKind::Error, format!("{}", e));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_switching_and_password_buffer_zeroization() {
        let dir = std::env::temp_dir().join(format!("yacrypt_tui_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app = TuiApp::new(dir.join("keystore"));

        assert_eq!(app.active_tab, ActiveTab::Keyring);

        app.handle_key_event(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::NONE));
        assert_eq!(app.active_tab, ActiveTab::Password);

        app.handle_key_event(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert!(app.generated_password.is_some());
        assert_eq!(app.generated_password.as_ref().unwrap().len(), 32);

        app.handle_key_event(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.active_tab, ActiveTab::Keyring);
        assert!(app.generated_password.is_none());

        app.handle_key_event(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert!(matches!(app.modal, ModalState::NewKeypair { .. }));
        app.handle_key_event(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        assert_eq!(app.password_buf.as_str(), "se");

        app.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);
        assert!(app.password_buf.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
