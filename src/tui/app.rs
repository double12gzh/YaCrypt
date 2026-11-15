/// TUI 核心状态机与事件处理模块
use crate::tui::i18n::{help_guide_lines, UiLang};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};
use yacrypt_core::{
    constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH},
    error::CryptError,
    file_ops::{
        decrypt_file_symmetric, encrypt_file_symmetric, preflight_validate_recipient_pubkey,
    },
    keystore::{
        change_keypair_password, generate_and_store_keys_in_dir, load_signing_key_with_password,
        scan_keystore, set_key_label, KeyringEntry,
    },
    password::generate_strong_password,
    utils::{
        default_decrypt_output_path, default_pubenc_output_path, default_symmetric_output_path,
        preflight_check_input_file, preflight_check_output_path,
    },
    workflow::{
        decrypt_workflow_with_password_in_dir, encrypt_workflow_with_existing_key_in_dir,
        encrypt_workflow_with_new_keys_opts, inspect_file, resolve_signer_fingerprint_in_dir,
        InspectedFile,
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
    DecryptFile,
    DecryptSymmetricFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBrowserTarget {
    EncryptInput,
    EncryptOutput,
    DecryptInput,
    DecryptOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBrowserEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub is_parent: bool,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryKind {
    EncryptNewKeypair,
    EncryptExistingSigned,
    EncryptExistingUnsigned,
    EncryptSymmetric,
    DecryptPubenc,
    DecryptSymmetric,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompanionInstrStatus {
    None,
    Written(PathBuf),
    Skipped,
    NotOverwritten(PathBuf),
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
    /// 纯口令对称加密双框确认弹窗（防止单次盲输错口令导致数据永久不可解）
    SymmetricPassword {
        focus_field: usize, // 0: password, 1: confirm, 2: submit
    },
    /// 单次口令输入弹窗（用于解锁自有签名私钥、解密对称文件或解密 .pubenc 文件）
    PasswordPrompt {
        title: String,
        action: PasswordAction,
    },
    /// 密钥环私钥备份口令轮换弹窗
    ChangeKeyPassword {
        fingerprint: String,
        display_name: String,
        focus_field: usize, // 0: old password, 1: new password, 2: confirm new password, 3: submit
    },
    /// 本地 `0600` 密钥别名（Petname）编辑弹窗
    SetKeyLabel {
        fingerprint: String,
        display_name: String,
    },
    /// 一次性展示自动生成的备份口令（含已保存复选确认锁与无边框纯文本复制模式）
    GeneratedPasswordDisplay {
        fingerprint: String,
        confirmed_saved: bool,
        plain_copy_mode: bool,
    },
    /// 加解密完成后的居中结果与安全处置摘要弹窗
    OperationSummary {
        kind: SummaryKind,
        output_path: PathBuf,
        key_fingerprint: Option<String>,
        verified_signer_fp: Option<String>,
        companion_instr: CompanionInstrStatus,
    },
    /// `[?] / [F1]` 交互式文件说明、用途与保密级别参考手册弹窗
    HelpGuide {
        scroll: u16,
    },
    /// 内置交互式文件浏览器弹窗（Ctrl+O / f 触发）
    FileBrowser {
        target: FileBrowserTarget,
        current_dir: PathBuf,
        entries: Vec<FileBrowserEntry>,
        selected_idx: usize,
        show_hidden: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Success,
    Warning,
    Error,
}

fn plain_char(key: KeyEvent) -> Option<char> {
    if key.modifiers.intersects(
        KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER | KeyModifiers::META,
    ) {
        return None;
    }
    match key.code {
        KeyCode::Char(c) => Some(c),
        _ => None,
    }
}

fn is_backspace_key(key: KeyEvent) -> bool {
    key.code == KeyCode::Backspace
        || (key.modifiers.contains(KeyModifiers::CONTROL)
            && !key
                .modifiers
                .intersects(KeyModifiers::ALT | KeyModifiers::SUPER | KeyModifiers::META)
            && matches!(key.code, KeyCode::Char('h') | KeyCode::Char('H')))
}

fn is_clear_line_key(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.intersects(KeyModifiers::ALT | KeyModifiers::SUPER | KeyModifiers::META)
        && matches!(key.code, KeyCode::Char('u') | KeyCode::Char('U'))
}

fn pop_secret_char(buf: &mut Zeroizing<String>) {
    if buf.is_empty() {
        return;
    }
    let mut trimmed = Zeroizing::new(buf.as_str().to_owned());
    trimmed.pop();
    buf.zeroize();
    *buf = trimmed;
}

pub struct TuiApp {
    pub keystore_dir: PathBuf,
    pub lang: UiLang,
    pub active_tab: ActiveTab,
    pub should_quit: bool,
    pub quit_confirm_pending: bool,

    // Keyring tab state
    pub keyring: Vec<KeyringEntry>,
    pub selected_key_idx: usize,

    // Encrypt tab state
    pub enc_focus: usize,
    pub enc_editing: bool,
    pub enc_input_path: String,
    pub enc_output_path: String,
    /// 0: `<Generate New Keypair>`, 1: `<Symmetric Password Only (.enc)>`,
    /// 2..2+recipient_keys.len(): `recipient_keys[choice - 2]`,
    /// 2+recipient_keys.len(): `<External X25519 Public Key (.asc file)>`
    pub enc_key_choice: usize,
    pub enc_external_pub_path: String,
    pub enc_sign_file: bool,
    /// 自有签名私钥索引（对应 `own_signing_keys()[enc_sign_key_idx]`，与接收方公钥解耦）
    pub enc_sign_key_idx: usize,
    pub enc_no_instructions: bool,
    pub enc_force: bool,

    // Decrypt tab state
    pub dec_focus: usize,
    pub dec_editing: bool,
    pub dec_input_path: String,
    pub dec_output_path: String,
    /// 自有解密私钥索引（对应 `own_decrypt_keys()[dec_key_idx]`，仅过滤含 `x25519_enc_path` 的条目）
    pub dec_key_idx: usize,
    /// 0: `<Self: Decryption Key Owner>`, `1..=keyring.len()`: 本地密钥环条目作为显式预期发送方
    pub dec_signer_choice: usize,
    pub dec_signer_arg: String,
    pub dec_require_sig: bool,
    pub dec_force: bool,
    pub dec_inspected: Option<Result<InspectedFile, String>>,
    pub dec_last_verified_fp: Option<String>,

    // Password tab state
    pub pw_length: usize,
    pub pw_reveal: bool,
    pub generated_password: Option<Zeroizing<String>>,

    // Modal & sensitive buffers (all secret buffers wrapped in Zeroizing)
    pub modal: ModalState,
    pub modal_error: Option<String>,
    pub busy_message: Option<String>,
    pub password_buf: Zeroizing<String>,
    pub confirm_buf: Zeroizing<String>,
    pub old_password_buf: Zeroizing<String>,
    pub one_time_backup_pass: Option<Zeroizing<String>>,
    pub backup_modal_encrypted_file: Option<PathBuf>,
    pub pending_post_backup_summary: Option<ModalState>,
    pub pending_encrypt_output: Option<PathBuf>,
    pub label_input_buf: String,

    // Footer status message
    pub status_kind: StatusKind,
    pub status_msg: String,

    drain_events_requested: bool,
    browser_for_recipient_key: bool,
}

impl Drop for TuiApp {
    fn drop(&mut self) {
        self.clear_secret_buffers();
        self.clear_generated_password();
    }
}

impl TuiApp {
    /// 用于确定性测试与默认英文入口的构造器
    #[allow(dead_code)]
    pub fn new(keystore_dir: PathBuf) -> Self {
        Self::new_with_lang(keystore_dir, UiLang::En)
    }

    pub fn new_with_lang(keystore_dir: PathBuf, lang: UiLang) -> Self {
        let mut app = Self {
            keystore_dir,
            lang,
            active_tab: ActiveTab::Keyring,
            should_quit: false,
            quit_confirm_pending: false,
            keyring: Vec::new(),
            selected_key_idx: 0,
            enc_focus: 0,
            enc_editing: false,
            enc_input_path: String::new(),
            enc_output_path: String::new(),
            enc_key_choice: 0,
            enc_external_pub_path: String::new(),
            enc_sign_file: true,
            enc_sign_key_idx: 0,
            enc_no_instructions: true,
            enc_force: false,
            dec_focus: 0,
            dec_editing: false,
            dec_input_path: String::new(),
            dec_output_path: String::new(),
            dec_key_idx: 0,
            dec_signer_choice: 0,
            dec_signer_arg: String::new(),
            dec_require_sig: true,
            dec_force: false,
            dec_inspected: None,
            dec_last_verified_fp: None,
            pw_length: 32,
            pw_reveal: false,
            generated_password: None,
            modal: ModalState::None,
            modal_error: None,
            busy_message: None,
            password_buf: Zeroizing::new(String::new()),
            confirm_buf: Zeroizing::new(String::new()),
            old_password_buf: Zeroizing::new(String::new()),
            one_time_backup_pass: None,
            backup_modal_encrypted_file: None,
            pending_post_backup_summary: None,
            pending_encrypt_output: None,
            label_input_buf: String::new(),
            status_kind: StatusKind::Info,
            status_msg: lang
                .pick(
                    "Welcome to YaCrypt TUI Workbench — Tab/1-4: Switch | ?: File Guide | Shift+L: 中文 | q: Quit",
                    "欢迎使用 YaCrypt 终端安全工作台 — Tab/1-4: 切换标签 | ?: 文件与保密说明 | Shift+L: EN | q: 退出",
                )
                .into(),
            drain_events_requested: false,
            browser_for_recipient_key: false,
        };
        app.refresh_keyring();
        // 默认优先选中本地已有的完整自有密钥对，避免在已有密钥时误触发反复新建密钥对
        if let Some(own_fp) = app
            .keyring
            .iter()
            .find(|k| k.x25519_enc_path.is_some() && k.x25519_pub_path.is_some())
            .map(|k| k.fingerprint.clone())
        {
            let _ = app.select_key_for_encryption(&own_fp);
        }
        app
    }

    /// 显式擦除所有口令缓冲与临时敏感数据
    pub fn clear_secret_buffers(&mut self) {
        self.password_buf.zeroize();
        self.confirm_buf.zeroize();
        self.old_password_buf.zeroize();
        if let Some(ref mut p) = self.one_time_backup_pass {
            p.zeroize();
        }
        self.one_time_backup_pass = None;
        self.backup_modal_encrypted_file = None;
        self.pending_post_backup_summary = None;
    }

    /// 将指定指纹密钥设置为 `[2] Encrypt` 的当前接收方公钥（若同时具备自有签名私钥则一并选中）
    pub fn select_key_for_encryption(&mut self, fp: &str) -> bool {
        let Some(rec_pos) =
            self.recipient_keyring_entries().iter().position(|k| k.fingerprint == fp)
        else {
            return false;
        };
        self.enc_key_choice = 2 + rec_pos;
        if let Some(sign_pos) = self.own_signing_keys().iter().position(|k| k.fingerprint == fp) {
            self.enc_sign_key_idx = sign_pos;
        }
        true
    }

    pub fn toggle_lang(&mut self) {
        self.lang = self.lang.toggle();
        self.lang.persist_if_keystore_exists(&self.keystore_dir);
        let msg = match self.lang {
            UiLang::Zh => "界面语言已切换为简体中文（按 Shift+L 或 F2 可切回英文）",
            UiLang::En => "Switched UI language to English (press Shift+L or F2 to switch to 中文)",
        };
        self.set_status(StatusKind::Info, msg);
    }

    fn companion_status(written: bool, skipped: bool, path: PathBuf) -> CompanionInstrStatus {
        if skipped {
            CompanionInstrStatus::Skipped
        } else if written {
            CompanionInstrStatus::Written(path)
        } else {
            CompanionInstrStatus::NotOverwritten(path)
        }
    }

    pub fn clear_generated_password(&mut self) {
        if let Some(ref mut pw) = self.generated_password {
            pw.zeroize();
        }
        self.generated_password = None;
        self.pw_reveal = false;
    }

    pub fn take_drain_events_flag(&mut self) -> bool {
        std::mem::take(&mut self.drain_events_requested)
    }

    pub fn set_status(&mut self, kind: StatusKind, msg: impl Into<String>) {
        self.status_kind = kind;
        self.status_msg = msg.into();
    }

    /// 返回本地密钥环中所有包含 `x25519_pub_path` 的接收方公钥条目（含自有密钥与导入的对端公钥）
    pub fn recipient_keyring_entries(&self) -> Vec<&KeyringEntry> {
        self.keyring.iter().filter(|k| k.x25519_pub_path.is_some()).collect()
    }

    /// 返回本地密钥环中所有包含 `ed25519_enc_path` 的自有签名私钥条目
    pub fn own_signing_keys(&self) -> Vec<&KeyringEntry> {
        self.keyring.iter().filter(|k| k.ed25519_enc_path.is_some()).collect()
    }

    /// 返回本地密钥环中所有包含 `x25519_enc_path` 的自有解密私钥条目
    pub fn own_decrypt_keys(&self) -> Vec<&KeyringEntry> {
        self.keyring.iter().filter(|k| k.x25519_enc_path.is_some()).collect()
    }

    /// 返回 `[2] Encrypt` 中外部 `.asc` 接收方公钥模式对应的 `enc_key_choice` 值
    pub fn external_recipient_choice_idx(&self) -> usize {
        self.recipient_keyring_entries().len() + 2
    }

    /// 返回 `[2] Encrypt` 当前生效的接收方模式总数（新生成 + 对称口令 + 密钥环公钥 + 外部 `.asc`）
    pub fn total_encrypt_recipient_modes(&self) -> usize {
        self.recipient_keyring_entries().len() + 3
    }

    /// 计算 `[3] Decrypt` 当前选定的预期签名者指纹（用于右侧 Inspector 预检对比，严禁自动信任密文头）
    pub fn effective_expected_signer_fp(&self) -> Option<String> {
        let custom = self.dec_signer_arg.trim();
        if !custom.is_empty() {
            return resolve_signer_fingerprint_in_dir(custom, &self.keystore_dir).ok();
        }
        if self.dec_signer_choice > 0 {
            return self.keyring.get(self.dec_signer_choice - 1).map(|k| k.fingerprint.clone());
        }
        self.own_decrypt_keys().get(self.dec_key_idx).map(|k| k.fingerprint.clone())
    }

    pub fn refresh_keyring(&mut self) {
        enum PrevEncChoice {
            NewKeypair,
            Symmetric,
            Keyring(String),
            External,
        }

        let prev_selected_fp =
            self.keyring.get(self.selected_key_idx).map(|k| k.fingerprint.clone());
        let prev_enc_choice = {
            let rec_entries = self.recipient_keyring_entries();
            let ext_idx = rec_entries.len() + 2;
            match self.enc_key_choice {
                0 => PrevEncChoice::NewKeypair,
                1 => PrevEncChoice::Symmetric,
                c if c >= 2 && c < ext_idx => {
                    PrevEncChoice::Keyring(rec_entries[c - 2].fingerprint.clone())
                }
                _ => PrevEncChoice::External,
            }
        };
        let prev_sign_fp =
            self.own_signing_keys().get(self.enc_sign_key_idx).map(|k| k.fingerprint.clone());
        let prev_dec_fp =
            self.own_decrypt_keys().get(self.dec_key_idx).map(|k| k.fingerprint.clone());
        let prev_signer_fp = if self.dec_signer_choice > 0 {
            self.keyring.get(self.dec_signer_choice - 1).map(|k| k.fingerprint.clone())
        } else {
            None
        };

        match scan_keystore(&self.keystore_dir) {
            Ok(list) => {
                self.keyring = list;
                if self.keyring.is_empty() {
                    self.selected_key_idx = 0;
                } else if let Some(fp) = prev_selected_fp {
                    self.selected_key_idx = self
                        .keyring
                        .iter()
                        .position(|k| k.fingerprint == fp)
                        .unwrap_or_else(|| self.selected_key_idx.min(self.keyring.len() - 1));
                } else if self.selected_key_idx >= self.keyring.len() {
                    self.selected_key_idx = self.keyring.len() - 1;
                }

                self.enc_key_choice = match prev_enc_choice {
                    PrevEncChoice::NewKeypair => 0,
                    PrevEncChoice::Symmetric => 1,
                    PrevEncChoice::Keyring(fp) => self
                        .recipient_keyring_entries()
                        .iter()
                        .position(|k| k.fingerprint == fp)
                        .map(|i| i + 2)
                        .unwrap_or(0),
                    PrevEncChoice::External => self.external_recipient_choice_idx(),
                };

                self.enc_sign_key_idx = prev_sign_fp
                    .and_then(|fp| self.own_signing_keys().iter().position(|k| k.fingerprint == fp))
                    .unwrap_or(0);

                self.dec_key_idx = prev_dec_fp
                    .and_then(|fp| self.own_decrypt_keys().iter().position(|k| k.fingerprint == fp))
                    .unwrap_or(0);

                self.dec_signer_choice = prev_signer_fp
                    .and_then(|fp| {
                        self.keyring.iter().position(|k| k.fingerprint == fp).map(|i| i + 1)
                    })
                    .unwrap_or(0);
            }
            Err(e) => {
                self.set_status(StatusKind::Error, format!("Failed to scan keystore: {}", e));
            }
        }
    }

    /// 当 `dec_input_path` 发生变化时立即清除旧的验签成功徽章并流式刷新头部透视（绝不自动篡改私钥或信任锚选择）
    pub fn update_decrypt_inspection(&mut self) {
        self.dec_last_verified_fp = None;
        let trimmed = self.dec_input_path.trim();
        if trimmed.is_empty() {
            self.dec_inspected = None;
            return;
        }
        let path = Path::new(trimmed);
        match inspect_file(path) {
            Ok(info) => {
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
        self.quit_confirm_pending = false;
        self.active_tab = next_tab;
    }

    fn is_focused_on_unedited_text_field(&self) -> bool {
        match self.active_tab {
            ActiveTab::Encrypt => !self.enc_editing && matches!(self.enc_focus, 0 | 1 | 3),
            ActiveTab::Decrypt => !self.dec_editing && matches!(self.dec_focus, 0 | 1 | 3),
            ActiveTab::Keyring | ActiveTab::Password => false,
        }
    }

    #[allow(dead_code)]
    pub fn handle_key_event(&mut self, key: KeyEvent) {
        self.handle_key_event_with_hook(key, |_| {});
    }

    pub fn handle_key_event_with_hook<F>(&mut self, key: KeyEvent, mut pre_heavy_op: F)
    where
        F: FnMut(&Self),
    {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            self.clear_secret_buffers();
            self.clear_generated_password();
            self.should_quit = true;
            return;
        }

        if self.modal != ModalState::None {
            self.quit_confirm_pending = false;
            self.handle_modal_key(key, &mut pre_heavy_op);
            return;
        }

        if self.active_tab == ActiveTab::Encrypt && self.enc_editing {
            self.quit_confirm_pending = false;
            self.handle_encrypt_edit_key(key);
            return;
        }
        if self.active_tab == ActiveTab::Decrypt && self.dec_editing {
            self.quit_confirm_pending = false;
            self.handle_decrypt_edit_key(key);
            return;
        }

        if key.code == KeyCode::F(2) || plain_char(key) == Some('L') {
            self.quit_confirm_pending = false;
            self.toggle_lang();
            return;
        }
        if key.code == KeyCode::F(1) || plain_char(key) == Some('?') {
            self.quit_confirm_pending = false;
            self.modal_error = None;
            self.modal = ModalState::HelpGuide { scroll: 0 };
            return;
        }

        if plain_char(key) != Some('q') {
            self.quit_confirm_pending = false;
        }

        match plain_char(key) {
            Some('q') => {
                if self.is_focused_on_unedited_text_field() && !self.quit_confirm_pending {
                    self.quit_confirm_pending = true;
                    let warn = self.lang.pick(
                        "Field is not in edit mode — press Enter to edit path, or press 'q' again (or Ctrl+C) to quit.",
                        "当前输入框未处于编辑态 — 按 Enter 编辑路径，或再按一次 'q'（或 Ctrl+C）退出。",
                    );
                    self.set_status(StatusKind::Warning, warn);
                    return;
                }
                self.clear_secret_buffers();
                self.clear_generated_password();
                self.should_quit = true;
                return;
            }
            Some('1') => {
                self.switch_tab(ActiveTab::Keyring);
                return;
            }
            Some('2') => {
                self.switch_tab(ActiveTab::Encrypt);
                return;
            }
            Some('3') => {
                self.switch_tab(ActiveTab::Decrypt);
                return;
            }
            Some('4') => {
                self.switch_tab(ActiveTab::Password);
                return;
            }
            _ => {}
        }

        match key.code {
            KeyCode::Tab => {
                self.switch_tab(self.active_tab.next());
                return;
            }
            KeyCode::BackTab => {
                self.switch_tab(self.active_tab.prev());
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
        let ch = plain_char(key);
        match key.code {
            KeyCode::Up if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {
                self.selected_key_idx = self.selected_key_idx.saturating_sub(1);
            }
            KeyCode::Down
                if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if self.selected_key_idx + 1 < self.keyring.len() {
                    self.selected_key_idx += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(entry) = self.keyring.get(self.selected_key_idx).cloned() {
                    if self.select_key_for_encryption(&entry.fingerprint) {
                        self.switch_tab(ActiveTab::Encrypt);
                        let msg = match self.lang {
                            UiLang::En => format!(
                                "Selected key ({}) as encryption recipient & switched to [2] Encrypt (press 'n' on Keyring for a new keypair).",
                                entry.display_name()
                            ),
                            UiLang::Zh => format!(
                                "已选用密钥 ({}) 作为加密接收方并切换到 [2] 加密（如需生成新密钥对请在密钥环按 'n'）。",
                                entry.display_name()
                            ),
                        };
                        self.set_status(StatusKind::Info, msg);
                    } else {
                        let msg = match self.lang {
                            UiLang::En => format!(
                                "⚠️ Key ({}) has no X25519 public key (.asc) for encryption; press 'n' to generate a new keypair.",
                                entry.display_name()
                            ),
                            UiLang::Zh => format!(
                                "⚠️ 密钥 ({}) 缺少可用于加密的 X25519 公钥（.asc）；按 'n' 可生成完整新密钥对。",
                                entry.display_name()
                            ),
                        };
                        self.set_status(StatusKind::Warning, msg);
                    }
                } else {
                    self.clear_secret_buffers();
                    self.pending_encrypt_output = None;
                    self.modal_error = None;
                    self.modal = ModalState::NewKeypair {
                        for_encrypt: false,
                        auto_generate: true,
                        focus_field: 0,
                    };
                }
            }
            _ => match ch {
                Some('k') => {
                    self.selected_key_idx = self.selected_key_idx.saturating_sub(1);
                }
                Some('j') => {
                    if self.selected_key_idx + 1 < self.keyring.len() {
                        self.selected_key_idx += 1;
                    }
                }
                Some('r') => {
                    self.refresh_keyring();
                    let msg = match self.lang {
                        UiLang::En => {
                            format!("Refreshed keystore ({} keypairs found)", self.keyring.len())
                        }
                        UiLang::Zh => {
                            format!("已刷新本地密钥环（共发现 {} 组密钥条目）", self.keyring.len())
                        }
                    };
                    self.set_status(StatusKind::Info, msg);
                }
                Some('n') => {
                    self.clear_secret_buffers();
                    self.pending_encrypt_output = None;
                    self.modal_error = None;
                    self.modal = ModalState::NewKeypair {
                        for_encrypt: false,
                        auto_generate: true,
                        focus_field: 0,
                    };
                }
                Some('l') => {
                    if let Some(entry) = self.keyring.get(self.selected_key_idx) {
                        self.label_input_buf = entry.label.clone().unwrap_or_default();
                        self.modal_error = None;
                        self.modal = ModalState::SetKeyLabel {
                            fingerprint: entry.fingerprint.clone(),
                            display_name: entry.display_name(),
                        };
                    } else {
                        let msg = self.lang.pick(
                            "No keypair selected to label.",
                            "当前未选中任何密钥对，无法设置别名。",
                        );
                        self.set_status(StatusKind::Warning, msg);
                    }
                }
                Some('p') => {
                    if let Some(entry) = self.keyring.get(self.selected_key_idx).cloned() {
                        if entry.ed25519_enc_path.is_none() || entry.x25519_enc_path.is_none() {
                            let disp = entry.display_name();
                            let msg = match self.lang {
                                UiLang::En => format!(
                                    "Key {} only has public key(s) — no local private key password to rotate.",
                                    disp
                                ),
                                UiLang::Zh => format!(
                                    "密钥 {} 仅包含对端公钥，无本地加密私钥可轮换口令。",
                                    disp
                                ),
                            };
                            self.set_status(StatusKind::Error, msg);
                        } else {
                            self.clear_secret_buffers();
                            self.modal_error = None;
                            let disp = entry.display_name();
                            self.modal = ModalState::ChangeKeyPassword {
                                fingerprint: entry.fingerprint,
                                display_name: disp,
                                focus_field: 0,
                            };
                        }
                    } else {
                        let msg = self.lang.pick(
                            "No keypair selected to rotate password.",
                            "当前未选中任何密钥对，无法轮换口令。",
                        );
                        self.set_status(StatusKind::Warning, msg);
                    }
                }
                _ => {}
            },
        }
    }

    pub fn open_file_browser(&mut self, target: FileBrowserTarget) {
        self.browser_for_recipient_key = false;
        let current_val = match target {
            FileBrowserTarget::EncryptInput => self.enc_input_path.trim(),
            FileBrowserTarget::EncryptOutput => self.enc_output_path.trim(),
            FileBrowserTarget::DecryptInput => self.dec_input_path.trim(),
            FileBrowserTarget::DecryptOutput => self.dec_output_path.trim(),
        };
        let initial_dir = Self::initial_browser_dir_from_value(current_val);
        self.open_file_browser_in_dir(target, initial_dir, false);
    }

    fn open_recipient_pubkey_browser(&mut self) {
        let initial_dir = Self::initial_browser_dir_from_value(self.enc_external_pub_path.trim());
        self.open_file_browser_in_dir(FileBrowserTarget::EncryptInput, initial_dir, false);
        self.browser_for_recipient_key = true;
    }

    fn initial_browser_dir_from_value(current_val: &str) -> PathBuf {
        if !current_val.is_empty() {
            let p = Path::new(current_val);
            if p.is_dir() {
                p.to_path_buf()
            } else if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() && parent.is_dir() {
                    parent.to_path_buf()
                } else {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                }
            } else {
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
            }
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        }
    }

    pub fn open_file_browser_in_dir(
        &mut self,
        target: FileBrowserTarget,
        dir: PathBuf,
        show_hidden: bool,
    ) {
        self.browser_for_recipient_key = false;
        self.open_file_browser_in_dir_preserving_aux(target, dir, show_hidden);
    }

    fn open_file_browser_in_dir_preserving_aux(
        &mut self,
        target: FileBrowserTarget,
        dir: PathBuf,
        show_hidden: bool,
    ) {
        let canon_dir = dir.canonicalize().unwrap_or(dir);
        let entries = Self::load_directory_entries(&canon_dir, show_hidden);
        self.enc_editing = false;
        self.dec_editing = false;
        self.modal_error = None;
        self.modal = ModalState::FileBrowser {
            target,
            current_dir: canon_dir,
            entries,
            selected_idx: 0,
            show_hidden,
        };
    }

    pub fn load_directory_entries(dir: &Path, show_hidden: bool) -> Vec<FileBrowserEntry> {
        let mut entries = Vec::new();
        if let Some(parent) = dir.parent() {
            entries.push(FileBrowserEntry {
                name: ".. (Parent Directory)".into(),
                path: parent.to_path_buf(),
                is_dir: true,
                is_parent: true,
                size: 0,
            });
        }

        let mut dirs = Vec::new();
        let mut files = Vec::new();

        if let Ok(rd) = std::fs::read_dir(dir) {
            for item in rd.flatten() {
                let name = item.file_name().to_string_lossy().to_string();
                if !show_hidden && name.starts_with('.') {
                    continue;
                }
                let path = item.path();
                let Ok(ft) = item.file_type() else {
                    continue;
                };
                if ft.is_dir() {
                    dirs.push(FileBrowserEntry {
                        name,
                        path,
                        is_dir: true,
                        is_parent: false,
                        size: 0,
                    });
                } else if ft.is_file() {
                    let size = item.metadata().map(|m| m.len()).unwrap_or(0);
                    files.push(FileBrowserEntry {
                        name,
                        path,
                        is_dir: false,
                        is_parent: false,
                        size,
                    });
                }
            }
        }

        // Sorting on a key owned by the closure (`String` from `to_lowercase`) keeps
        // clippy::unnecessary_sort_by happy on floating CI toolchains.
        dirs.sort_by_key(|a| a.name.to_lowercase());
        files.sort_by_key(|a| a.name.to_lowercase());
        entries.extend(dirs);
        entries.extend(files);
        entries
    }

    fn format_selected_path(path: &Path) -> String {
        if let Ok(cwd) = std::env::current_dir() {
            let canon_cwd = cwd.canonicalize().unwrap_or(cwd);
            let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            if let Ok(rel) = canon_path.strip_prefix(&canon_cwd) {
                if !rel.as_os_str().is_empty() {
                    return rel.to_string_lossy().to_string();
                }
            }
        }
        path.to_string_lossy().to_string()
    }

    pub fn complete_path_prefix(current: &str) -> Option<(String, usize)> {
        let trimmed = current.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (dir_prefix, search_dir, file_prefix) = if trimmed.ends_with('/') {
            (trimmed.to_string(), PathBuf::from(trimmed), String::new())
        } else {
            let p = Path::new(trimmed);
            let fname = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            match p.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => {
                    let mut dp = parent.to_string_lossy().to_string();
                    if !dp.ends_with('/') {
                        dp.push('/');
                    }
                    (dp, parent.to_path_buf(), fname)
                }
                _ => (String::new(), PathBuf::from("."), fname),
            }
        };

        let show_hidden = file_prefix.starts_with('.');
        let Ok(rd) = std::fs::read_dir(&search_dir) else {
            return None;
        };

        let mut matches: Vec<(String, bool)> = Vec::new();
        for item in rd.flatten() {
            let name = item.file_name().to_string_lossy().to_string();
            if !show_hidden && name.starts_with('.') {
                continue;
            }
            if name.starts_with(&file_prefix) {
                if let Ok(ft) = item.file_type() {
                    if ft.is_dir() || ft.is_file() {
                        matches.push((name, ft.is_dir()));
                    }
                }
            }
        }

        if matches.is_empty() {
            return None;
        }
        matches.sort_by(|a, b| a.0.cmp(&b.0));

        if matches.len() == 1 {
            let (ref name, is_dir) = matches[0];
            let completed = format!("{}{}{}", dir_prefix, name, if is_dir { "/" } else { "" });
            return Some((completed, 1));
        }

        let first = &matches[0].0;
        let mut lcp_len = first.len();
        for (other, _) in &matches[1..] {
            lcp_len = first
                .char_indices()
                .zip(other.chars())
                .take_while(|((_, c1), c2)| *c1 == *c2)
                .last()
                .map(|((idx, c), _)| idx + c.len_utf8())
                .unwrap_or(0)
                .min(lcp_len);
        }
        let completed = format!("{}{}", dir_prefix, &first[..lcp_len]);
        Some((completed, matches.len()))
    }

    fn handle_tab_completion_or_browser(&mut self, target: FileBrowserTarget) {
        let current = match target {
            FileBrowserTarget::EncryptInput => self.enc_input_path.clone(),
            FileBrowserTarget::EncryptOutput => self.enc_output_path.clone(),
            FileBrowserTarget::DecryptInput => self.dec_input_path.clone(),
            FileBrowserTarget::DecryptOutput => self.dec_output_path.clone(),
        };

        if current.trim().is_empty() {
            self.open_file_browser(target);
            return;
        }

        if let Some((completed, count)) = Self::complete_path_prefix(&current) {
            if completed != current {
                match target {
                    FileBrowserTarget::EncryptInput => self.enc_input_path = completed,
                    FileBrowserTarget::EncryptOutput => self.enc_output_path = completed,
                    FileBrowserTarget::DecryptInput => {
                        self.dec_input_path = completed;
                        self.update_decrypt_inspection();
                    }
                    FileBrowserTarget::DecryptOutput => self.dec_output_path = completed,
                }
                if count > 1 {
                    let msg = match self.lang {
                        UiLang::En => {
                            format!(
                                "{} matching paths — press Tab again to open File Browser",
                                count
                            )
                        }
                        UiLang::Zh => {
                            format!("找到 {} 个匹配路径 — 再按一次 Tab 打开文件浏览器", count)
                        }
                    };
                    self.set_status(StatusKind::Info, msg);
                }
                return;
            }
        }

        self.open_file_browser(target);
    }

    fn handle_recipient_key_tab_completion(&mut self) {
        let current = self.enc_external_pub_path.clone();
        if current.trim().is_empty() {
            self.open_recipient_pubkey_browser();
            return;
        }
        if let Some((completed, count)) = Self::complete_path_prefix(&current) {
            if completed != current {
                self.enc_external_pub_path = completed;
                if count > 1 {
                    let msg = match self.lang {
                        UiLang::En => {
                            format!(
                                "{} matching paths — press Tab again to open File Browser",
                                count
                            )
                        }
                        UiLang::Zh => {
                            format!("找到 {} 个匹配路径 — 再按一次 Tab 打开文件浏览器", count)
                        }
                    };
                    self.set_status(StatusKind::Info, msg);
                }
                return;
            }
        }
        self.open_recipient_pubkey_browser();
    }

    fn handle_encrypt_edit_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O'))
        {
            match self.enc_focus {
                0 => self.open_file_browser(FileBrowserTarget::EncryptInput),
                1 => self.open_file_browser(FileBrowserTarget::EncryptOutput),
                _ => self.open_recipient_pubkey_browser(),
            }
            return;
        }
        if key.code == KeyCode::Tab {
            match self.enc_focus {
                0 => self.handle_tab_completion_or_browser(FileBrowserTarget::EncryptInput),
                1 => self.handle_tab_completion_or_browser(FileBrowserTarget::EncryptOutput),
                _ => self.handle_recipient_key_tab_completion(),
            }
            return;
        }

        let target = match self.enc_focus {
            0 => &mut self.enc_input_path,
            1 => &mut self.enc_output_path,
            _ => &mut self.enc_external_pub_path,
        };

        if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
            self.enc_editing = false;
            return;
        }
        if is_clear_line_key(key) {
            target.clear();
            return;
        }
        if is_backspace_key(key) {
            target.pop();
            return;
        }
        if let Some(c) = plain_char(key) {
            target.push(c);
        }
    }

    fn cycle_encrypt_signing_key(&mut self, forward: bool) {
        let own_len = self.own_signing_keys().len();
        // 状态空间: 0 => Unsigned, 1..=own_len => own_signing_keys()[state - 1]
        let total = own_len + 1;
        let cur = if !self.enc_sign_file || own_len == 0 {
            0
        } else {
            (self.enc_sign_key_idx + 1).min(own_len)
        };
        let next = if forward { (cur + 1) % total } else { (cur + total - 1) % total };
        if next == 0 {
            self.enc_sign_file = false;
        } else {
            self.enc_sign_file = true;
            self.enc_sign_key_idx = next - 1;
        }
    }

    fn handle_encrypt_key(&mut self, key: KeyEvent) {
        const FIELD_COUNT: usize = 8;
        let total_modes = self.total_encrypt_recipient_modes();
        let ext_choice = self.external_recipient_choice_idx();
        let ch = plain_char(key);

        if (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O')))
            || ch == Some('f')
        {
            match self.enc_focus {
                0 => {
                    self.open_file_browser(FileBrowserTarget::EncryptInput);
                    return;
                }
                1 => {
                    self.open_file_browser(FileBrowserTarget::EncryptOutput);
                    return;
                }
                3 => {
                    self.enc_key_choice = ext_choice;
                    self.open_recipient_pubkey_browser();
                    return;
                }
                _ => {}
            }
        }

        if key.code == KeyCode::Up || ch == Some('k') {
            self.enc_focus = (self.enc_focus + FIELD_COUNT - 1) % FIELD_COUNT;
            return;
        }
        if key.code == KeyCode::Down || ch == Some('j') {
            self.enc_focus = (self.enc_focus + 1) % FIELD_COUNT;
            return;
        }
        if (key.code == KeyCode::Left || ch == Some('h')) && self.enc_focus == 2 {
            self.enc_key_choice = (self.enc_key_choice + total_modes - 1) % total_modes;
            return;
        }
        if (key.code == KeyCode::Right || ch == Some('l')) && self.enc_focus == 2 {
            self.enc_key_choice = (self.enc_key_choice + 1) % total_modes;
            return;
        }
        if (key.code == KeyCode::Left || ch == Some('h')) && self.enc_focus == 4 {
            if self.enc_key_choice >= 2 {
                self.cycle_encrypt_signing_key(false);
            }
            return;
        }
        if (key.code == KeyCode::Right || ch == Some('l')) && self.enc_focus == 4 {
            if self.enc_key_choice >= 2 {
                self.cycle_encrypt_signing_key(true);
            }
            return;
        }
        if ch == Some(' ') {
            match self.enc_focus {
                4 if self.enc_key_choice >= 2 => self.enc_sign_file = !self.enc_sign_file,
                5 => self.enc_no_instructions = !self.enc_no_instructions,
                6 => self.enc_force = !self.enc_force,
                _ => {}
            }
            return;
        }
        if key.code == KeyCode::Enter || ch == Some('e') {
            match self.enc_focus {
                0 | 1 => self.enc_editing = true,
                2 => self.enc_key_choice = (self.enc_key_choice + 1) % total_modes,
                3 => {
                    self.enc_key_choice = ext_choice;
                    self.enc_editing = true;
                }
                4 if self.enc_key_choice >= 2 => self.cycle_encrypt_signing_key(true),
                5 => self.enc_no_instructions = !self.enc_no_instructions,
                6 => self.enc_force = !self.enc_force,
                7 => self.trigger_encrypt_action(),
                _ => {}
            }
        }
    }

    fn resolve_selected_recipient_pubkey_path(&self) -> Result<PathBuf, String> {
        let recipients = self.recipient_keyring_entries();
        let ext_idx = self.external_recipient_choice_idx();
        if self.enc_key_choice >= 2 && self.enc_key_choice < ext_idx {
            let entry = recipients
                .get(self.enc_key_choice - 2)
                .ok_or_else(|| "Selected recipient key is no longer available.".to_string())?;
            entry
                .x25519_pub_path
                .clone()
                .ok_or_else(|| format!("Missing X25519 public key for {}", entry.display_name()))
        } else if self.enc_key_choice == ext_idx {
            let trimmed = self.enc_external_pub_path.trim();
            if trimmed.is_empty() {
                return Err(
                    "Please enter or browse an External Recipient X25519 Public Key (.asc) file."
                        .into(),
                );
            }
            Ok(PathBuf::from(trimmed))
        } else {
            Err("Invalid recipient key selection.".into())
        }
    }

    fn trigger_encrypt_action(&mut self) {
        let input_trimmed = self.enc_input_path.trim();
        if input_trimmed.is_empty() {
            let msg = self.lang.pick(
                "Please enter an Input File path to encrypt.",
                "请先输入或选择要加密的源文件路径。",
            );
            self.set_status(StatusKind::Error, msg);
            return;
        }
        let input_path = PathBuf::from(input_trimmed);
        if let Err(e) = preflight_check_input_file(&input_path, "Input file not found") {
            self.set_status(StatusKind::Error, format!("❌ {}", e));
            return;
        }

        // 前置输出冲突与 (dev, ino) 同文件自覆盖拦截（在弹窗输口令前立即反馈），并锁定单次解析出的输出路径
        self.pending_encrypt_output = None;
        let planned_out = if self.enc_output_path.trim().is_empty() {
            if self.enc_key_choice == 1 {
                default_symmetric_output_path(&input_path)
            } else {
                default_pubenc_output_path(&input_path)
            }
        } else {
            PathBuf::from(self.enc_output_path.trim())
        };
        if let Err(e) = preflight_check_output_path(Some(&input_path), &planned_out, self.enc_force)
        {
            self.set_status(StatusKind::Error, format!("❌ {}", e));
            return;
        }

        if self.enc_key_choice == 0 {
            self.clear_secret_buffers();
            self.pending_encrypt_output = Some(planned_out);
            self.modal_error = None;
            self.modal =
                ModalState::NewKeypair { for_encrypt: true, auto_generate: true, focus_field: 0 };
        } else if self.enc_key_choice == 1 {
            self.clear_secret_buffers();
            self.pending_encrypt_output = Some(planned_out);
            self.modal_error = None;
            self.modal = ModalState::SymmetricPassword { focus_field: 0 };
        } else {
            let ext_idx = self.external_recipient_choice_idx();
            let rec_fp = if self.enc_key_choice >= 2 && self.enc_key_choice < ext_idx {
                self.recipient_keyring_entries()
                    .get(self.enc_key_choice - 2)
                    .map(|k| k.fingerprint.clone())
            } else {
                None
            };
            let x_pub = match self.resolve_selected_recipient_pubkey_path() {
                Ok(p) => p,
                Err(msg) => {
                    self.set_status(StatusKind::Error, msg);
                    return;
                }
            };
            if let Err(e) = preflight_validate_recipient_pubkey(&x_pub, Some(&self.keystore_dir)) {
                self.set_status(StatusKind::Error, format!("❌ {}", e));
                return;
            }

            if self.enc_sign_file {
                let Some(sign_entry) = self.own_signing_keys().get(self.enc_sign_key_idx).copied()
                else {
                    let msg = self.lang.pick(
                        "No own Ed25519 signing key in keystore — generate a keypair first or toggle Signing Key to Unsigned.",
                        "密钥环中暂无自有 Ed25519 签名私钥 — 请先生成密钥对或按 Space 切换为无签名加密。",
                    );
                    self.set_status(StatusKind::Error, msg);
                    return;
                };
                let sign_disp = sign_entry.display_name();
                self.clear_secret_buffers();
                self.pending_encrypt_output = Some(planned_out);
                self.modal_error = None;
                let prompt_title = match self.lang {
                    UiLang::En => {
                        format!("Enter password for own signing key ({})", sign_disp)
                    }
                    UiLang::Zh => {
                        format!("请输入自有签名私钥的解锁口令 ({})", sign_disp)
                    }
                };
                self.modal = ModalState::PasswordPrompt {
                    title: prompt_title,
                    action: PasswordAction::SignAndEncrypt,
                };
            } else {
                match encrypt_workflow_with_existing_key_in_dir(
                    Some(&self.keystore_dir),
                    &input_path,
                    &x_pub,
                    Some(planned_out.as_path()),
                    None,
                    !self.enc_no_instructions,
                    self.enc_force,
                ) {
                    Ok(outcome) => {
                        if !outcome.instructions_skipped && !outcome.instructions_written {
                            let msg = match self.lang {
                                UiLang::En => format!(
                                    "✅ Encrypted (unsigned) -> {} (⚠️ {} already exists; not overwritten)",
                                    outcome.encrypted_file.display(),
                                    outcome.instructions_file.display()
                                ),
                                UiLang::Zh => format!(
                                    "✅ 已公钥加密（无签名）-> {}（⚠️ 伴生说明 {} 已存在，未覆盖）",
                                    outcome.encrypted_file.display(),
                                    outcome.instructions_file.display()
                                ),
                            };
                            self.set_status(StatusKind::Warning, msg);
                        } else {
                            let msg = match self.lang {
                                UiLang::En => format!(
                                    "✅ Encrypted (unsigned) -> {}",
                                    outcome.encrypted_file.display()
                                ),
                                UiLang::Zh => format!(
                                    "✅ 已公钥加密（无签名）-> {}",
                                    outcome.encrypted_file.display()
                                ),
                            };
                            self.set_status(StatusKind::Success, msg);
                        }
                        self.modal = ModalState::OperationSummary {
                            kind: SummaryKind::EncryptExistingUnsigned,
                            output_path: outcome.encrypted_file,
                            key_fingerprint: rec_fp,
                            verified_signer_fp: None,
                            companion_instr: Self::companion_status(
                                outcome.instructions_written,
                                outcome.instructions_skipped,
                                outcome.instructions_file,
                            ),
                        };
                    }
                    Err(e) => {
                        let prefix = self.lang.pick("❌ Encryption failed", "❌ 加密失败");
                        self.set_status(StatusKind::Error, format!("{}: {}", prefix, e));
                    }
                }
            }
        }
    }

    fn handle_decrypt_edit_key(&mut self, key: KeyEvent) {
        let maybe_browser_target = match self.dec_focus {
            0 => Some(FileBrowserTarget::DecryptInput),
            1 => Some(FileBrowserTarget::DecryptOutput),
            _ => None,
        };
        if let Some(bt) = maybe_browser_target {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O'))
            {
                self.open_file_browser(bt);
                return;
            }
            if key.code == KeyCode::Tab {
                self.handle_tab_completion_or_browser(bt);
                return;
            }
        }

        if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
            self.dec_editing = false;
            if self.dec_focus == 0 {
                self.update_decrypt_inspection();
            }
            return;
        }
        if is_clear_line_key(key) {
            match self.dec_focus {
                0 => {
                    self.dec_input_path.clear();
                    self.update_decrypt_inspection();
                }
                1 => self.dec_output_path.clear(),
                _ => self.dec_signer_arg.clear(),
            }
            return;
        }
        if is_backspace_key(key) {
            match self.dec_focus {
                0 => {
                    self.dec_input_path.pop();
                    self.update_decrypt_inspection();
                }
                1 => {
                    self.dec_output_path.pop();
                }
                _ => {
                    self.dec_signer_arg.pop();
                }
            }
            return;
        }
        if let Some(c) = plain_char(key) {
            match self.dec_focus {
                0 => {
                    self.dec_input_path.push(c);
                    self.update_decrypt_inspection();
                }
                1 => self.dec_output_path.push(c),
                _ => self.dec_signer_arg.push(c),
            }
        }
    }

    fn handle_decrypt_key(&mut self, key: KeyEvent) {
        const FIELD_COUNT: usize = 7;
        let ch = plain_char(key);
        let own_dec_len = self.own_decrypt_keys().len();
        let signer_choices = self.keyring.len() + 1;

        if (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O')))
            || ch == Some('f')
        {
            match self.dec_focus {
                0 => {
                    self.open_file_browser(FileBrowserTarget::DecryptInput);
                    return;
                }
                1 => {
                    self.open_file_browser(FileBrowserTarget::DecryptOutput);
                    return;
                }
                _ => {}
            }
        }

        if key.code == KeyCode::Up || ch == Some('k') {
            self.dec_focus = (self.dec_focus + FIELD_COUNT - 1) % FIELD_COUNT;
            return;
        }
        if key.code == KeyCode::Down || ch == Some('j') {
            self.dec_focus = (self.dec_focus + 1) % FIELD_COUNT;
            return;
        }
        if (key.code == KeyCode::Left || ch == Some('h')) && self.dec_focus == 2 {
            if own_dec_len > 0 {
                self.dec_key_idx = (self.dec_key_idx + own_dec_len - 1) % own_dec_len;
            }
            return;
        }
        if (key.code == KeyCode::Right || ch == Some('l')) && self.dec_focus == 2 {
            if own_dec_len > 0 {
                self.dec_key_idx = (self.dec_key_idx + 1) % own_dec_len;
            }
            return;
        }
        if (key.code == KeyCode::Left || ch == Some('h')) && self.dec_focus == 3 {
            self.dec_signer_arg.clear();
            self.dec_signer_choice = (self.dec_signer_choice + signer_choices - 1) % signer_choices;
            return;
        }
        if (key.code == KeyCode::Right || ch == Some('l')) && self.dec_focus == 3 {
            self.dec_signer_arg.clear();
            self.dec_signer_choice = (self.dec_signer_choice + 1) % signer_choices;
            return;
        }
        if ch == Some(' ') {
            match self.dec_focus {
                4 => self.dec_require_sig = !self.dec_require_sig,
                5 => self.dec_force = !self.dec_force,
                _ => {}
            }
            return;
        }
        if key.code == KeyCode::Enter || ch == Some('e') {
            match self.dec_focus {
                0 | 1 | 3 => self.dec_editing = true,
                2 => {
                    if own_dec_len > 0 {
                        self.dec_key_idx = (self.dec_key_idx + 1) % own_dec_len;
                    }
                }
                4 => self.dec_require_sig = !self.dec_require_sig,
                5 => self.dec_force = !self.dec_force,
                6 => self.trigger_decrypt_action(),
                _ => {}
            }
        }
    }

    fn trigger_decrypt_action(&mut self) {
        let input_trimmed = self.dec_input_path.trim();
        if input_trimmed.is_empty() {
            let msg = self.lang.pick(
                "Please enter an Encrypted File (.pubenc / .enc) path.",
                "请先输入或选择待解密文件（.pubenc / .enc）的路径。",
            );
            self.set_status(StatusKind::Error, msg);
            return;
        }
        let path = Path::new(input_trimmed);
        if let Err(e) = preflight_check_input_file(path, "Encrypted file not found") {
            self.set_status(StatusKind::Error, format!("❌ {}", e));
            return;
        }

        let inspected = match inspect_file(path) {
            Ok(info) => info,
            Err(e) => {
                self.set_status(StatusKind::Error, format!("❌ {}", e));
                return;
            }
        };

        // 免密检查 SGPG 子类型：仅允许 type=file 走对称文件解密，遇到私钥备份零口令直接给出精确指引
        if let InspectedFile::Sgpg(ref s) = inspected {
            match s.blob_type.as_deref() {
                Some("file") => {
                    if self.dec_signer_choice > 0 || !self.dec_signer_arg.trim().is_empty() {
                        let msg = match self.lang {
                            UiLang::En => format!(
                                "❌ Symmetric SGPGv{} (.enc) files carry no Ed25519 signature and cannot verify Expected Signer — reset Expected Signer to default or use a signed .pubenc file.",
                                s.format_version
                            ),
                            UiLang::Zh => format!(
                                "❌ 对称容器 SGPGv{} (.enc) 无内嵌 Ed25519 签名（no Ed25519 signature），无法验证 Expected Signer — 请将第 4 项重置为默认或改用已签名的 .pubenc 文件。",
                                s.format_version
                            ),
                        };
                        self.set_status(StatusKind::Error, msg);
                        return;
                    }
                    let planned_out = if self.dec_output_path.trim().is_empty() {
                        default_decrypt_output_path(path, "enc")
                    } else {
                        PathBuf::from(self.dec_output_path.trim())
                    };
                    if let Err(e) =
                        preflight_check_output_path(Some(path), &planned_out, self.dec_force)
                    {
                        self.set_status(StatusKind::Error, format!("❌ {}", e));
                        return;
                    }
                    self.clear_secret_buffers();
                    self.modal_error = None;
                    let title = match self.lang {
                        UiLang::En => {
                            format!("Enter password for symmetric SGPGv{} file", s.format_version)
                        }
                        UiLang::Zh => {
                            format!(
                                "请输入纯口令对称加密文件 (.enc / SGPGv{}) 的解密口令",
                                s.format_version
                            )
                        }
                    };
                    self.modal = ModalState::PasswordPrompt {
                        title,
                        action: PasswordAction::DecryptSymmetricFile,
                    };
                    return;
                }
                Some("ed25519") => {
                    let msg = match self.lang {
                        UiLang::En => format!(
                            "'{}' is an Ed25519 signing private key backup (type=ed25519), not an encrypted data file. Use CLI 'yacrypt decrypt-private-key' if you need PKCS#8 DER.",
                            path.display()
                        ),
                        UiLang::Zh => format!(
                            "'{}' 是 Ed25519 签名私钥备份（type=ed25519），并非加密数据文件；如需导出 DER 请使用 CLI 'yacrypt decrypt-private-key'。",
                            path.display()
                        ),
                    };
                    self.set_status(StatusKind::Error, msg);
                    return;
                }
                Some("x25519") => {
                    let msg = match self.lang {
                        UiLang::En => format!(
                            "'{}' is an X25519 decryption private key backup (type=x25519), not an encrypted data file. Select a .pubenc file in field 1 instead.",
                            path.display()
                        ),
                        UiLang::Zh => format!(
                            "'{}' 是 X25519 解密私钥备份（type=x25519），并非加密数据文件；请在第 1 项选择 .pubenc 密文文件。",
                            path.display()
                        ),
                    };
                    self.set_status(StatusKind::Error, msg);
                    return;
                }
                other => {
                    let msg = match self.lang {
                        UiLang::En => format!(
                            "Refusing to decrypt SGPGv{} container with type={:?} as a regular file.",
                            s.format_version, other
                        ),
                        UiLang::Zh => format!(
                            "拒绝将 type={:?} 的 SGPGv{} 容器当作普通文件解密。",
                            other, s.format_version
                        ),
                    };
                    self.set_status(StatusKind::Error, msg);
                    return;
                }
            }
        }

        // 仅当遗留 SCFv1 在外层明确标记为“无签名” (`Some(false)`) 时才免密前置拦截；
        // SCFv2 (`None`) 将签名隐藏在 AEAD 密文内层，须解密后再做先验签后落盘校验
        if let InspectedFile::Pubenc(ref p) = inspected {
            if p.has_signature == Some(false)
                && (self.dec_require_sig
                    || self.dec_signer_choice > 0
                    || !self.dec_signer_arg.trim().is_empty())
            {
                let msg = self.lang.pick(
                    "❌ Signature verification FAILED — file has no embedded Ed25519 signature, but signature verification is required.",
                    "❌ 签名校验失败 — 该文件未携带 Ed25519 数字签名，但当前已开启强制验签。",
                );
                self.set_status(StatusKind::Error, msg);
                return;
            }
        }

        let Some(entry) = self.own_decrypt_keys().get(self.dec_key_idx).copied().cloned() else {
            let msg = self.lang.pick(
                "No own decryption keypair (with X25519 private key) in keystore — generate a keypair first.",
                "本地密钥环中暂无可用于解密的 X25519 私钥 — 请先生成或拷贝密钥备份。",
            );
            self.set_status(StatusKind::Error, msg);
            return;
        };
        let Some(ref x_enc) = entry.x25519_enc_path else {
            self.set_status(
                StatusKind::Error,
                format!("Missing X25519 private key backup for {}", entry.display_name()),
            );
            return;
        };

        let planned_out = if self.dec_output_path.trim().is_empty() {
            default_decrypt_output_path(path, "pubenc")
        } else {
            PathBuf::from(self.dec_output_path.trim())
        };
        if let Err(e) = preflight_check_output_path(Some(path), &planned_out, self.dec_force) {
            self.set_status(StatusKind::Error, format!("❌ {}", e));
            return;
        }
        if let Err(e) = preflight_check_output_path(Some(x_enc), &planned_out, self.dec_force) {
            self.set_status(StatusKind::Error, format!("❌ {}", e));
            return;
        }

        if !self.dec_signer_arg.trim().is_empty() {
            if let Err(e) =
                resolve_signer_fingerprint_in_dir(self.dec_signer_arg.trim(), &self.keystore_dir)
            {
                self.set_status(StatusKind::Error, format!("❌ {}", e));
                return;
            }
        }

        self.clear_secret_buffers();
        self.modal_error = None;
        let prompt_title = match self.lang {
            UiLang::En => {
                format!("Enter password for X25519 private key ({})", entry.display_name())
            }
            UiLang::Zh => {
                format!("请输入 X25519 解密私钥的解锁口令 ({})", entry.display_name())
            }
        };
        self.modal =
            ModalState::PasswordPrompt { title: prompt_title, action: PasswordAction::DecryptFile };
    }

    fn handle_password_key(&mut self, key: KeyEvent) {
        let ch = plain_char(key);
        if key.code == KeyCode::Left || matches!(ch, Some('h') | Some('-')) {
            if self.pw_length > 12 {
                self.pw_length -= 1;
            }
            return;
        }
        if key.code == KeyCode::Right || matches!(ch, Some('l') | Some('+') | Some('=')) {
            if self.pw_length < 128 {
                self.pw_length += 1;
            }
            return;
        }
        if ch == Some('v') {
            self.pw_reveal = !self.pw_reveal;
            return;
        }
        if key.code == KeyCode::Enter || ch == Some('g') {
            match generate_strong_password(self.pw_length) {
                Ok(pw) => {
                    self.generated_password = Some(pw);
                    let msg = match self.lang {
                        UiLang::En => format!(
                            "Generated {}-char strong password (press 'v' to toggle visibility)",
                            self.pw_length
                        ),
                        UiLang::Zh => format!(
                            "已生成 {} 位高强度随机口令（按 'v' 切换显示/隐藏）",
                            self.pw_length
                        ),
                    };
                    self.set_status(StatusKind::Success, msg);
                }
                Err(e) => {
                    self.set_status(StatusKind::Error, format!("Password error: {}", e));
                }
            }
            return;
        }
        if ch == Some('c') {
            self.clear_generated_password();
            let msg = self
                .lang
                .pick("Cleared password buffer from memory.", "已从内存中擦除当前生成的口令。");
            self.set_status(StatusKind::Info, msg);
        }
    }

    fn run_with_busy_overlay<F, R, T>(&mut self, msg: &str, pre_heavy_op: &mut F, task: T) -> R
    where
        F: FnMut(&Self),
        T: FnOnce(&mut Self) -> R,
    {
        self.busy_message = Some(msg.to_string());
        pre_heavy_op(self);
        let res = task(self);
        self.busy_message = None;
        self.drain_events_requested = true;
        res
    }

    fn handle_modal_key<F>(&mut self, key: KeyEvent, pre_heavy_op: &mut F)
    where
        F: FnMut(&Self),
    {
        // GeneratedPasswordDisplay 拥有专属的防误触关闭保护，不能被单次 Esc 直接擦除！
        if let ModalState::GeneratedPasswordDisplay {
            fingerprint,
            mut confirmed_saved,
            mut plain_copy_mode,
        } = self.modal.clone()
        {
            let ch = plain_char(key);
            if key.code == KeyCode::F(2) || ch == Some('L') {
                self.toggle_lang();
                return;
            }
            if matches!(ch, Some('p') | Some('P')) {
                plain_copy_mode = !plain_copy_mode;
                self.modal_error = None;
                self.modal = ModalState::GeneratedPasswordDisplay {
                    fingerprint,
                    confirmed_saved,
                    plain_copy_mode,
                };
                return;
            }
            if matches!(ch, Some(' ') | Some('y') | Some('Y')) {
                confirmed_saved = !confirmed_saved;
                self.modal_error = None;
                self.modal = ModalState::GeneratedPasswordDisplay {
                    fingerprint,
                    confirmed_saved,
                    plain_copy_mode,
                };
                return;
            }
            if key.code == KeyCode::Esc && plain_copy_mode {
                self.modal = ModalState::GeneratedPasswordDisplay {
                    fingerprint,
                    confirmed_saved,
                    plain_copy_mode: false,
                };
                return;
            }
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                if confirmed_saved {
                    let pending_summary = self.pending_post_backup_summary.take();
                    self.clear_secret_buffers();
                    self.modal_error = None;
                    if let Some(summary) = pending_summary {
                        let out_desc = match &summary {
                            ModalState::OperationSummary { output_path, .. } => {
                                output_path.display().to_string()
                            }
                            _ => String::new(),
                        };
                        self.modal = summary;
                        let msg = match self.lang {
                            UiLang::En => format!(
                                "Backup password zeroized; showing encryption summary ({}).",
                                out_desc
                            ),
                            UiLang::Zh => format!(
                                "备份口令缓冲已清零；正在展示加密结果摘要（{}）。",
                                out_desc
                            ),
                        };
                        self.set_status(StatusKind::Success, msg);
                    } else {
                        self.modal = ModalState::None;
                        let msg = self.lang.pick(
                            "Closed one-time backup password dialog (memory buffer zeroized).",
                            "已关闭一次性备份口令弹窗（内存口令缓冲已立即清零）。",
                        );
                        self.set_status(StatusKind::Info, msg);
                    }
                } else {
                    let warn = self.lang.pick(
                        "Please press [Space] to confirm you have saved this backup password before closing.",
                        "关闭前请先按 [Space] 勾选确认您已妥善保存此备份口令。",
                    );
                    self.modal_error = Some(warn.into());
                    self.set_status(StatusKind::Warning, warn);
                }
            }
            return;
        }

        if matches!(self.modal, ModalState::OperationSummary { .. }) {
            if key.code == KeyCode::F(2) || plain_char(key) == Some('L') {
                self.toggle_lang();
                return;
            }
            if key.code == KeyCode::F(1) || plain_char(key) == Some('?') {
                self.modal_error = None;
                self.modal = ModalState::HelpGuide { scroll: 0 };
                return;
            }
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc)
                || matches!(plain_char(key), Some(' ') | Some('q'))
            {
                self.modal_error = None;
                self.modal = ModalState::None;
                return;
            }
            return;
        }

        if let ModalState::HelpGuide { mut scroll } = self.modal {
            let max_scroll =
                help_guide_lines(self.lang, &self.keystore_dir).len().saturating_sub(6) as u16;
            if key.code == KeyCode::F(2) || plain_char(key) == Some('L') {
                self.toggle_lang();
                return;
            }
            let ch = plain_char(key);
            if key.code == KeyCode::Up || ch == Some('k') {
                scroll = scroll.saturating_sub(1);
                self.modal = ModalState::HelpGuide { scroll };
                return;
            }
            if key.code == KeyCode::Down || ch == Some('j') {
                scroll = scroll.saturating_add(1).min(max_scroll);
                self.modal = ModalState::HelpGuide { scroll };
                return;
            }
            if key.code == KeyCode::PageUp {
                scroll = scroll.saturating_sub(8);
                self.modal = ModalState::HelpGuide { scroll };
                return;
            }
            if key.code == KeyCode::PageDown {
                scroll = scroll.saturating_add(8).min(max_scroll);
                self.modal = ModalState::HelpGuide { scroll };
                return;
            }
            if key.code == KeyCode::Home || ch == Some('g') {
                self.modal = ModalState::HelpGuide { scroll: 0 };
                return;
            }
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::F(1))
                || matches!(ch, Some('?') | Some('q'))
            {
                self.modal_error = None;
                self.modal = ModalState::None;
                return;
            }
            return;
        }

        if key.code == KeyCode::Esc {
            self.clear_secret_buffers();
            self.pending_encrypt_output = None;
            self.label_input_buf.clear();
            self.modal_error = None;
            self.browser_for_recipient_key = false;
            self.modal = ModalState::None;
            let msg = self.lang.pick(
                "Cancelled modal dialog (buffers zeroized).",
                "已取消弹窗操作（临时口令缓冲已清零）。",
            );
            self.set_status(StatusKind::Info, msg);
            return;
        }

        match self.modal.clone() {
            ModalState::None
            | ModalState::GeneratedPasswordDisplay { .. }
            | ModalState::OperationSummary { .. }
            | ModalState::HelpGuide { .. } => {}
            ModalState::PasswordPrompt { title, action } => {
                if is_clear_line_key(key) {
                    self.password_buf.zeroize();
                    self.modal_error = None;
                } else if is_backspace_key(key) {
                    pop_secret_char(&mut self.password_buf);
                    self.modal_error = None;
                } else if key.code == KeyCode::Enter {
                    let pass_copy = self.password_buf.clone();
                    self.clear_secret_buffers();
                    self.modal_error = None;
                    self.execute_password_action(title, action, &pass_copy, pre_heavy_op);
                } else if let Some(c) = plain_char(key) {
                    self.password_buf.push(c);
                    self.modal_error = None;
                }
            }
            ModalState::SymmetricPassword { mut focus_field } => {
                if matches!(key.code, KeyCode::Up | KeyCode::BackTab) {
                    focus_field = (focus_field + 2) % 3;
                    self.modal = ModalState::SymmetricPassword { focus_field };
                } else if matches!(key.code, KeyCode::Down | KeyCode::Tab) {
                    focus_field = (focus_field + 1) % 3;
                    self.modal = ModalState::SymmetricPassword { focus_field };
                } else if is_clear_line_key(key) {
                    if focus_field == 0 {
                        self.password_buf.zeroize();
                    } else if focus_field == 1 {
                        self.confirm_buf.zeroize();
                    }
                    self.modal_error = None;
                } else if is_backspace_key(key) {
                    if focus_field == 0 {
                        pop_secret_char(&mut self.password_buf);
                    } else if focus_field == 1 {
                        pop_secret_char(&mut self.confirm_buf);
                    }
                    self.modal_error = None;
                } else if key.code == KeyCode::Enter {
                    if focus_field == 0 {
                        self.modal = ModalState::SymmetricPassword { focus_field: 1 };
                    } else {
                        self.submit_symmetric_encrypt(pre_heavy_op);
                    }
                } else if let Some(c) = plain_char(key) {
                    if focus_field == 0 {
                        self.password_buf.push(c);
                        self.modal_error = None;
                    } else if focus_field == 1 {
                        self.confirm_buf.push(c);
                        self.modal_error = None;
                    }
                }
            }
            ModalState::NewKeypair { for_encrypt, mut auto_generate, mut focus_field } => {
                if matches!(key.code, KeyCode::Up | KeyCode::BackTab) {
                    focus_field = (focus_field + 3) % 4;
                    self.modal = ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                } else if matches!(key.code, KeyCode::Down | KeyCode::Tab) {
                    focus_field = (focus_field + 1) % 4;
                    self.modal = ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                } else if plain_char(key) == Some(' ') && focus_field == 0 {
                    auto_generate = !auto_generate;
                    if auto_generate {
                        self.password_buf.zeroize();
                        self.confirm_buf.zeroize();
                    }
                    self.modal_error = None;
                    self.modal = ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                } else if is_clear_line_key(key) {
                    if !auto_generate {
                        if focus_field == 1 {
                            self.password_buf.zeroize();
                        } else if focus_field == 2 {
                            self.confirm_buf.zeroize();
                        }
                    }
                    self.modal_error = None;
                } else if is_backspace_key(key) {
                    if !auto_generate {
                        if focus_field == 1 {
                            pop_secret_char(&mut self.password_buf);
                        } else if focus_field == 2 {
                            pop_secret_char(&mut self.confirm_buf);
                        }
                    }
                    self.modal_error = None;
                } else if key.code == KeyCode::Enter {
                    if focus_field == 0 {
                        auto_generate = !auto_generate;
                        if auto_generate {
                            self.password_buf.zeroize();
                            self.confirm_buf.zeroize();
                        }
                        self.modal =
                            ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                    } else if !auto_generate && focus_field == 1 {
                        focus_field = 2;
                        self.modal =
                            ModalState::NewKeypair { for_encrypt, auto_generate, focus_field };
                    } else {
                        self.submit_new_keypair(for_encrypt, auto_generate, pre_heavy_op);
                    }
                } else if let Some(c) = plain_char(key) {
                    if !auto_generate {
                        if focus_field == 1 {
                            self.password_buf.push(c);
                            self.modal_error = None;
                        } else if focus_field == 2 {
                            self.confirm_buf.push(c);
                            self.modal_error = None;
                        }
                    }
                }
            }
            ModalState::ChangeKeyPassword { fingerprint, display_name, mut focus_field } => {
                if matches!(key.code, KeyCode::Up | KeyCode::BackTab) {
                    focus_field = (focus_field + 3) % 4;
                    self.modal =
                        ModalState::ChangeKeyPassword { fingerprint, display_name, focus_field };
                } else if matches!(key.code, KeyCode::Down | KeyCode::Tab) {
                    focus_field = (focus_field + 1) % 4;
                    self.modal =
                        ModalState::ChangeKeyPassword { fingerprint, display_name, focus_field };
                } else if is_clear_line_key(key) {
                    match focus_field {
                        0 => self.old_password_buf.zeroize(),
                        1 => self.password_buf.zeroize(),
                        2 => self.confirm_buf.zeroize(),
                        _ => {}
                    }
                    self.modal_error = None;
                } else if is_backspace_key(key) {
                    match focus_field {
                        0 => pop_secret_char(&mut self.old_password_buf),
                        1 => pop_secret_char(&mut self.password_buf),
                        2 => pop_secret_char(&mut self.confirm_buf),
                        _ => {}
                    }
                    self.modal_error = None;
                } else if key.code == KeyCode::Enter {
                    if focus_field < 2 {
                        self.modal = ModalState::ChangeKeyPassword {
                            fingerprint,
                            display_name,
                            focus_field: focus_field + 1,
                        };
                    } else {
                        self.submit_change_key_password(fingerprint, display_name, pre_heavy_op);
                    }
                } else if let Some(c) = plain_char(key) {
                    match focus_field {
                        0 => self.old_password_buf.push(c),
                        1 => self.password_buf.push(c),
                        2 => self.confirm_buf.push(c),
                        _ => {}
                    }
                    self.modal_error = None;
                }
            }
            ModalState::SetKeyLabel { fingerprint, .. } => {
                if is_clear_line_key(key) {
                    self.label_input_buf.clear();
                    self.modal_error = None;
                } else if is_backspace_key(key) {
                    self.label_input_buf.pop();
                    self.modal_error = None;
                } else if key.code == KeyCode::Enter {
                    let desired = if self.label_input_buf.trim().is_empty() {
                        None
                    } else {
                        Some(self.label_input_buf.trim().to_string())
                    };
                    match set_key_label(&self.keystore_dir, &fingerprint, desired.as_deref()) {
                        Ok(()) => {
                            self.label_input_buf.clear();
                            self.modal_error = None;
                            self.modal = ModalState::None;
                            self.refresh_keyring();
                            match desired {
                                Some(lbl) => {
                                    let msg = match self.lang {
                                        UiLang::En => {
                                            format!(
                                                "✅ Assigned local label [{}] (0600 local-only)",
                                                lbl
                                            )
                                        }
                                        UiLang::Zh => {
                                            format!(
                                                "✅ 已设置本机别名 [{}]（0600 仅本机保存）",
                                                lbl
                                            )
                                        }
                                    };
                                    self.set_status(StatusKind::Success, msg);
                                }
                                None => self.set_status(
                                    StatusKind::Info,
                                    self.lang.pick(
                                        "Cleared local label from keypair.",
                                        "已清除该密钥对的本机别名。",
                                    ),
                                ),
                            }
                        }
                        Err(e) => {
                            self.modal_error = Some(format!("❌ {}", e));
                            self.set_status(StatusKind::Error, format!("{}", e));
                        }
                    }
                } else if let Some(c) = plain_char(key) {
                    self.label_input_buf.push(c);
                    self.modal_error = None;
                }
            }
            ModalState::FileBrowser {
                target,
                current_dir,
                entries,
                mut selected_idx,
                mut show_hidden,
            } => {
                let ch = plain_char(key);
                if key.code == KeyCode::Up || ch == Some('k') {
                    selected_idx = selected_idx.saturating_sub(1);
                    self.modal = ModalState::FileBrowser {
                        target,
                        current_dir,
                        entries,
                        selected_idx,
                        show_hidden,
                    };
                } else if key.code == KeyCode::Down || ch == Some('j') {
                    if selected_idx + 1 < entries.len() {
                        selected_idx += 1;
                    }
                    self.modal = ModalState::FileBrowser {
                        target,
                        current_dir,
                        entries,
                        selected_idx,
                        show_hidden,
                    };
                } else if ch == Some('.') {
                    show_hidden = !show_hidden;
                    self.open_file_browser_in_dir_preserving_aux(target, current_dir, show_hidden);
                } else if is_backspace_key(key) || key.code == KeyCode::Left || ch == Some('h') {
                    if let Some(parent) = current_dir.parent() {
                        let parent_buf = parent.to_path_buf();
                        self.open_file_browser_in_dir_preserving_aux(
                            target,
                            parent_buf,
                            show_hidden,
                        );
                    }
                } else if matches!(key.code, KeyCode::Enter | KeyCode::Right) || ch == Some('l') {
                    let Some(chosen) = entries.get(selected_idx).cloned() else {
                        return;
                    };
                    if chosen.is_dir {
                        self.open_file_browser_in_dir_preserving_aux(
                            target,
                            chosen.path,
                            show_hidden,
                        );
                    } else if key.code == KeyCode::Enter {
                        let formatted = Self::format_selected_path(&chosen.path);
                        let for_rec_key = self.browser_for_recipient_key;
                        self.browser_for_recipient_key = false;
                        self.modal = ModalState::None;
                        if for_rec_key {
                            self.enc_external_pub_path = formatted.clone();
                            let msg = match self.lang {
                                UiLang::En => {
                                    format!("Selected external recipient public key: {}", formatted)
                                }
                                UiLang::Zh => format!("已选择外部接收方公钥: {}", formatted),
                            };
                            self.set_status(StatusKind::Info, msg);
                        } else {
                            match target {
                                FileBrowserTarget::EncryptInput => {
                                    self.enc_input_path = formatted.clone();
                                    let msg = match self.lang {
                                        UiLang::En => format!("Selected input file: {}", formatted),
                                        UiLang::Zh => format!("已选择待加密文件: {}", formatted),
                                    };
                                    self.set_status(StatusKind::Info, msg);
                                }
                                FileBrowserTarget::EncryptOutput => {
                                    self.enc_output_path = formatted.clone();
                                    let msg = match self.lang {
                                        UiLang::En => {
                                            format!("Selected output path: {}", formatted)
                                        }
                                        UiLang::Zh => format!("已选择输出路径: {}", formatted),
                                    };
                                    self.set_status(StatusKind::Info, msg);
                                }
                                FileBrowserTarget::DecryptInput => {
                                    self.dec_input_path = formatted.clone();
                                    self.update_decrypt_inspection();
                                    let msg = match self.lang {
                                        UiLang::En => format!(
                                            "Selected & inspected encrypted file: {}",
                                            formatted
                                        ),
                                        UiLang::Zh => {
                                            format!("已选择并透视加密文件: {}", formatted)
                                        }
                                    };
                                    self.set_status(StatusKind::Info, msg);
                                }
                                FileBrowserTarget::DecryptOutput => {
                                    self.dec_output_path = formatted.clone();
                                    let msg = match self.lang {
                                        UiLang::En => {
                                            format!("Selected output path: {}", formatted)
                                        }
                                        UiLang::Zh => format!("已选择输出路径: {}", formatted),
                                    };
                                    self.set_status(StatusKind::Info, msg);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn validate_confirmed_buffers(&mut self) -> Result<Zeroizing<String>, String> {
        if self.password_buf.chars().count() < MIN_PASSWORD_LENGTH {
            let err = match self.lang {
                UiLang::En => {
                    format!("Password too short; must be >= {} chars", MIN_PASSWORD_LENGTH)
                }
                UiLang::Zh => {
                    format!("口令长度过短，至少需要 {} 个字符", MIN_PASSWORD_LENGTH)
                }
            };
            return Err(err);
        }
        if self.password_buf.len() > MAX_PASSWORD_LENGTH {
            let err = match self.lang {
                UiLang::En => {
                    format!("Password too long; must be <= {} bytes", MAX_PASSWORD_LENGTH)
                }
                UiLang::Zh => {
                    format!("口令长度超出上限（最多 {} 字节）", MAX_PASSWORD_LENGTH)
                }
            };
            return Err(err);
        }
        if *self.password_buf != *self.confirm_buf {
            let err = self.lang.pick(
                "Passwords mismatched! Buffers wiped — please re-enter.",
                "两次输入的口令不一致！已清空重输缓冲，请重新输入。",
            );
            return Err(err.into());
        }
        Ok(self.password_buf.clone())
    }

    fn submit_symmetric_encrypt<F>(&mut self, pre_heavy_op: &mut F)
    where
        F: FnMut(&Self),
    {
        let pw = match self.validate_confirmed_buffers() {
            Ok(p) => p,
            Err(err_msg) => {
                self.clear_secret_buffers();
                self.modal = ModalState::SymmetricPassword { focus_field: 0 };
                self.modal_error = Some(format!("❌ {}", err_msg));
                self.set_status(StatusKind::Error, err_msg);
                return;
            }
        };

        self.clear_secret_buffers();
        self.modal_error = None;
        self.modal = ModalState::None;

        let input_path = PathBuf::from(self.enc_input_path.trim());
        let out_opt = self.pending_encrypt_output.take().or_else(|| {
            if self.enc_output_path.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(self.enc_output_path.trim()))
            }
        });
        let force = self.enc_force;

        let busy_msg = self.lang.pick(
            "⏳ Deriving Argon2id key (64 MiB) & encrypting file...",
            "⏳ 正在派生 Argon2id 密钥（64 MiB）并加密文件...",
        );
        let res = self.run_with_busy_overlay(busy_msg, pre_heavy_op, |_| {
            encrypt_file_symmetric(&input_path, &pw, out_opt.as_deref(), force)
        });

        match res {
            Ok(out_path) => {
                let status = match self.lang {
                    UiLang::En => {
                        format!("✅ Symmetrically encrypted (SGPGv2) -> {}", out_path.display())
                    }
                    UiLang::Zh => {
                        format!("✅ 纯口令对称加密完成 (SGPGv2) -> {}", out_path.display())
                    }
                };
                self.set_status(StatusKind::Success, status);
                self.modal = ModalState::OperationSummary {
                    kind: SummaryKind::EncryptSymmetric,
                    output_path: out_path,
                    key_fingerprint: None,
                    verified_signer_fp: None,
                    companion_instr: CompanionInstrStatus::None,
                };
            }
            Err(e) => {
                let prefix = self.lang.pick("❌ Symmetric encryption failed", "❌ 对称加密失败");
                self.set_status(StatusKind::Error, format!("{}: {}", prefix, e));
            }
        }
    }

    fn submit_new_keypair<F>(
        &mut self,
        for_encrypt: bool,
        auto_generate: bool,
        pre_heavy_op: &mut F,
    ) where
        F: FnMut(&Self),
    {
        self.backup_modal_encrypted_file = None;
        let user_pw: Option<Zeroizing<String>> = if auto_generate {
            None
        } else {
            match self.validate_confirmed_buffers() {
                Ok(pw) => Some(pw),
                Err(err_msg) => {
                    self.clear_secret_buffers();
                    self.modal =
                        ModalState::NewKeypair { for_encrypt, auto_generate, focus_field: 1 };
                    self.modal_error = Some(format!("❌ {}", err_msg));
                    self.set_status(StatusKind::Error, err_msg);
                    return;
                }
            }
        };

        self.clear_secret_buffers();
        self.modal_error = None;
        self.modal = ModalState::None;

        if for_encrypt {
            let ks_dir = self.keystore_dir.clone();
            let input_path = PathBuf::from(self.enc_input_path.trim());
            let out_opt = self.pending_encrypt_output.take().or_else(|| {
                if self.enc_output_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.enc_output_path.trim()))
                }
            });
            let write_instr = !self.enc_no_instructions;
            let force = self.enc_force;

            let busy_msg = self.lang.pick(
                "⏳ Generating Ed25519+X25519 keys (Argon2id 2×64 MiB) & encrypting file...",
                "⏳ 正在生成 Ed25519+X25519 密钥对（Argon2id 2×64 MiB）并加密文件...",
            );
            let res = self.run_with_busy_overlay(busy_msg, pre_heavy_op, |_| {
                encrypt_workflow_with_new_keys_opts(
                    &ks_dir,
                    &input_path,
                    user_pw.as_deref().map(|s| s.as_str()),
                    out_opt.as_deref(),
                    None,
                    write_instr,
                    force,
                )
            });

            match res {
                Ok(outcome) => {
                    let fp = outcome.keys.fingerprint.clone();
                    let auto_pw = outcome.keys.auto_generated_password.clone();
                    self.refresh_keyring();
                    if let Some(pos) = self.keyring.iter().position(|k| k.fingerprint == fp) {
                        self.selected_key_idx = pos;
                    }
                    let _ = self.select_key_for_encryption(&fp);
                    if !outcome.instructions_skipped && !outcome.instructions_written {
                        let msg = match self.lang {
                            UiLang::En => format!(
                                "✅ Generated keypair ({}) & encrypted -> {} (⚠️ {} already exists; not overwritten)",
                                &fp[..12],
                                outcome.encrypted_file.display(),
                                outcome.instructions_file.display()
                            ),
                            UiLang::Zh => format!(
                                "✅ 已生成新密钥 ({}) 并加密 -> {}（⚠️ 伴生说明 {} 已存在，未覆盖）",
                                &fp[..12],
                                outcome.encrypted_file.display(),
                                outcome.instructions_file.display()
                            ),
                        };
                        self.set_status(StatusKind::Warning, msg);
                    } else {
                        let msg = match self.lang {
                            UiLang::En => format!(
                                "✅ Generated keypair ({}) & signed/encrypted -> {}",
                                &fp[..12],
                                outcome.encrypted_file.display()
                            ),
                            UiLang::Zh => format!(
                                "✅ 已生成新密钥 ({}) 并完成签名加密 -> {}",
                                &fp[..12],
                                outcome.encrypted_file.display()
                            ),
                        };
                        self.set_status(StatusKind::Success, msg);
                    }
                    let summary_modal = ModalState::OperationSummary {
                        kind: SummaryKind::EncryptNewKeypair,
                        output_path: outcome.encrypted_file.clone(),
                        key_fingerprint: Some(fp.clone()),
                        verified_signer_fp: Some(fp.clone()),
                        companion_instr: Self::companion_status(
                            outcome.instructions_written,
                            outcome.instructions_skipped,
                            outcome.instructions_file,
                        ),
                    };
                    if let Some(pw) = auto_pw {
                        self.backup_modal_encrypted_file = Some(outcome.encrypted_file);
                        self.one_time_backup_pass = Some(pw);
                        self.pending_post_backup_summary = Some(summary_modal);
                        self.modal = ModalState::GeneratedPasswordDisplay {
                            fingerprint: fp,
                            confirmed_saved: false,
                            plain_copy_mode: false,
                        };
                    } else {
                        self.modal = summary_modal;
                    }
                }
                Err(e) => {
                    let prefix =
                        self.lang.pick("❌ Encrypt workflow failed", "❌ 生成密钥并加密失败");
                    self.set_status(StatusKind::Error, format!("{}: {}", prefix, e));
                }
            }
        } else {
            let ks_dir = self.keystore_dir.clone();
            let busy_msg = self.lang.pick(
                "⏳ Generating Ed25519+X25519 keypair & encrypting backups (Argon2id 2×64 MiB)...",
                "⏳ 正在生成 Ed25519+X25519 密钥对并加密私钥备份（Argon2id 2×64 MiB）...",
            );
            let res = self.run_with_busy_overlay(busy_msg, pre_heavy_op, |_| {
                generate_and_store_keys_in_dir(&ks_dir, user_pw.as_deref().map(|s| s.as_str()))
            });

            match res {
                Ok(keys) => {
                    let fp = keys.fingerprint.clone();
                    let auto_pw = keys.auto_generated_password.clone();
                    self.refresh_keyring();
                    if let Some(pos) = self.keyring.iter().position(|k| k.fingerprint == fp) {
                        self.selected_key_idx = pos;
                    }
                    let _ = self.select_key_for_encryption(&fp);
                    let msg = match self.lang {
                        UiLang::En => format!("✅ Keypair generated: {}", fp),
                        UiLang::Zh => format!("✅ 新密钥对已生成: {}", fp),
                    };
                    self.set_status(StatusKind::Success, msg);
                    if let Some(pw) = auto_pw {
                        self.one_time_backup_pass = Some(pw);
                        self.modal = ModalState::GeneratedPasswordDisplay {
                            fingerprint: fp,
                            confirmed_saved: false,
                            plain_copy_mode: false,
                        };
                    }
                }
                Err(e) => {
                    let prefix = self.lang.pick("❌ Key generation failed", "❌ 密钥对生成失败");
                    self.set_status(StatusKind::Error, format!("{}: {}", prefix, e));
                }
            }
        }
    }

    fn submit_change_key_password<F>(
        &mut self,
        fingerprint: String,
        display_name: String,
        pre_heavy_op: &mut F,
    ) where
        F: FnMut(&Self),
    {
        if self.old_password_buf.is_empty() {
            self.modal_error = Some(
                self.lang
                    .pick("❌ Please enter the current backup password.", "❌ 请输入当前备份口令。")
                    .into(),
            );
            self.modal =
                ModalState::ChangeKeyPassword { fingerprint, display_name, focus_field: 0 };
            return;
        }
        let old_pw = self.old_password_buf.clone();
        let new_pw = match self.validate_confirmed_buffers() {
            Ok(p) => p,
            Err(err_msg) => {
                self.password_buf.zeroize();
                self.confirm_buf.zeroize();
                self.modal_error = Some(format!("❌ {}", err_msg));
                self.modal =
                    ModalState::ChangeKeyPassword { fingerprint, display_name, focus_field: 1 };
                self.set_status(StatusKind::Error, err_msg);
                return;
            }
        };

        self.clear_secret_buffers();
        self.modal_error = None;
        let ks_dir = self.keystore_dir.clone();
        let fp_ref = fingerprint.clone();
        let busy = self.lang.pick(
            "⏳ Unlocking & re-encrypting Ed25519+X25519 backups (Argon2id)...",
            "⏳ 正在解锁并重新加密 Ed25519+X25519 私钥备份 (Argon2id)...",
        );

        let res = self.run_with_busy_overlay(busy, pre_heavy_op, |_| {
            change_keypair_password(&ks_dir, &fp_ref, &old_pw, &new_pw)
        });

        match res {
            Ok(fp) => {
                self.modal = ModalState::None;
                let msg = match self.lang {
                    UiLang::En => format!("✅ Rotated backup password for keypair {}", &fp[..16]),
                    UiLang::Zh => format!("✅ 已轮换密钥 {} 的备份口令", &fp[..16]),
                };
                self.set_status(StatusKind::Success, msg);
            }
            Err(e) => {
                self.clear_secret_buffers();
                let err_modal = match self.lang {
                    UiLang::En => format!("❌ {} — please try again", e),
                    UiLang::Zh => format!("❌ {} — 请重试", e),
                };
                self.modal_error = Some(err_modal);
                self.modal =
                    ModalState::ChangeKeyPassword { fingerprint, display_name, focus_field: 0 };
                self.set_status(StatusKind::Error, format!("❌ {}", e));
            }
        }
    }

    fn execute_password_action<F>(
        &mut self,
        title: String,
        action: PasswordAction,
        password: &str,
        pre_heavy_op: &mut F,
    ) where
        F: FnMut(&Self),
    {
        match action {
            PasswordAction::DecryptSymmetricFile => {
                let input_path = PathBuf::from(self.dec_input_path.trim());
                let out_opt = if self.dec_output_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.dec_output_path.trim()))
                };
                let force = self.dec_force;
                let busy_msg = self.lang.pick(
                    "⏳ Deriving Argon2id key (64 MiB) & decrypting file...",
                    "⏳ 正在派生 Argon2id 密钥（64 MiB）并解密文件...",
                );
                let res = self.run_with_busy_overlay(busy_msg, pre_heavy_op, |_| {
                    decrypt_file_symmetric(&input_path, password, out_opt.as_deref(), force)
                });
                match res {
                    Ok(out_path) => {
                        self.dec_last_verified_fp = None;
                        let msg = match self.lang {
                            UiLang::En => {
                                format!("✅ Symmetric file decrypted -> {}", out_path.display())
                            }
                            UiLang::Zh => {
                                format!("✅ 对称文件解密成功 -> {}", out_path.display())
                            }
                        };
                        self.set_status(StatusKind::Success, msg);
                        self.modal = ModalState::OperationSummary {
                            kind: SummaryKind::DecryptSymmetric,
                            output_path: out_path,
                            key_fingerprint: None,
                            verified_signer_fp: None,
                            companion_instr: CompanionInstrStatus::None,
                        };
                    }
                    Err(CryptError::Crypto(msg)) => {
                        self.clear_secret_buffers();
                        let modal_err = match self.lang {
                            UiLang::En => format!(
                                "❌ Wrong password or authentication failed ({}) — try again or Esc",
                                msg
                            ),
                            UiLang::Zh => format!(
                                "❌ 口令错误或密文认证失败 ({}) — 请重输或按 Esc 取消",
                                msg
                            ),
                        };
                        self.modal_error = Some(modal_err);
                        self.modal = ModalState::PasswordPrompt { title, action };
                        let prefix =
                            self.lang.pick("❌ Symmetric decryption failed", "❌ 对称解密失败");
                        self.set_status(StatusKind::Error, format!("{}: {}", prefix, msg));
                    }
                    Err(e) => {
                        self.modal = ModalState::None;
                        let prefix =
                            self.lang.pick("❌ Symmetric decryption failed", "❌ 对称解密失败");
                        self.set_status(StatusKind::Error, format!("{}: {}", prefix, e));
                    }
                }
            }
            PasswordAction::SignAndEncrypt => {
                let ext_idx = self.external_recipient_choice_idx();
                let rec_fp = if self.enc_key_choice >= 2 && self.enc_key_choice < ext_idx {
                    self.recipient_keyring_entries()
                        .get(self.enc_key_choice - 2)
                        .map(|k| k.fingerprint.clone())
                } else {
                    None
                };
                let x_pub = match self.resolve_selected_recipient_pubkey_path() {
                    Ok(p) => p,
                    Err(msg) => {
                        self.modal = ModalState::None;
                        self.set_status(StatusKind::Error, msg);
                        return;
                    }
                };
                if let Err(e) =
                    preflight_validate_recipient_pubkey(&x_pub, Some(&self.keystore_dir))
                {
                    self.modal = ModalState::None;
                    self.set_status(StatusKind::Error, format!("❌ {}", e));
                    return;
                }
                let Some(ed_enc) = self
                    .own_signing_keys()
                    .get(self.enc_sign_key_idx)
                    .and_then(|e| e.ed25519_enc_path.clone())
                else {
                    self.modal = ModalState::None;
                    let msg = self.lang.pick(
                        "Own signing key backup not found.",
                        "未找到自有 Ed25519 签名私钥备份。",
                    );
                    self.set_status(StatusKind::Error, msg);
                    return;
                };

                let busy_msg = self.lang.pick(
                    "⏳ Unlocking Ed25519 signing key (Argon2id 64 MiB)...",
                    "⏳ 正在解锁 Ed25519 签名私钥（Argon2id 64 MiB）...",
                );
                let unlock_res = self.run_with_busy_overlay(busy_msg, pre_heavy_op, |_| {
                    load_signing_key_with_password(&ed_enc, password)
                });
                let sk = match unlock_res {
                    Ok(k) => k,
                    Err(e) => {
                        self.clear_secret_buffers();
                        let modal_err = match self.lang {
                            UiLang::En => format!(
                                "❌ Failed to unlock signing key ({}) — try again or Esc",
                                e
                            ),
                            UiLang::Zh => {
                                format!("❌ 签名私钥解锁失败 ({}) — 请重输口令或按 Esc 取消", e)
                            }
                        };
                        self.modal_error = Some(modal_err);
                        self.modal = ModalState::PasswordPrompt { title, action };
                        let prefix = self
                            .lang
                            .pick("❌ Failed to unlock signing key", "❌ 解锁签名私钥失败");
                        self.set_status(StatusKind::Error, format!("{}: {}", prefix, e));
                        return;
                    }
                };

                self.modal = ModalState::None;
                let input_path = PathBuf::from(self.enc_input_path.trim());
                let out_opt = self.pending_encrypt_output.take().or_else(|| {
                    if self.enc_output_path.trim().is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(self.enc_output_path.trim()))
                    }
                });

                match encrypt_workflow_with_existing_key_in_dir(
                    Some(&self.keystore_dir),
                    &input_path,
                    &x_pub,
                    out_opt.as_deref(),
                    Some(&sk),
                    !self.enc_no_instructions,
                    self.enc_force,
                ) {
                    Ok(outcome) => {
                        if !outcome.instructions_skipped && !outcome.instructions_written {
                            let msg = match self.lang {
                                UiLang::En => format!(
                                    "✅ Signed & encrypted -> {} (⚠️ {} already exists; not overwritten)",
                                    outcome.encrypted_file.display(),
                                    outcome.instructions_file.display()
                                ),
                                UiLang::Zh => format!(
                                    "✅ 已签名并加密 -> {}（⚠️ 伴生说明 {} 已存在，未覆盖）",
                                    outcome.encrypted_file.display(),
                                    outcome.instructions_file.display()
                                ),
                            };
                            self.set_status(StatusKind::Warning, msg);
                        } else {
                            let msg = match self.lang {
                                UiLang::En => format!(
                                    "✅ Signed & encrypted -> {}",
                                    outcome.encrypted_file.display()
                                ),
                                UiLang::Zh => {
                                    format!(
                                        "✅ 已签名并加密 -> {}",
                                        outcome.encrypted_file.display()
                                    )
                                }
                            };
                            self.set_status(StatusKind::Success, msg);
                        }
                        self.modal = ModalState::OperationSummary {
                            kind: SummaryKind::EncryptExistingSigned,
                            output_path: outcome.encrypted_file,
                            key_fingerprint: rec_fp,
                            verified_signer_fp: outcome.signed_fingerprint,
                            companion_instr: Self::companion_status(
                                outcome.instructions_written,
                                outcome.instructions_skipped,
                                outcome.instructions_file,
                            ),
                        };
                    }
                    Err(e) => {
                        let prefix = self.lang.pick("❌ Encryption failed", "❌ 加密失败");
                        self.set_status(StatusKind::Error, format!("{}: {}", prefix, e));
                    }
                }
            }
            PasswordAction::DecryptFile => {
                let Some(entry) = self.own_decrypt_keys().get(self.dec_key_idx).copied().cloned()
                else {
                    self.modal = ModalState::None;
                    let msg = self.lang.pick(
                        "No decryption private key selected.",
                        "未选中有效的 X25519 解密私钥。",
                    );
                    self.set_status(StatusKind::Error, msg);
                    return;
                };
                let Some(ref x_enc) = entry.x25519_enc_path else {
                    self.modal = ModalState::None;
                    let msg = self
                        .lang
                        .pick("Missing X25519 private key file.", "缺少 X25519 解密私钥备份文件。");
                    self.set_status(StatusKind::Error, msg);
                    return;
                };

                let ks_dir = self.keystore_dir.clone();
                let input_path = PathBuf::from(self.dec_input_path.trim());
                let x_enc_path = x_enc.clone();
                let out_opt = if self.dec_output_path.trim().is_empty() {
                    None
                } else {
                    Some(PathBuf::from(self.dec_output_path.trim()))
                };
                let signer_owned: Option<String> = if !self.dec_signer_arg.trim().is_empty() {
                    Some(self.dec_signer_arg.trim().to_string())
                } else if self.dec_signer_choice > 0 {
                    self.keyring.get(self.dec_signer_choice - 1).map(|k| k.fingerprint.clone())
                } else {
                    None
                };
                let require_sig = self.dec_require_sig;
                let force = self.dec_force;

                let busy_msg = self.lang.pick(
                    "⏳ Unlocking X25519 key (Argon2id 64 MiB), verifying & decrypting...",
                    "⏳ 正在解锁 X25519 私钥（Argon2id 64 MiB）、验签并解密...",
                );
                let res = self.run_with_busy_overlay(busy_msg, pre_heavy_op, |_| {
                    decrypt_workflow_with_password_in_dir(
                        &ks_dir,
                        &input_path,
                        &x_enc_path,
                        password,
                        out_opt.as_deref(),
                        signer_owned.as_deref(),
                        require_sig,
                        force,
                    )
                });

                match res {
                    Ok(outcome) => {
                        self.dec_last_verified_fp = outcome.verified_signer_fingerprint.clone();
                        match &outcome.verified_signer_fingerprint {
                            Some(fp) => {
                                let msg = match self.lang {
                                    UiLang::En => format!(
                                        "✅ Signature verified ({}…) & decrypted -> {}",
                                        &fp[..12],
                                        outcome.decrypted_file.display()
                                    ),
                                    UiLang::Zh => format!(
                                        "✅ 验签通过 ({}…) 并解密还原 -> {}",
                                        &fp[..12],
                                        outcome.decrypted_file.display()
                                    ),
                                };
                                self.set_status(StatusKind::Success, msg);
                            }
                            None => {
                                let msg = match self.lang {
                                    UiLang::En => format!(
                                        "ℹ️ Decrypted (no embedded signature) -> {}",
                                        outcome.decrypted_file.display()
                                    ),
                                    UiLang::Zh => format!(
                                        "ℹ️ 已解密还原（该密文无内嵌签名）-> {}",
                                        outcome.decrypted_file.display()
                                    ),
                                };
                                self.set_status(StatusKind::Warning, msg);
                            }
                        }
                        self.modal = ModalState::OperationSummary {
                            kind: SummaryKind::DecryptPubenc,
                            output_path: outcome.decrypted_file,
                            key_fingerprint: Some(entry.fingerprint),
                            verified_signer_fp: outcome.verified_signer_fingerprint,
                            companion_instr: CompanionInstrStatus::None,
                        };
                    }
                    Err(CryptError::Key(msg)) if msg.contains("Failed to unlock private key") => {
                        self.clear_secret_buffers();
                        self.dec_last_verified_fp = None;
                        let modal_err = match self.lang {
                            UiLang::En => format!("❌ {} — try again or Esc", msg),
                            UiLang::Zh => format!("❌ {} — 请重试或按 Esc 取消", msg),
                        };
                        self.modal_error = Some(modal_err);
                        self.modal = ModalState::PasswordPrompt { title, action };
                        self.set_status(StatusKind::Error, format!("❌ {}", msg));
                    }
                    Err(e) => {
                        self.modal = ModalState::None;
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
    use yacrypt_core::keystore::{export_public_key_bundle, import_public_key_bundle};

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
        assert!(matches!(
            app.modal,
            ModalState::NewKeypair { auto_generate: true, focus_field: 0, .. }
        ));
        // Toggle auto-generate off (Space) and move to Backup Password field (Down)
        app.handle_key_event(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        assert_eq!(app.password_buf.as_str(), "se");

        // Ctrl+V / Alt+X must NOT append 'v' or 'x'; Ctrl+H backspaces; Ctrl+U wipes buffer
        app.handle_key_event(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL));
        app.handle_key_event(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT));
        assert_eq!(app.password_buf.as_str(), "se");
        app.handle_key_event(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL));
        assert_eq!(app.password_buf.as_str(), "s");
        app.handle_key_event(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert!(app.password_buf.is_empty());

        app.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);
        assert!(app.password_buf.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generated_backup_password_requires_confirmation_checkbox_before_closing() {
        let dir = std::env::temp_dir().join(format!("yacrypt_tui_pwlock_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app = TuiApp::new(dir.join("keystore"));
        app.one_time_backup_pass = Some(Zeroizing::new("A".repeat(64)));
        app.modal = ModalState::GeneratedPasswordDisplay {
            fingerprint: "F".repeat(64),
            confirmed_saved: false,
            plain_copy_mode: false,
        };

        // Enter & Esc while unchecked MUST NOT close or erase the backup password
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.one_time_backup_pass.is_some());
        assert!(app.modal_error.is_some());

        app.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.one_time_backup_pass.is_some());

        // Toggle plain copy view with 'p' and back with Esc
        app.handle_key_event(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert!(matches!(
            app.modal,
            ModalState::GeneratedPasswordDisplay { plain_copy_mode: true, .. }
        ));
        app.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(
            app.modal,
            ModalState::GeneratedPasswordDisplay { plain_copy_mode: false, .. }
        ));

        // Check confirmation with Space -> Enter closes and zeroizes
        app.handle_key_event(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);
        assert!(app.one_time_backup_pass.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symmetric_dual_box_and_unedited_path_quit_guard_and_preflight_conflict() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_tui_sym_guard_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("doc.txt");
        let existing_out = dir.join("doc.txt.enc");
        std::fs::write(&input, b"secret").unwrap();
        std::fs::write(&existing_out, b"already here").unwrap();

        let mut app = TuiApp::new(dir.join("keystore"));
        app.switch_tab(ActiveTab::Encrypt);
        app.enc_input_path = input.to_string_lossy().to_string();
        app.enc_key_choice = 1; // Symmetric

        // 1. Single 'q' on unedited Input File field warns instead of instant-quitting
        app.enc_focus = 0;
        app.handle_key_event(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.should_quit);
        assert_eq!(app.status_kind, StatusKind::Warning);
        // Second 'q' quits
        app.handle_key_event(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.should_quit);
        app.should_quit = false;

        // 2. Preflight conflict blocks BEFORE opening SymmetricPassword modal
        app.enc_output_path = existing_out.to_string_lossy().to_string();
        app.trigger_encrypt_action();
        assert_eq!(app.modal, ModalState::None);
        assert_eq!(app.status_kind, StatusKind::Error);

        // 3. With force=true, opens dual-box SymmetricPassword modal (unless same inode!)
        app.enc_output_path = input.to_string_lossy().to_string();
        app.enc_force = true;
        app.trigger_encrypt_action();
        assert_eq!(
            app.modal,
            ModalState::None,
            "same-inode overwrite must be blocked even with force"
        );

        app.enc_output_path.clear();
        app.trigger_encrypt_action();
        assert_eq!(app.modal, ModalState::SymmetricPassword { focus_field: 0 });

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_key_decoupling_h1_safe_anchor_and_stale_badge_clearing() {
        let dir = std::env::temp_dir().join(format!("yacrypt_tui_peer_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let alice_ks = dir.join("alice_ks");
        let bob_ks = dir.join("bob_ks");
        let pw = "peer-test-pass-1234";
        let alice_keys = generate_and_store_keys_in_dir(&alice_ks, Some(pw)).unwrap();
        let bob_keys = generate_and_store_keys_in_dir(&bob_ks, Some(pw)).unwrap();

        // Export Bob's public bundle and import into Alice's keystore (public-only peer entry!)
        let bundle_path = dir.join("bob_bundle.asc");
        export_public_key_bundle(&bob_ks, &bob_keys.fingerprint, pw, Some(&bundle_path), false)
            .unwrap();
        import_public_key_bundle(&alice_ks, &bundle_path, Some("bob"), false).unwrap();

        let mut alice_app = TuiApp::new(alice_ks.clone());
        // Alice's keystore has 2 recipient keys (Alice + Bob), 1 own signing key (Alice), 1 own decrypt key (Alice)
        assert_eq!(alice_app.recipient_keyring_entries().len(), 2);
        assert_eq!(alice_app.own_signing_keys().len(), 1);
        assert_eq!(alice_app.own_decrypt_keys().len(), 1);
        assert_eq!(alice_app.own_signing_keys()[0].fingerprint, alice_keys.fingerprint);

        // Encrypt a file TO Bob signed BY Alice via TUI state machine
        let msg_path = dir.join("for_bob.txt");
        std::fs::write(&msg_path, b"hello bob from alice").unwrap();
        let bob_rec_idx = alice_app
            .recipient_keyring_entries()
            .iter()
            .position(|k| k.fingerprint == bob_keys.fingerprint)
            .unwrap();
        alice_app.enc_input_path = msg_path.to_string_lossy().to_string();
        alice_app.enc_key_choice = 2 + bob_rec_idx;
        alice_app.enc_sign_file = true;
        alice_app.enc_sign_key_idx = 0; // Alice's own signing key!
        alice_app.trigger_encrypt_action();
        assert!(matches!(
            alice_app.modal,
            ModalState::PasswordPrompt { action: PasswordAction::SignAndEncrypt, .. }
        ));

        // Wrong signing password keeps modal open and wipes password_buf
        alice_app.password_buf = Zeroizing::new("wrong-password-999".into());
        alice_app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(alice_app.modal, ModalState::PasswordPrompt { .. }));
        assert!(alice_app.password_buf.is_empty());
        assert!(alice_app.modal_error.is_some());

        // Correct signing password encrypts to for_bob.txt.pubenc
        let mut saw_busy = false;
        alice_app.password_buf = Zeroizing::new(pw.into());
        alice_app.handle_key_event_with_hook(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            |busy_state| {
                if busy_state.busy_message.is_some() {
                    saw_busy = true;
                }
            },
        );
        assert!(saw_busy, "Argon2id busy overlay hook must fire before heavy KDF");
        assert!(alice_app.take_drain_events_flag());
        let pubenc_path = match &alice_app.modal {
            ModalState::OperationSummary {
                kind: SummaryKind::EncryptExistingSigned,
                output_path,
                companion_instr: CompanionInstrStatus::Skipped,
                ..
            } => output_path.clone(),
            other => panic!(
                "expected EncryptExistingSigned OperationSummary with Skipped instructions, got {:?}",
                other
            ),
        };
        alice_app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(alice_app.modal, ModalState::None);
        assert!(pubenc_path.exists());
        assert_eq!(pubenc_path.parent(), Some(dir.as_path()));
        assert_eq!(pubenc_path.extension().and_then(|s| s.to_str()), Some("pubenc"));
        assert!(
            !pubenc_path.file_name().unwrap().to_string_lossy().contains("for_bob.txt"),
            "default TUI output must not leak original filename: {:?}",
            pubenc_path
        );
        assert!(!dir
            .join(format!("{}.decrypt.txt", pubenc_path.file_name().unwrap().to_string_lossy()))
            .exists());

        // Import Alice's public bundle into Bob's keystore and inspect in Bob's TUI
        let alice_bundle = dir.join("alice_bundle.asc");
        export_public_key_bundle(
            &alice_ks,
            &alice_keys.fingerprint,
            pw,
            Some(&alice_bundle),
            false,
        )
        .unwrap();
        import_public_key_bundle(&bob_ks, &alice_bundle, Some("alice"), false).unwrap();

        let mut bob_app = TuiApp::new(bob_ks.clone());
        assert_eq!(bob_app.own_decrypt_keys().len(), 1);
        assert_eq!(bob_app.own_decrypt_keys()[0].fingerprint, bob_keys.fingerprint);

        bob_app.dec_last_verified_fp = Some("STALE_FP".into());
        bob_app.dec_input_path = pubenc_path.to_string_lossy().to_string();
        bob_app.update_decrypt_inspection();
        // Stale verified badge cleared immediately AND Expected Signer NOT auto-changed from header!
        assert!(bob_app.dec_last_verified_fp.is_none());
        assert_eq!(bob_app.dec_signer_choice, 0);
        assert_eq!(bob_app.effective_expected_signer_fp(), Some(bob_keys.fingerprint.clone()));

        // Passing SGPGv1 private key backup to Decrypt tab gives immediate zero-password guidance
        bob_app.dec_input_path = bob_keys.enc_path.to_string_lossy().to_string();
        bob_app.trigger_decrypt_action();
        assert_eq!(bob_app.modal, ModalState::None);
        assert!(bob_app.status_msg.contains("type=ed25519"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_browser_navigation_selection_and_tab_completion() {
        let dir = std::env::temp_dir().join(format!("yacrypt_tui_fb_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("alpha_doc.txt"), b"hello").unwrap();
        std::fs::write(dir.join(".hidden_secret"), b"hidden").unwrap();

        // 1. Test Tab path prefix completion
        let prefix = dir.join("alp").to_string_lossy().to_string();
        let (completed, count) = TuiApp::complete_path_prefix(&prefix).unwrap();
        assert_eq!(count, 1);
        assert!(completed.ends_with("alpha_doc.txt"));

        // 2. Test FileBrowser directory loading, hidden toggle, and file selection
        let mut app = TuiApp::new(dir.join("keystore"));
        app.switch_tab(ActiveTab::Encrypt);
        app.open_file_browser_in_dir(FileBrowserTarget::EncryptInput, dir.clone(), false);

        if let ModalState::FileBrowser { ref entries, .. } = app.modal {
            assert!(entries.iter().any(|e| e.name == "alpha_doc.txt"));
            assert!(!entries.iter().any(|e| e.name == ".hidden_secret"));
        } else {
            panic!("expected FileBrowser modal");
        }

        // Toggle hidden files with '.'
        app.handle_key_event(KeyEvent::new(KeyCode::Char('.'), KeyModifiers::NONE));
        if let ModalState::FileBrowser { ref entries, show_hidden, .. } = app.modal {
            assert!(show_hidden);
            assert!(entries.iter().any(|e| e.name == ".hidden_secret"));
        } else {
            panic!("expected FileBrowser modal");
        }

        // Move selection to alpha_doc.txt and press Enter
        if let ModalState::FileBrowser { ref entries, .. } = app.modal.clone() {
            let target_idx = entries.iter().position(|e| e.name == "alpha_doc.txt").unwrap();
            for _ in 0..target_idx {
                app.handle_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
            }
        }
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);
        assert!(app.enc_input_path.ends_with("alpha_doc.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refresh_keyring_preserves_selections_and_symmetric_rejects_explicit_signer_and_short_utf8() {
        let dir = std::env::temp_dir().join(format!("yacrypt_tui_preserve_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ks_dir = dir.join("keystore");
        std::fs::create_dir_all(&ks_dir).unwrap();
        // Create recipient entry sorting late ("FF...") first
        let late_fp = "FF".repeat(32);
        std::fs::write(ks_dir.join(format!("public_{}.asc", late_fp)), "AAAA").unwrap();
        std::fs::write(ks_dir.join(format!("x25519_public_{}.asc", late_fp)), "BBBB").unwrap();

        let mut app = TuiApp::new(ks_dir.clone());
        assert_eq!(app.keyring.len(), 1);
        app.selected_key_idx = 0;
        app.enc_key_choice = 2; // Keyring recipient late_fp
        app.dec_signer_choice = 1; // Explicit Expected Signer = late_fp

        // Insert an earlier-sorting fingerprint ("00...") into keystore and refresh
        let early_fp = "00".repeat(32);
        std::fs::write(ks_dir.join(format!("public_{}.asc", early_fp)), "CCCC").unwrap();
        std::fs::write(ks_dir.join(format!("x25519_public_{}.asc", early_fp)), "DDDD").unwrap();
        app.refresh_keyring();

        assert_eq!(app.keyring.len(), 2);
        assert_eq!(app.keyring[app.selected_key_idx].fingerprint, late_fp);
        assert_eq!(app.recipient_keyring_entries()[app.enc_key_choice - 2].fingerprint, late_fp);
        assert_eq!(app.keyring[app.dec_signer_choice - 1].fingerprint, late_fp);

        // External .asc recipient mode also stays on External after another key is added
        app.enc_key_choice = app.external_recipient_choice_idx();
        let mid_fp = "88".repeat(32);
        std::fs::write(ks_dir.join(format!("x25519_public_{}.asc", mid_fp)), "EEEE").unwrap();
        app.refresh_keyring();
        assert_eq!(app.enc_key_choice, app.external_recipient_choice_idx());

        // SUPER modifier (Cmd+V) must NOT append 'v'; CONTROL|SHIFT backspace/clear must work
        app.modal = ModalState::SymmetricPassword { focus_field: 0 };
        app.handle_key_event(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::SUPER));
        assert_eq!(app.password_buf.as_str(), "ab");
        app.handle_key_event(KeyEvent::new(
            KeyCode::Char('H'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ));
        assert_eq!(app.password_buf.as_str(), "a");
        app.handle_key_event(KeyEvent::new(
            KeyCode::Char('U'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ));
        assert!(app.password_buf.is_empty());

        // 3-char multi-byte UTF-8 password ("🔑🔑🔑", 12 bytes) MUST be rejected as < 12 chars
        app.password_buf = Zeroizing::new("🔑🔑🔑".into());
        app.confirm_buf = Zeroizing::new("🔑🔑🔑".into());
        assert!(app.validate_confirmed_buffers().is_err());
        app.clear_secret_buffers();
        app.modal = ModalState::None;

        // Symmetric .enc file in [3] Decrypt MUST refuse when an explicit Expected Signer is set
        let plain = dir.join("note.txt");
        std::fs::write(&plain, b"sym data").unwrap();
        let sym_enc = encrypt_file_symmetric(&plain, "valid-sym-pass-123", None, false).unwrap();
        app.dec_input_path = sym_enc.to_string_lossy().to_string();
        app.dec_output_path = dir.join("note_out.txt").to_string_lossy().to_string();
        app.dec_signer_choice = 1; // Explicit Expected Signer active!
        app.trigger_decrypt_action();
        assert_eq!(app.modal, ModalState::None);
        assert_eq!(app.status_kind, StatusKind::Error);
        assert!(app.status_msg.contains("no Ed25519 signature"));

        // Resetting Expected Signer to default (0) allows opening symmetric PasswordPrompt
        app.dec_signer_choice = 0;
        app.trigger_decrypt_action();
        assert!(matches!(
            app.modal,
            ModalState::PasswordPrompt { action: PasswordAction::DecryptSymmetricFile, .. }
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn operation_summary_and_help_guide_across_encrypt_decrypt_flows() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_tui_summary_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ks_dir = dir.join("keystore");
        let pw = "strong-test-pass-123";
        let keys =
            yacrypt_core::keystore::generate_and_store_keys_in_dir(&ks_dir, Some(pw)).unwrap();

        let src = dir.join("memo.txt");
        std::fs::write(&src, b"confidential summary flow").unwrap();

        let mut app = TuiApp::new(ks_dir.clone());
        assert_eq!(app.lang, UiLang::En);

        // 1. Unsigned existing-key encrypt -> OperationSummary(EncryptExistingUnsigned) -> ? opens HelpGuide
        app.switch_tab(ActiveTab::Encrypt);
        app.enc_input_path = src.to_string_lossy().to_string();
        let unsigned_out = dir.join("memo_unsigned.pubenc");
        app.enc_output_path = unsigned_out.to_string_lossy().to_string();
        app.enc_key_choice = 2; // first own keyring entry
        app.enc_sign_file = false;
        app.trigger_encrypt_action();
        assert!(matches!(
            app.modal,
            ModalState::OperationSummary { kind: SummaryKind::EncryptExistingUnsigned, .. }
        ));

        app.handle_key_event(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::HelpGuide { scroll: 0 });
        app.handle_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::HelpGuide { scroll: 1 });
        app.handle_key_event(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::HelpGuide { scroll: 9 });
        app.handle_key_event(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::HelpGuide { scroll: 8 });
        app.handle_key_event(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::HelpGuide { scroll: 0 });
        app.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);

        // 2. Symmetric encrypt -> OperationSummary(EncryptSymmetric)
        let sym_out = dir.join("memo_sym.enc");
        app.enc_output_path = sym_out.to_string_lossy().to_string();
        app.enc_key_choice = 1; // Symmetric SGPGv1
        app.trigger_encrypt_action();
        assert!(matches!(app.modal, ModalState::SymmetricPassword { .. }));
        app.password_buf = Zeroizing::new("sym-pass-phrase-999".into());
        app.confirm_buf = Zeroizing::new("sym-pass-phrase-999".into());
        app.handle_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            app.modal,
            ModalState::OperationSummary {
                kind: SummaryKind::EncryptSymmetric,
                companion_instr: CompanionInstrStatus::None,
                ..
            }
        ));
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);

        // 3. Symmetric decrypt -> OperationSummary(DecryptSymmetric)
        app.switch_tab(ActiveTab::Decrypt);
        app.dec_input_path = sym_out.to_string_lossy().to_string();
        let sym_dec_out = dir.join("memo_sym_dec.txt");
        app.dec_output_path = sym_dec_out.to_string_lossy().to_string();
        app.update_decrypt_inspection();
        app.trigger_decrypt_action();
        assert!(matches!(
            app.modal,
            ModalState::PasswordPrompt { action: PasswordAction::DecryptSymmetricFile, .. }
        ));
        app.password_buf = Zeroizing::new("sym-pass-phrase-999".into());
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            app.modal,
            ModalState::OperationSummary { kind: SummaryKind::DecryptSymmetric, .. }
        ));
        assert_eq!(std::fs::read(&sym_dec_out).unwrap(), b"confidential summary flow");
        app.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);

        // 4. Fresh-keypair encrypt (manual password, default skipped .decrypt.txt) -> OperationSummary(EncryptNewKeypair), then DecryptPubenc
        app.switch_tab(ActiveTab::Encrypt);
        app.enc_key_choice = 0; // Fresh keypair
        let manual_pubenc = dir.join("memo_newmanual.pubenc");
        app.enc_output_path = manual_pubenc.to_string_lossy().to_string();
        app.trigger_encrypt_action();
        assert!(matches!(
            app.modal,
            ModalState::NewKeypair { for_encrypt: true, auto_generate: true, focus_field: 0 }
        ));
        app.modal =
            ModalState::NewKeypair { for_encrypt: true, auto_generate: false, focus_field: 3 };
        app.password_buf = Zeroizing::new("manual-keypair-pw-123".into());
        app.confirm_buf = Zeroizing::new("manual-keypair-pw-123".into());
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let fresh_fp = match &app.modal {
            ModalState::OperationSummary {
                kind: SummaryKind::EncryptNewKeypair,
                key_fingerprint: Some(fp),
                companion_instr: CompanionInstrStatus::Skipped,
                ..
            } => fp.clone(),
            other => panic!("expected EncryptNewKeypair OperationSummary, got {:?}", other),
        };
        assert_ne!(fresh_fp, keys.fingerprint);
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);

        // Decrypt that newly generated signed .pubenc -> OperationSummary(DecryptPubenc) with verified_signer_fp
        app.switch_tab(ActiveTab::Decrypt);
        app.dec_input_path = manual_pubenc.to_string_lossy().to_string();
        let pub_dec_out = dir.join("memo_newmanual_dec.txt");
        app.dec_output_path = pub_dec_out.to_string_lossy().to_string();
        app.update_decrypt_inspection();
        assert!(matches!(
            app.dec_inspected,
            Some(Ok(InspectedFile::Pubenc(ref p)))
                if p.format_version == 2
                    && p.has_signature.is_none()
                    && p.signer_fingerprint.is_none()
                    && p.padding_enabled
        ));
        let fresh_dec_idx = app
            .own_decrypt_keys()
            .iter()
            .position(|k| k.fingerprint == fresh_fp)
            .expect("newly created key should be selectable for decryption");
        app.dec_key_idx = fresh_dec_idx;
        app.trigger_decrypt_action();
        assert!(matches!(
            app.modal,
            ModalState::PasswordPrompt { action: PasswordAction::DecryptFile, .. }
        ));
        app.password_buf = Zeroizing::new("manual-keypair-pw-123".into());
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            app.modal,
            ModalState::OperationSummary {
                kind: SummaryKind::DecryptPubenc,
                verified_signer_fp: Some(ref sfp),
                ..
            } if sfp == &fresh_fp
        ));
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);

        // Unsigned SCFv2 with dec_require_sig = true proceeds past header inspect (concealed sig),
        // then rejects after AEAD decryption and writes ZERO bytes to disk
        let unsigned_scfv2 = dir.join("memo_unsigned_v2.pubenc");
        let unsigned_dec_out = dir.join("memo_unsigned_dec_should_not_exist.txt");
        yacrypt_core::file_ops::encrypt_file_with_key_in_dir(
            &src,
            &keys.x25519_pub_path,
            Some(&unsigned_scfv2),
            None,
            false,
            Some(&ks_dir),
        )
        .unwrap();
        app.dec_input_path = unsigned_scfv2.to_string_lossy().to_string();
        app.dec_output_path = unsigned_dec_out.to_string_lossy().to_string();
        app.dec_require_sig = true;
        app.update_decrypt_inspection();
        app.dec_key_idx =
            app.own_decrypt_keys().iter().position(|k| k.fingerprint == keys.fingerprint).unwrap();
        app.trigger_decrypt_action();
        assert!(matches!(
            app.modal,
            ModalState::PasswordPrompt { action: PasswordAction::DecryptFile, .. }
        ));
        app.password_buf = Zeroizing::new(pw.into());
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.status_kind, StatusKind::Error);
        assert!(app.status_msg.contains("no embedded signature"));
        assert!(!unsigned_dec_out.exists());

        // 5. Fresh-keypair encrypt (auto_generate: true) chains GeneratedPasswordDisplay -> OperationSummary on close while zeroizing secrets
        app.switch_tab(ActiveTab::Encrypt);
        app.enc_key_choice = 0;
        let auto_pubenc = dir.join("memo_auto.pubenc");
        app.enc_output_path = auto_pubenc.to_string_lossy().to_string();
        app.trigger_encrypt_action();
        app.modal =
            ModalState::NewKeypair { for_encrypt: true, auto_generate: true, focus_field: 3 };
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(app.modal, ModalState::GeneratedPasswordDisplay { .. }));
        assert_eq!(app.backup_modal_encrypted_file.as_ref(), Some(&auto_pubenc));
        assert!(app.one_time_backup_pass.is_some());
        assert!(app.pending_post_backup_summary.is_some());
        app.handle_key_event(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.backup_modal_encrypted_file.is_none());
        assert!(app.one_time_backup_pass.is_none());
        assert!(app.pending_post_backup_summary.is_none());
        assert!(matches!(
            app.modal,
            ModalState::OperationSummary {
                kind: SummaryKind::EncryptNewKeypair,
                output_path: ref p,
                ..
            } if p == &auto_pubenc
        ));
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyring_enter_selects_existing_key_or_opens_new_keypair_when_empty() {
        let dir = std::env::temp_dir()
            .join(format!("yacrypt_tui_keyring_enter_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ks_dir = dir.join("keystore");

        // 1. Empty keystore: defaults to Generate Fresh Keypair (0), and Keyring Enter opens NewKeypair
        let mut empty_app = TuiApp::new(ks_dir.clone());
        assert_eq!(empty_app.enc_key_choice, 0);
        empty_app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(empty_app.modal, ModalState::NewKeypair { for_encrypt: false, .. }));

        // 2. Non-empty keystore with existing own keypairs: defaults enc_key_choice to first own key (>= 2)
        let k1 =
            yacrypt_core::keystore::generate_and_store_keys_in_dir(&ks_dir, Some("test-pw-111111"))
                .unwrap();
        let k2 =
            yacrypt_core::keystore::generate_and_store_keys_in_dir(&ks_dir, Some("test-pw-222222"))
                .unwrap();
        let mut app = TuiApp::new(ks_dir.clone());
        assert!(app.enc_key_choice >= 2);
        let first_own_fp = app
            .keyring
            .iter()
            .find(|k| k.x25519_enc_path.is_some() && k.x25519_pub_path.is_some())
            .unwrap()
            .fingerprint
            .clone();
        assert_eq!(
            app.recipient_keyring_entries()[app.enc_key_choice - 2].fingerprint,
            first_own_fp
        );

        // 3. Move selection in Keyring to the other own keypair and press Enter: selects it for [2] Encrypt
        let second_pos = app.keyring.iter().position(|k| k.fingerprint != first_own_fp).unwrap();
        let second_fp = app.keyring[second_pos].fingerprint.clone();
        assert!(second_fp == k1.fingerprint || second_fp == k2.fingerprint);
        app.selected_key_idx = second_pos;
        app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);
        assert_eq!(app.active_tab, ActiveTab::Encrypt);
        assert_eq!(app.recipient_keyring_entries()[app.enc_key_choice - 2].fingerprint, second_fp);
        assert_eq!(app.own_signing_keys()[app.enc_sign_key_idx].fingerprint, second_fp);

        // 4. Pressing 'n' on non-empty Keyring still explicitly opens NewKeypair
        app.switch_tab(ActiveTab::Keyring);
        app.handle_key_event(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert!(matches!(app.modal, ModalState::NewKeypair { for_encrypt: false, .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_language_toggle_and_keyring_label_disambiguation() {
        let dir =
            std::env::temp_dir().join(format!("yacrypt_tui_lang_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ks_dir = dir.join("keystore");
        let _ =
            yacrypt_core::keystore::generate_and_store_keys_in_dir(&ks_dir, Some("test-pw-123456"))
                .unwrap();

        let mut app = TuiApp::new(ks_dir.clone());
        assert_eq!(app.lang, UiLang::En);

        // Lowercase 'l' on Keyring MUST open SetKeyLabel modal without changing language
        app.handle_key_event(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        assert!(matches!(app.modal, ModalState::SetKeyLabel { .. }));
        assert_eq!(app.lang, UiLang::En);
        app.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.modal, ModalState::None);

        // Shift+L toggles En -> Zh and persists 0600 <keystore_dir>/ui_lang
        app.handle_key_event(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::SHIFT));
        assert_eq!(app.lang, UiLang::Zh);
        let ui_lang_path = ks_dir.join("ui_lang");
        assert!(ui_lang_path.exists());
        assert_eq!(std::fs::read_to_string(&ui_lang_path).unwrap().trim(), "zh");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&ui_lang_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Reconstructing app via detect_initial restores Zh
        let restored_lang = UiLang::detect_initial(&ks_dir);
        assert_eq!(restored_lang, UiLang::Zh);
        let mut app2 = TuiApp::new_with_lang(ks_dir.clone(), restored_lang);
        assert_eq!(app2.lang, UiLang::Zh);

        // F2 toggles inside OperationSummary and Shift+L toggles inside HelpGuide
        app2.modal = ModalState::OperationSummary {
            kind: SummaryKind::EncryptSymmetric,
            output_path: dir.join("out.enc"),
            key_fingerprint: None,
            verified_signer_fp: None,
            companion_instr: CompanionInstrStatus::None,
        };
        app2.handle_key_event(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert_eq!(app2.lang, UiLang::En);
        app2.handle_key_event(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
        assert!(matches!(app2.modal, ModalState::HelpGuide { .. }));
        app2.handle_key_event(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::SHIFT));
        assert_eq!(app2.lang, UiLang::Zh);
        assert!(matches!(app2.modal, ModalState::HelpGuide { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
