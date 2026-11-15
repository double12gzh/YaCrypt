/// CLI 结构定义与终端交互适配模块
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use dialoguer::{Confirm, Password, Select};
use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};
use yacrypt_core::{
    constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH},
    file_ops::{
        decrypt_file_symmetric, encrypt_file_symmetric, encrypt_file_with_key_in_dir,
        preflight_validate_recipient_pubkey,
    },
    keystore::{
        change_keypair_password, decrypt_backup_with_password, default_bundle_output_path,
        export_public_key_bundle, find_keyring_entry, generate_and_store_keys_with_label,
        import_public_key_bundle, load_signing_key_with_password, resolve_decrypt_key_arg,
        resolve_recipient_key_arg, resolve_signing_key_arg, scan_keystore, set_key_label,
        validate_key_label, GeneratedKeys, KeyringEntry,
    },
    password::generate_strong_password,
    utils::{
        default_decrypt_output_path, default_der_output_path, default_pubenc_output_path,
        default_symmetric_output_path, preflight_check_input_file, preflight_check_output_path,
    },
    workflow::{
        decrypt_workflow_with_password_in_dir, encrypt_workflow_with_existing_key_in_dir,
        encrypt_workflow_with_new_keys_opts, inspect_file, resolve_signer_fingerprint_in_dir,
        InspectedFile,
    },
};
use zeroize::Zeroizing;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    #[value(name = "powershell", alias = "pwsh")]
    PowerShell,
}

#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    /// Custom keystore directory (overrides YACRYPT_KEYSTORE, ./keystore, and ~/.yacrypt/keystore)
    #[arg(long, global = true, value_name = "DIR")]
    pub keystore_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Launch interactive 4-in-1 TUI workbench (default when run on a TTY with no subcommand)
    Tui,
    /// Inspect an encrypted file (.pubenc, .enc, or .asc.enc) without a password
    Inspect {
        /// Path to the encrypted file or key backup to inspect
        file: PathBuf,
    },
    /// List all Ed25519 + X25519 keypairs stored in the local keystore directory
    #[command(visible_alias = "keys")]
    KeyList,
    /// Generate a new Ed25519 and X25519 keypair with encrypted private key backup
    GenKeypair {
        /// Optional local petname/alias stored only in local 0600 keystore index (never in ciphertexts)
        #[arg(long)]
        label: Option<String>,
    },
    /// Set or clear a local 0600 petname/alias for a keypair in the keystore
    KeyLabel {
        /// Key selector: existing label, >=16-char hex fingerprint prefix, or key file path
        key: String,
        /// New local label to assign (omit with --clear to remove label)
        label: Option<String>,
        /// Remove the local label from this keypair
        #[arg(long)]
        clear: bool,
    },
    /// Export a self-signed Ed25519 + X25519 public key bundle (.asc) for sharing
    #[command(visible_alias = "export-key")]
    KeyExport {
        /// Key selector: local label, >=16-char fingerprint prefix, or key file path (interactive on TTY if omitted)
        key: Option<String>,
        /// Output bundle file path (default: yacrypt_pubkey_<FP16>.asc)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Verify self-signature and import a peer's Ed25519 + X25519 public key bundle into keystore
    #[command(visible_alias = "import-key")]
    KeyImport {
        /// Path to the peer's exported public key bundle (.asc)
        bundle: PathBuf,
        /// Optional local petname/alias to assign in local 0600 keystore index
        #[arg(long)]
        label: Option<String>,
        /// Overwrite existing public key files if already imported
        #[arg(short, long)]
        force: bool,
    },
    /// Rotate the backup encryption password for both Ed25519 and X25519 private keys
    ChangeKeyPassword {
        /// Key selector: local label, >=16-char fingerprint prefix, or key file path (interactive on TTY if omitted)
        key: Option<String>,
    },
    /// Generate a strong password (print to stdout)
    GenPassword {
        /// Number of characters in the output password (default: 32)
        #[arg(short, long, default_value_t = 32)]
        length: usize,
    },
    /// Decrypt an encrypted Ed25519 private key backup file to produce plaintext private key (PKCS#8 DER format)
    DecryptPrivateKey {
        /// Encrypted Ed25519 backup path, local label, or >=16-char fingerprint prefix (interactive on TTY if omitted)
        enc_path: Option<String>,
        /// Output DER file path (default: <stem>.der, stripping .asc.enc)
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Encrypt a file using an existing X25519 public key (hybrid encryption: X25519 + XChaCha20-Poly1305)
    EncryptFileWithKey {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        /// Recipient X25519 public key: .asc path, local label, or >=16-char fingerprint prefix (interactive on TTY if omitted)
        #[arg(short, long, num_args = 0..=1, default_missing_value = "")]
        public_key: Option<String>,
        /// Output encrypted file (default: anonymous <random>.pubenc in input directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Optional Ed25519 signing private key: .asc.enc path, local label, or >=16-char fingerprint prefix (interactive on TTY if flag value omitted)
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        sign_key: Option<String>,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Encrypt file: generate keypair (or reuse existing via --key, or use password-only via --symmetric)
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,
        /// Output encrypted file (default: anonymous <random>.pubenc, or <random>.enc with --symmetric)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Reuse existing recipient X25519 public key (.asc path, local label, or >=16-char fingerprint prefix; interactive on TTY if flag value omitted)
        #[arg(short, long, num_args = 0..=1, default_missing_value = "")]
        key: Option<String>,
        /// Optional Ed25519 signing private key (.asc.enc path, local label, or >=16-char fingerprint prefix; interactive on TTY if flag value omitted) when using --key
        #[arg(long, requires = "key", num_args = 0..=1, default_missing_value = "")]
        sign_key: Option<String>,
        /// Optional local petname/alias for newly generated keypair (stored only in local 0600 keystore index)
        #[arg(long, conflicts_with_all = ["key", "symmetric"])]
        label: Option<String>,
        /// Encrypt directly with a password (Argon2id + XChaCha20-Poly1305, SGPGv2 padded format) without public/private keys
        #[arg(short = 'c', long, conflicts_with_all = ["key", "sign_key"])]
        symmetric: bool,
        /// Write the companion <output>.decrypt.txt instructions file (disabled by default for privacy)
        #[arg(long)]
        instructions: bool,
        /// Skip writing the companion <output>.decrypt.txt instructions file (default behavior; kept for compatibility)
        #[arg(long, conflicts_with = "instructions")]
        no_instructions: bool,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Decrypt file: supports both .pubenc (hybrid public-key) and .enc (symmetric password-encrypted) files
    Decrypt {
        /// Input encrypted file to decrypt (.pubenc or .enc)
        input: PathBuf,
        /// Encrypted X25519 private key (.asc.enc path, local label, or >=16-char fingerprint prefix; interactive on TTY if omitted)
        #[arg(short, long, num_args = 0..=1, default_missing_value = "")]
        private_key: Option<String>,
        /// Output decrypted file (default: input without .pubenc / .enc extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Expected signer Ed25519 full 64-char hex fingerprint, local label, or public_<FP>.asc path
        #[arg(short, long)]
        signer: Option<String>,
        /// Explicitly require a valid Ed25519 signature (default for .pubenc; rejects unsigned .enc files)
        #[arg(long)]
        require_signature: bool,
        /// Allow decrypting an unsigned .pubenc file (not recommended)
        #[arg(long, conflicts_with = "require_signature")]
        allow_unsigned: bool,
        /// Force symmetric password decryption mode (auto-detected for SGPGv1/SGPGv2 type=file .enc files)
        #[arg(short = 'c', long)]
        symmetric: bool,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Generate shell auto-completion script to stdout (bash, zsh, fish, powershell)
    Completions {
        /// Target shell
        shell: CompletionShell,
    },
}

fn is_interactive_tty() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

fn select_keyring_entry_interactively<F>(
    keystore_dir: &Path,
    prompt: &str,
    empty_err: &str,
    predicate: F,
) -> Result<KeyringEntry, Box<dyn std::error::Error>>
where
    F: Fn(&KeyringEntry) -> bool,
{
    let candidates: Vec<KeyringEntry> =
        scan_keystore(keystore_dir)?.into_iter().filter(predicate).collect();
    if candidates.is_empty() {
        return Err(empty_err.into());
    }
    let items: Vec<String> = candidates.iter().map(|e| e.display_name()).collect();
    let idx = Select::new().with_prompt(prompt).items(&items).default(0).interact()?;
    Ok(candidates.into_iter().nth(idx).unwrap())
}

fn preflight_validate_new_label(
    keystore_dir: &Path,
    label: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(raw) = label.map(str::trim).filter(|s| !s.is_empty()) {
        let clean = validate_key_label(raw)?;
        let active_entries = scan_keystore(keystore_dir)?;
        if let Some(other) = active_entries.iter().find(|entry| {
            entry.label.as_deref().map(|lbl| lbl.eq_ignore_ascii_case(&clean)).unwrap_or(false)
        }) {
            return Err(format!(
                "Label '{}' is already assigned to key {}",
                clean, other.fingerprint
            )
            .into());
        }
    }
    Ok(())
}

/// 提示用户输入并确认密码，验证长度（字符数 >= 12，字节数 <= 1024）
pub fn prompt_password_confirm(prompt: &str) -> Option<Zeroizing<String>> {
    loop {
        let p = Zeroizing::new(
            Password::new()
                .with_prompt(prompt)
                .with_confirmation("Confirm password", "Passwords mismatched")
                .interact()
                .ok()?,
        );

        if p.chars().count() < MIN_PASSWORD_LENGTH {
            eprintln!("Password too short; must be >= {} chars", MIN_PASSWORD_LENGTH);
            continue;
        }
        if p.len() > MAX_PASSWORD_LENGTH {
            eprintln!("Password too long; must be <= {} bytes", MAX_PASSWORD_LENGTH);
            continue;
        }
        return Some(p);
    }
}

/// 交互式询问是否自动生成备份口令（默认高熵自动生成），否则读取用户确认口令
fn prompt_backup_password_choice() -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>>
{
    let auto_backup_pass = Confirm::new()
        .with_prompt("Auto-generate backup encryption password?")
        .default(true)
        .interact()?;

    if auto_backup_pass {
        Ok(None)
    } else {
        match prompt_password_confirm("Enter backup encryption password") {
            Some(x) => Ok(Some(x)),
            None => Err("Failed to read backup password".into()),
        }
    }
}

/// 打印自动生成口令（若启用）与本地别名提示
fn print_generated_keys_notice(keys: &GeneratedKeys, label: Option<&str>) {
    if let Some(ref backup_pass) = keys.auto_generated_password {
        println!("✅ Backup password generated:");
        println!("   {}", backup_pass.as_str());
        println!("   ⚠️  IMPORTANT: Save this password securely! You will need it to decrypt your private key backup.");
    }
    if let Some(lbl) = label.map(str::trim).filter(|s| !s.is_empty()) {
        println!("🏷️  Local key label: [{}] (stored only in local 0600 keystore index)", lbl);
    }
}

pub fn cmd_inspect_file(
    path: &Path,
    keystore_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = inspect_file(path)?;
    let keyring = scan_keystore(keystore_dir).unwrap_or_default();

    println!("🔍 File Inspection: {}", path.display());
    println!("========================================");
    match info {
        InspectedFile::Pubenc(p) => {
            println!(
                "Format:             SCFv{} (Hybrid Public-Key Encrypted File)",
                p.format_version
            );
            println!("Algorithm Suite:    X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305");
            println!(
                "Length Padding:     {}",
                if p.padding_enabled {
                    "Enabled (Length-Hiding Random + Padme)"
                } else {
                    "None (Legacy SCFv1)"
                }
            );
            println!("Ephemeral X25519:   {}", p.ephemeral_pub_hex);
            println!("Ciphertext Size:    {} bytes", p.ciphertext_len);
            match p.has_signature {
                None => {
                    println!(
                        "Embedded Signature: 🔒 Concealed inside AEAD payload (verified upon decryption)"
                    );
                }
                Some(true) => {
                    if let Some(fp) = p.signer_fingerprint {
                        println!("Embedded Signature: ✅ Present (Ed25519)");
                        println!("Signer Fingerprint: {}", fp);
                        if let Some(matched) =
                            keyring.iter().find(|k| k.fingerprint.eq_ignore_ascii_case(&fp))
                        {
                            match matched.label {
                                Some(ref lbl) => println!(
                                    "Local Keyring:      ✅ Matching key found [{}] in {}",
                                    lbl,
                                    keystore_dir.display()
                                ),
                                None => println!(
                                    "Local Keyring:      ✅ Matching keypair found in {}",
                                    keystore_dir.display()
                                ),
                            }
                        } else {
                            println!(
                                "Local Keyring:      ℹ️  No matching keypair in {}",
                                keystore_dir.display()
                            );
                        }
                    }
                }
                Some(false) => {
                    println!("Embedded Signature: ⚠️  None (Unsigned)");
                }
            }
        }
        InspectedFile::Sgpg(s) => {
            let kind_desc = match s.blob_type.as_deref() {
                Some("file") => "Symmetric Password-Encrypted File (type=file)",
                Some("ed25519") => "Encrypted Ed25519 Signing Private Key Backup (type=ed25519)",
                Some("x25519") => "Encrypted X25519 Decryption Private Key Backup (type=x25519)",
                Some(other) => other,
                None => "Unknown SGPG payload",
            };
            println!(
                "Format:             SGPGv{} (Password-Based Encrypted Container)",
                s.format_version
            );
            println!("Payload Type:       {}", kind_desc);
            println!("Algorithm Suite:    Argon2id + XChaCha20-Poly1305");
            println!(
                "Length Padding:     {}",
                if s.padding_enabled {
                    "Enabled (Length-Hiding Random + Padme)"
                } else {
                    "None (Legacy SGPGv1)"
                }
            );
            println!(
                "Argon2id Params:    m_cost={} KiB ({} MiB), t_cost={}, p_cost={}",
                s.mem_kib,
                s.mem_kib / 1024,
                s.t_cost,
                s.p_cost
            );
            println!("Ciphertext Size:    {} bytes", s.ciphertext_len);
            if let Some(fp) = s.fingerprint {
                println!("Bound Fingerprint:  {}", fp);
                if let Some(matched) =
                    keyring.iter().find(|k| k.fingerprint.eq_ignore_ascii_case(&fp))
                {
                    match matched.label {
                        Some(ref lbl) => println!(
                            "Local Keyring:      ✅ Present [{}] in {}",
                            lbl,
                            keystore_dir.display()
                        ),
                        None => {
                            println!("Local Keyring:      ✅ Present in {}", keystore_dir.display())
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn cmd_key_list(keystore_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let entries = scan_keystore(keystore_dir)?;
    if entries.is_empty() {
        println!("📭 No keypairs found in {} directory.", keystore_dir.display());
        println!("   Run 'yacrypt gen-keypair --label <alias>' to generate one.");
        return Ok(());
    }

    println!(
        "🔑 Local Keystore ({} keypair(s) found in {}):",
        entries.len(),
        keystore_dir.display()
    );
    println!("========================================");
    for (idx, entry) in entries.iter().enumerate() {
        match entry.label {
            Some(ref lbl) => {
                println!("[{}] Label: [{}]  Fingerprint: {}", idx + 1, lbl, entry.fingerprint)
            }
            None => println!("[{}] Fingerprint: {}", idx + 1, entry.fingerprint),
        }
        let mark = |opt: &Option<PathBuf>| if opt.is_some() { "✅" } else { "❌" };
        println!(
            "    Ed25519 (Sign/Verify): pub={} priv={}",
            mark(&entry.ed25519_pub_path),
            mark(&entry.ed25519_enc_path)
        );
        println!(
            "    X25519  (ECDH Crypt):  pub={} priv={}",
            mark(&entry.x25519_pub_path),
            mark(&entry.x25519_enc_path)
        );
        if let Some(ref x_enc) = entry.x25519_enc_path {
            println!("    Decrypt Private Key:   {}", x_enc.display());
        }
    }
    Ok(())
}

pub fn cmd_key_label(
    keystore_dir: &Path,
    selector: &str,
    label: Option<&str>,
    clear: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = find_keyring_entry(keystore_dir, selector)?;
    if clear {
        set_key_label(keystore_dir, &entry.fingerprint, None)?;
        println!("✅ Cleared local label for key {}", entry.fingerprint);
        return Ok(());
    }
    let Some(lbl) = label.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err("Provide a <LABEL> to set, or pass --clear to remove an existing label".into());
    };
    set_key_label(keystore_dir, &entry.fingerprint, Some(lbl))?;
    println!("✅ Assigned local label [{}] to key {}", lbl, entry.fingerprint);
    Ok(())
}

pub fn cmd_key_export(
    keystore_dir: &Path,
    selector: Option<&str>,
    output: Option<&Path>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = match selector {
        Some(sel) => find_keyring_entry(keystore_dir, sel)?,
        None if is_interactive_tty() => select_keyring_entry_interactively(
            keystore_dir,
            "Select own keypair to export signed public key bundle",
            "No signable keypair (with Ed25519 private key) found in keystore",
            |e| {
                e.ed25519_pub_path.is_some()
                    && e.x25519_pub_path.is_some()
                    && e.ed25519_enc_path.is_some()
            },
        )?,
        None => {
            return Err(
                "Missing key selector <label|fingerprint>; specify one or run on an interactive TTY"
                    .into(),
            );
        }
    };

    if entry.ed25519_enc_path.is_none() {
        return Err(format!(
            "Cannot sign public key bundle for {}: Ed25519 private key backup is not in local keystore",
            entry.display_name()
        )
        .into());
    }

    let planned_out = match output {
        Some(p) => p.to_path_buf(),
        None => default_bundle_output_path(&entry.fingerprint),
    };
    preflight_check_output_path(None, &planned_out, force)?;

    let pass = Zeroizing::new(
        Password::new()
            .with_prompt(format!(
                "Enter Ed25519 signing key password to sign bundle ({})",
                entry.display_name()
            ))
            .interact()?,
    );

    let (fp, out_path) =
        export_public_key_bundle(keystore_dir, &entry.fingerprint, &pass, output, force)?;
    println!("✅ Signed Ed25519 + X25519 public key bundle exported: {}", out_path.display());
    println!("   Fingerprint: {}", fp);
    println!(
        "   Share this file with peers; they can run: yacrypt key-import {}",
        out_path.display()
    );
    Ok(())
}

pub fn cmd_key_import(
    keystore_dir: &Path,
    bundle: &Path,
    label: Option<&str>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let fp = import_public_key_bundle(keystore_dir, bundle, label, force)?;
    println!(
        "✅ Verified self-signature and imported peer public keys into {}",
        keystore_dir.display()
    );
    println!("   Fingerprint: {}", fp);
    if let Some(lbl) = label.map(str::trim).filter(|s| !s.is_empty()) {
        println!("   Local Label: [{}]", lbl);
    }
    Ok(())
}

pub fn cmd_change_key_password(
    keystore_dir: &Path,
    selector: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = match selector {
        Some(sel) => find_keyring_entry(keystore_dir, sel)?,
        None if is_interactive_tty() => select_keyring_entry_interactively(
            keystore_dir,
            "Select keypair to rotate backup encryption password",
            "No local keypair with encrypted private keys found in keystore",
            |e| e.ed25519_enc_path.is_some() && e.x25519_enc_path.is_some(),
        )?,
        None => {
            return Err(
                "Missing key selector <label|fingerprint>; specify one or run on an interactive TTY"
                    .into(),
            );
        }
    };

    if entry.ed25519_enc_path.is_none() || entry.x25519_enc_path.is_none() {
        return Err(format!(
            "Key {} does not have both encrypted private keys in {}",
            entry.display_name(),
            keystore_dir.display()
        )
        .into());
    }

    let old_pass = Zeroizing::new(
        Password::new()
            .with_prompt(format!("Enter current password for {}", entry.display_name()))
            .interact()?,
    );
    let new_pass = match prompt_password_confirm("Enter new backup password") {
        Some(p) => p,
        None => return Err("Failed to read new password".into()),
    };

    let fp = change_keypair_password(keystore_dir, &entry.fingerprint, &old_pass, &new_pass)?;
    println!("✅ Rotated backup password for Ed25519 + X25519 private keys ({})", fp);
    Ok(())
}

pub fn cmd_generate_strong_password(length: usize) -> Result<(), Box<dyn std::error::Error>> {
    let pw = generate_strong_password(length)?;
    println!("{}", pw.as_str());
    Ok(())
}

pub fn cmd_generate_protected_key(
    keystore_dir: &Path,
    label: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    preflight_validate_new_label(keystore_dir, label)?;
    let user_pass = prompt_backup_password_choice()?;
    let keys = generate_and_store_keys_with_label(
        keystore_dir,
        user_pass.as_deref().map(|s| s.as_str()),
        label,
    )?;
    print_generated_keys_notice(&keys, label);

    println!(
        "✅ Ed25519 keypair generated and encrypted backup written to: {}",
        keys.enc_path.display()
    );
    println!("✅ Ed25519 public key written to: {}", keys.pub_path.display());
    println!("✅ X25519 keypair generated for encryption");
    println!("✅ X25519 public key written to: {}", keys.x25519_pub_path.display());
    println!("✅ X25519 private key encrypted: {}", keys.x25519_enc_path.display());
    println!("Fingerprint: {}", keys.fingerprint);

    Ok(())
}

fn resolve_optional_signing_key(
    keystore_dir: &Path,
    sign_key: Option<&str>,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    match sign_key {
        None => Ok(None),
        Some(raw) if raw.trim().is_empty() => {
            if !is_interactive_tty() {
                return Err(
                    "Missing value for --sign-key <path|label|fingerprint>; specify one or run on an interactive TTY"
                        .into(),
                );
            }
            let entry = select_keyring_entry_interactively(
                keystore_dir,
                "Select own Ed25519 signing key",
                "No Ed25519 signing private keys found in keystore",
                |e| e.ed25519_enc_path.is_some(),
            )?;
            Ok(entry.ed25519_enc_path)
        }
        Some(sk_arg) => {
            let sk_path = resolve_signing_key_arg(keystore_dir, sk_arg)?;
            preflight_check_input_file(&sk_path, "Signing key file not found")?;
            Ok(Some(sk_path))
        }
    }
}

pub fn cmd_decrypt_backup(
    keystore_dir: &Path,
    enc_arg: Option<&str>,
    out: Option<&Path>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let enc_path = match enc_arg.filter(|s| !s.trim().is_empty()) {
        Some(arg) => {
            let direct = Path::new(arg);
            if direct.exists() {
                direct.to_path_buf()
            } else {
                resolve_signing_key_arg(keystore_dir, arg)?
            }
        }
        None if is_interactive_tty() => {
            let entry = select_keyring_entry_interactively(
                keystore_dir,
                "Select Ed25519 private key backup to export as PKCS#8 DER",
                "No Ed25519 private key backups found in keystore",
                |e| e.ed25519_enc_path.is_some(),
            )?;
            entry.ed25519_enc_path.unwrap()
        }
        None => {
            return Err(
                "Missing <enc_path|label|fingerprint>; specify one or run on an interactive TTY"
                    .into(),
            );
        }
    };

    preflight_check_input_file(&enc_path, "Encrypted file not found")?;
    match inspect_file(&enc_path)? {
        InspectedFile::Sgpg(s) => match s.blob_type.as_deref() {
            Some("ed25519") => {}
            Some(other) => {
                return Err(format!(
                    "Cannot export '{}' key as PKCS#8 DER — only Ed25519 signing keys are supported",
                    other
                )
                .into());
            }
            None => {
                return Err(
                    "Missing key 'type' in AAD — refusing to export unverified key blob".into()
                );
            }
        },
        InspectedFile::Pubenc(p) => {
            return Err(format!(
                "'{}' is a public-key encrypted data file (SCFv{} / .pubenc), not an Ed25519 private key backup; use 'yacrypt decrypt' instead",
                enc_path.display(),
                p.format_version
            )
            .into());
        }
    }

    let planned_out = match out {
        Some(p) => p.to_path_buf(),
        None => default_der_output_path(&enc_path),
    };
    preflight_check_output_path(Some(&enc_path), &planned_out, force)?;

    let pass = Zeroizing::new(Password::new().with_prompt("Enter backup password").interact()?);
    let out_path = decrypt_backup_with_password(&enc_path, &pass, out, force)?;

    println!("✅ Decrypted private key written to: {}", out_path.display());
    Ok(())
}

pub fn cmd_encrypt_file_with_key_cli(
    keystore_dir: &Path,
    input: &Path,
    public_key: Option<&str>,
    output: Option<&Path>,
    sign_key: Option<&str>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    preflight_check_input_file(input, "Input file not found")?;

    let pub_key_path = match public_key.filter(|s| !s.trim().is_empty()) {
        Some(arg) => resolve_recipient_key_arg(keystore_dir, arg)?,
        None if is_interactive_tty() => {
            let entry = select_keyring_entry_interactively(
                keystore_dir,
                "Select recipient X25519 public key",
                "No recipient X25519 public keys found in keystore",
                |e| e.x25519_pub_path.is_some(),
            )?;
            entry.x25519_pub_path.unwrap()
        }
        None => {
            return Err(
                "Missing --public-key <path|label|fingerprint>; specify one or run on an interactive TTY"
                    .into(),
            );
        }
    };

    preflight_validate_recipient_pubkey(&pub_key_path, Some(keystore_dir))?;

    let planned_out = match output {
        Some(p) => p.to_path_buf(),
        None => default_pubenc_output_path(input),
    };
    preflight_check_output_path(Some(input), &planned_out, force)?;

    let resolved_sign_key = resolve_optional_signing_key(keystore_dir, sign_key)?;

    let loaded_sk = match resolved_sign_key {
        Some(ref sk_path) => {
            let pass = Zeroizing::new(
                Password::new().with_prompt("Enter signing private key password").interact()?,
            );
            Some(load_signing_key_with_password(sk_path, &pass)?)
        }
        None => None,
    };

    let out_path = encrypt_file_with_key_in_dir(
        input,
        &pub_key_path,
        Some(planned_out.as_path()),
        loaded_sk.as_ref(),
        force,
        Some(keystore_dir),
    )?;
    println!("✅ File encrypted with public key: {}", out_path.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_encrypt_workflow(
    keystore_dir: &Path,
    input: &Path,
    output: Option<&Path>,
    existing_key: Option<&str>,
    sign_key: Option<&str>,
    label: Option<&str>,
    symmetric: bool,
    write_instructions: bool,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    preflight_check_input_file(input, "Input file not found")?;

    if symmetric {
        let planned_out = match output {
            Some(p) => p.to_path_buf(),
            None => default_symmetric_output_path(input),
        };
        preflight_check_output_path(Some(input), &planned_out, force)?;

        println!("🔐 Encrypting file in symmetric password mode (SGPGv2)...");
        let pass = match prompt_password_confirm("Enter encryption password") {
            Some(p) => p,
            None => return Err("Failed to read encryption password".into()),
        };
        let out_path = encrypt_file_symmetric(input, &pass, Some(planned_out.as_path()), force)?;
        println!("✅ File symmetrically encrypted: {}", out_path.display());
        println!("📋 To decrypt, run: yacrypt decrypt {}", out_path.display());
        return Ok(());
    }

    let planned_out = match output {
        Some(p) => p.to_path_buf(),
        None => default_pubenc_output_path(input),
    };
    preflight_check_output_path(Some(input), &planned_out, force)?;

    if let Some(key_arg) = existing_key {
        let key_path = if key_arg.trim().is_empty() {
            if !is_interactive_tty() {
                return Err(
                    "Missing value for --key <path|label|fingerprint>; specify one or run on an interactive TTY"
                        .into(),
                );
            }
            let entry = select_keyring_entry_interactively(
                keystore_dir,
                "Select recipient X25519 public key",
                "No recipient X25519 public keys found in keystore",
                |e| e.x25519_pub_path.is_some(),
            )?;
            entry.x25519_pub_path.unwrap()
        } else {
            resolve_recipient_key_arg(keystore_dir, key_arg)?
        };
        preflight_validate_recipient_pubkey(&key_path, Some(keystore_dir))?;

        let resolved_sk_path = resolve_optional_signing_key(keystore_dir, sign_key)?;

        let loaded_sk = match resolved_sk_path {
            Some(ref sk_path) => {
                let pass = Zeroizing::new(
                    Password::new().with_prompt("Enter signing private key password").interact()?,
                );
                Some(load_signing_key_with_password(sk_path, &pass)?)
            }
            None => None,
        };

        println!("🔐 Encrypting file with existing key: {}", key_path.display());
        let outcome = encrypt_workflow_with_existing_key_in_dir(
            Some(keystore_dir),
            input,
            &key_path,
            Some(planned_out.as_path()),
            loaded_sk.as_ref(),
            write_instructions,
            force,
        )?;
        println!("✅ File encrypted with public key: {}", outcome.encrypted_file.display());

        if !outcome.instructions_skipped && !outcome.instructions_written {
            eprintln!(
                "⚠️  Failed to write decryption instructions to {} (already exists? use --force to overwrite)",
                outcome.instructions_file.display()
            );
        }

        if outcome.signed_fingerprint.is_some() {
            println!("✅ File signed and encrypted with existing key");
        } else {
            println!("✅ File encrypted (no signature — use full workflow or --sign-key for signed encryption)");
        }
        println!();
        println!("📋 To decrypt, you need the corresponding encrypted private key:");
        println!(
            "   yacrypt decrypt {} --private-key <x25519_private_*.asc.enc | label>",
            outcome.encrypted_file.display()
        );
        println!();
        if outcome.instructions_written {
            println!(
                "📄 Decryption instructions saved to: {}",
                outcome.instructions_file.display()
            );
        }
    } else {
        preflight_validate_new_label(keystore_dir, label)?;

        println!("🔐 Step 1/2: Generating keypair and encrypting keys...");
        let user_pass = prompt_backup_password_choice()?;
        let outcome = encrypt_workflow_with_new_keys_opts(
            keystore_dir,
            input,
            user_pass.as_deref().map(|s| s.as_str()),
            Some(planned_out.as_path()),
            label,
            write_instructions,
            force,
        )?;

        print_generated_keys_notice(&outcome.keys, label);
        println!("✅ Keys generated and encrypted. Fingerprint: {}", outcome.keys.fingerprint);
        println!("🔐 Step 2/2: Signing and encrypting file...");
        println!("✅ File encrypted with public key: {}", outcome.encrypted_file.display());

        if !outcome.instructions_skipped && !outcome.instructions_written {
            eprintln!(
                "⚠️  Failed to write decryption instructions to {} (already exists? use --force to overwrite)",
                outcome.instructions_file.display()
            );
        }

        println!("✅ Complete encryption workflow finished!");
        println!();
        println!("📦 Generated files:");
        println!("   - Encrypted file:        {}", outcome.encrypted_file.display());
        println!("   - Public key:            {}", outcome.keys.x25519_pub_path.display());
        println!("   - Encrypted private key: {}", outcome.keys.x25519_enc_path.display());
        println!("   - Fingerprint:           {}", outcome.keys.fingerprint);
        println!();
        println!("📋 To decrypt this file, run:");
        println!("   yacrypt decrypt {} \\", outcome.encrypted_file.display());
        println!("       --private-key {}", outcome.keys.x25519_enc_path.display());
        println!();
        if outcome.instructions_written {
            println!(
                "📄 Decryption instructions saved to: {}",
                outcome.instructions_file.display()
            );
        }
        println!("⚠️  Keep your encryption password safe! It is required for decryption.");
    }

    Ok(())
}

fn sgpg_non_file_guidance(input: &Path, version: u8, blob_type: Option<&str>) -> String {
    match blob_type {
        Some("ed25519") => format!(
            "'{}' is an encrypted Ed25519 signing private key backup (SGPGv{} type=ed25519), not an encrypted data file. To export raw PKCS#8 DER, run: yacrypt decrypt-private-key {}",
            input.display(),
            version,
            input.display()
        ),
        Some("x25519") => format!(
            "'{}' is an encrypted X25519 decryption private key backup (SGPGv{} type=x25519), not an encrypted data file. Pass it via '--private-key {}' when decrypting a .pubenc file.",
            input.display(),
            version,
            input.display()
        ),
        Some(other) => format!(
            "Refusing to decrypt SGPGv{} container '{}' with type='{}' as a regular file (expected type=file)",
            version,
            input.display(),
            other
        ),
        None => format!(
            "Invalid SGPGv{} container '{}': missing 'type=file' domain tag in AAD",
            version,
            input.display()
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_decrypt_workflow(
    keystore_dir: &Path,
    input: &Path,
    private_key_arg: Option<&str>,
    output: Option<&Path>,
    signer: Option<&str>,
    require_signature: bool,
    allow_unsigned: bool,
    symmetric: bool,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    preflight_check_input_file(input, "Encrypted file not found")?;

    // 前置流式头部与 AAD 完整性自检：格式错误、非加密文件或 M-1 签名剥离在选钥/输口令之前直接报错
    let inspected = inspect_file(input)?;

    match inspected {
        InspectedFile::Sgpg(ref s) => {
            if s.blob_type.as_deref() != Some("file") {
                return Err(sgpg_non_file_guidance(
                    input,
                    s.format_version,
                    s.blob_type.as_deref(),
                )
                .into());
            }
            if require_signature || signer.is_some() {
                return Err(format!(
                    "❌ Signature verification FAILED — '{}' is a symmetric password-encrypted file (SGPGv{} type=file) which carries no Ed25519 signature, but --require-signature / --signer was specified. Decrypted content NOT written to disk.",
                    input.display(),
                    s.format_version
                )
                .into());
            }
            if private_key_arg.is_some() && !symmetric {
                return Err(format!(
                    "'{}' is a symmetric password-encrypted file (SGPGv{} type=file); omit --private-key and run: yacrypt decrypt {}",
                    input.display(),
                    s.format_version,
                    input.display()
                )
                .into());
            }

            let planned_out = match output {
                Some(p) => p.to_path_buf(),
                None => default_decrypt_output_path(input, "enc"),
            };
            preflight_check_output_path(Some(input), &planned_out, force)?;

            println!("🔓 Decrypting symmetric password-protected file...");
            let pass = Zeroizing::new(
                Password::new().with_prompt("Enter decryption password").interact()?,
            );
            let out_path = decrypt_file_symmetric(input, &pass, output, force)?;
            println!("✅ Complete decryption workflow finished!");
            println!("   - Decrypted file: {}", out_path.display());
            return Ok(());
        }
        InspectedFile::Pubenc(ref p) if symmetric => {
            return Err(format!(
                "'{}' is a public-key encrypted file (SCFv{} / .pubenc), not a symmetric SGPGv1/SGPGv2 file; omit --symmetric and provide --private-key",
                input.display(),
                p.format_version
            )
            .into());
        }
        InspectedFile::Pubenc(_) => {}
    }

    if let Some(s) = signer {
        let _ = resolve_signer_fingerprint_in_dir(s, keystore_dir)?;
    }

    let priv_key = match private_key_arg.filter(|s| !s.trim().is_empty()) {
        Some(arg) => resolve_decrypt_key_arg(keystore_dir, arg)?,
        None if is_interactive_tty() => {
            let entry = select_keyring_entry_interactively(
                keystore_dir,
                "Select X25519 decryption private key",
                "Missing --private-key <x25519_private_*.asc.enc | label | fingerprint> (no decryption keys in keystore)",
                |e| e.x25519_enc_path.is_some(),
            )?;
            entry.x25519_enc_path.unwrap()
        }
        None => {
            return Err(
                "Missing --private-key <x25519_private_*.asc.enc | label | fingerprint> (required for .pubenc public-key encrypted files)"
                    .into(),
            );
        }
    };

    preflight_check_input_file(&priv_key, "Private key file not found")?;

    let planned_out = match output {
        Some(p) => p.to_path_buf(),
        None => default_decrypt_output_path(input, "pubenc"),
    };
    preflight_check_output_path(Some(input), &planned_out, force)?;
    preflight_check_output_path(Some(&priv_key), &planned_out, force)?;

    println!("🔓 Step 1/2: Decrypting private key...");
    let pass =
        Zeroizing::new(Password::new().with_prompt("Enter private key password").interact()?);

    println!("🔓 Step 2/2: Decrypting and verifying file...");
    let effective_require_sig = !allow_unsigned;
    let outcome = decrypt_workflow_with_password_in_dir(
        keystore_dir,
        input,
        &priv_key,
        &pass,
        output,
        signer,
        effective_require_sig,
        force,
    )?;

    match outcome.verified_signer_fingerprint {
        Some(verified_fp) => {
            println!(
                "✅ File signature verified successfully (signer fingerprint: {})",
                verified_fp
            );
        }
        None => {
            println!("ℹ️  No signature embedded in encrypted file, skipping verification");
        }
    }

    println!("✅ Complete decryption workflow finished!");
    println!("   - Decrypted file: {}", outcome.decrypted_file.display());

    Ok(())
}

/// 基于 `Cli::command()` 动态反射生成 Shell 自动补全脚本（零额外外部依赖）
pub fn cmd_completions(shell: CompletionShell) -> Result<(), Box<dyn std::error::Error>> {
    let script = render_completions_script(shell);
    let mut out = io::stdout().lock();
    out.write_all(script.as_bytes())?;
    out.flush()?;
    Ok(())
}

pub fn render_completions_script(shell: CompletionShell) -> String {
    let cmd = Cli::command();
    let mut global_opts: Vec<(String, bool)> = vec![
        ("-h".to_string(), false),
        ("--help".to_string(), false),
        ("-V".to_string(), false),
        ("--version".to_string(), false),
    ];
    for arg in cmd.get_arguments() {
        let takes_val = arg.get_num_args().map(|r| r.max_values() > 0).unwrap_or(false);
        if let Some(short) = arg.get_short() {
            let s = format!("-{}", short);
            if !global_opts.iter().any(|(k, _)| k == &s) {
                global_opts.push((s, takes_val));
            }
        }
        if let Some(long) = arg.get_long() {
            let l = format!("--{}", long);
            if !global_opts.iter().any(|(k, _)| k == &l) {
                global_opts.push((l, takes_val));
            }
        }
    }

    struct SubSpec {
        name: String,
        aliases: Vec<String>,
        about: String,
        opts: Vec<(String, bool)>,
    }

    let mut subs = Vec::new();
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        let mut opts: Vec<(String, bool)> =
            vec![("-h".to_string(), false), ("--help".to_string(), false)];
        for arg in sub.get_arguments() {
            let takes_val = arg.get_num_args().map(|r| r.max_values() > 0).unwrap_or(false);
            if let Some(short) = arg.get_short() {
                let s = format!("-{}", short);
                if !opts.iter().any(|(k, _)| k == &s) {
                    opts.push((s, takes_val));
                }
            }
            if let Some(long) = arg.get_long() {
                let l = format!("--{}", long);
                if !opts.iter().any(|(k, _)| k == &l) {
                    opts.push((l, takes_val));
                }
            }
        }
        for (g, g_takes) in &global_opts {
            if !opts.iter().any(|(k, _)| k == g) {
                opts.push((g.clone(), *g_takes));
            }
        }
        let about = sub
            .get_about()
            .map(|s| s.to_string())
            .unwrap_or_default()
            .replace(['\'', '"', '\n'], " ");
        let aliases = sub.get_visible_aliases().map(str::to_string).collect();
        subs.push(SubSpec { name: sub.get_name().to_string(), aliases, about, opts });
    }
    subs.push(SubSpec {
        name: "help".into(),
        aliases: Vec::new(),
        about: "Print help for a subcommand".into(),
        opts: vec![("-h".into(), false), ("--help".into(), false)],
    });

    match shell {
        CompletionShell::Bash => {
            let mut sub_words: Vec<String> = Vec::new();
            for s in &subs {
                sub_words.push(s.name.clone());
                for a in &s.aliases {
                    sub_words.push(a.clone());
                }
            }
            let global_words: Vec<&str> = global_opts.iter().map(|(k, _)| k.as_str()).collect();
            let mut cases = String::new();
            for s in &subs {
                let mut patterns = vec![s.name.clone()];
                patterns.extend(s.aliases.iter().cloned());
                let pat = patterns.join("|");
                let opt_words: Vec<&str> = s.opts.iter().map(|(k, _)| k.as_str()).collect();
                if s.name == "completions" {
                    cases.push_str(&format!(
                        "        {})\n            COMPREPLY=( $(compgen -W \"bash zsh fish powershell pwsh {}\" -- \"${{cur}}\") )\n            return 0\n            ;;\n",
                        pat,
                        opt_words.join(" ")
                    ));
                } else {
                    cases.push_str(&format!(
                        "        {})\n            if [[ \"${{cur}}\" == -* ]]; then\n                COMPREPLY=( $(compgen -W \"{}\" -- \"${{cur}}\") )\n            else\n                COMPREPLY=( $(compgen -f -- \"${{cur}}\") )\n            fi\n            return 0\n            ;;\n",
                        pat,
                        opt_words.join(" ")
                    ));
                }
            }
            format!(
                "# bash completion for yacrypt\n\
_yacrypt() {{\n\
    local cur prev subcmd\n\
    COMPREPLY=()\n\
    cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n\
    prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\
    if [[ \"${{prev}}\" == \"--keystore-dir\" ]]; then\n\
        COMPREPLY=( $(compgen -d -- \"${{cur}}\") )\n\
        return 0\n\
    fi\n\
    subcmd=\"\"\n\
    local i=1\n\
    while [[ $i -lt $COMP_CWORD ]]; do\n\
        case \"${{COMP_WORDS[$i]}}\" in\n\
            --keystore-dir)\n\
                i=$((i + 2))\n\
                continue\n\
                ;;\n\
            -*)\n\
                i=$((i + 1))\n\
                continue\n\
                ;;\n\
            *)\n\
                subcmd=\"${{COMP_WORDS[$i]}}\"\n\
                break\n\
                ;;\n\
        esac\n\
    done\n\
    if [[ -z \"${{subcmd}}\" ]]; then\n\
        if [[ \"${{cur}}\" == -* ]]; then\n\
            COMPREPLY=( $(compgen -W \"{global}\" -- \"${{cur}}\") )\n\
        else\n\
            COMPREPLY=( $(compgen -W \"{subs}\" -- \"${{cur}}\") )\n\
        fi\n\
        return 0\n\
    fi\n\
    case \"${{subcmd}}\" in\n\
{cases}        *)\n\
            COMPREPLY=( $(compgen -f -- \"${{cur}}\") )\n\
            return 0\n\
            ;;\n\
    esac\n\
}}\n\
complete -F _yacrypt yacrypt\n",
                global = global_words.join(" "),
                subs = sub_words.join(" "),
                cases = cases,
            )
        }
        CompletionShell::Zsh => {
            let mut sub_entries = String::new();
            let mut sub_cases = String::new();
            for s in &subs {
                let desc = s.about.replace(':', "\\:");
                sub_entries.push_str(&format!("        '{}:{}'\n", s.name, desc));
                for a in &s.aliases {
                    sub_entries.push_str(&format!("        '{}:{}'\n", a, desc));
                }
                let mut patterns = vec![s.name.clone()];
                patterns.extend(s.aliases.iter().cloned());
                let pat = patterns.join("|");
                if s.name == "completions" {
                    sub_cases.push_str(&format!(
                        "                {})\n                    _arguments -s '(-h --help)'{{-h,--help}}'[Print help]' '--keystore-dir=:dir:_files -/' '1:shell:(bash zsh fish powershell pwsh)'\n                    ;;\n",
                        pat
                    ));
                } else {
                    let quoted_opts: Vec<String> = s
                        .opts
                        .iter()
                        .map(|(o, takes_val)| {
                            if o == "--keystore-dir" {
                                "'--keystore-dir=:dir:_files -/'".to_string()
                            } else if *takes_val {
                                if o.starts_with("--") {
                                    format!("'{}=:value:_files'", o)
                                } else {
                                    format!("'{}+:value:_files'", o)
                                }
                            } else {
                                format!("'{}'", o)
                            }
                        })
                        .collect();
                    sub_cases.push_str(&format!(
                        "                {})\n                    _arguments -s {} '*:file:_files'\n                    ;;\n",
                        pat,
                        quoted_opts.join(" ")
                    ));
                }
            }
            format!(
                "#compdef yacrypt\n\
_yacrypt() {{\n\
    local line state\n\
    local -a subcommands\n\
    subcommands=(\n\
{sub_entries}    )\n\
    _arguments -C \\\n\
        '--keystore-dir=[Custom keystore directory]:dir:_files -/' \\\n\
        '(-h --help)'{{-h,--help}}'[Print help]' \\\n\
        '(-V --version)'{{-V,--version}}'[Print version]' \\\n\
        '1:subcommand:->subcmd' \\\n\
        '*::arg:->args'\n\
    case \"$state\" in\n\
        subcmd)\n\
            _describe -t commands 'yacrypt subcommand' subcommands\n\
            ;;\n\
        args)\n\
            case \"$line[1]\" in\n\
{sub_cases}            esac\n\
            ;;\n\
    esac\n\
}}\n\
_yacrypt \"$@\"\n",
                sub_entries = sub_entries,
                sub_cases = sub_cases,
            )
        }
        CompletionShell::Fish => {
            let mut out = String::from("# fish completion for yacrypt\n");
            out.push_str(
                "complete -c yacrypt -l keystore-dir -r -a '(__fish_complete_directories)' -d 'Custom keystore directory'\n",
            );
            for s in &subs {
                out.push_str(&format!(
                    "complete -c yacrypt -n '__fish_use_subcommand' -a '{}' -d '{}'\n",
                    s.name, s.about
                ));
                for a in &s.aliases {
                    out.push_str(&format!(
                        "complete -c yacrypt -n '__fish_use_subcommand' -a '{}' -d '{}'\n",
                        a, s.about
                    ));
                }
                let cond = if s.aliases.is_empty() {
                    format!("__fish_seen_subcommand_from {}", s.name)
                } else {
                    format!("__fish_seen_subcommand_from {} {}", s.name, s.aliases.join(" "))
                };
                if s.name == "completions" {
                    out.push_str(&format!(
                        "complete -c yacrypt -n '{}' -f -a 'bash zsh fish powershell pwsh'\n",
                        cond
                    ));
                }
                for (opt, _) in &s.opts {
                    if opt == "--keystore-dir" {
                        continue;
                    }
                    if let Some(long) = opt.strip_prefix("--") {
                        out.push_str(&format!("complete -c yacrypt -n '{}' -l '{}'\n", cond, long));
                    } else if let Some(short) = opt.strip_prefix('-') {
                        out.push_str(&format!(
                            "complete -c yacrypt -n '{}' -s '{}'\n",
                            cond, short
                        ));
                    }
                }
            }
            out
        }
        CompletionShell::PowerShell => {
            let mut top_words: Vec<String> = global_opts.iter().map(|(k, _)| k.clone()).collect();
            for s in &subs {
                top_words.push(s.name.clone());
                top_words.extend(s.aliases.iter().cloned());
            }
            let top_quoted: Vec<String> =
                top_words.into_iter().map(|w| format!("'{}'", w)).collect();
            let mut ps_cases = String::new();
            for s in &subs {
                let mut names: Vec<String> = vec![format!("'{}'", s.name)];
                names.extend(s.aliases.iter().map(|a| format!("'{}'", a)));
                let mut cands: Vec<String> =
                    s.opts.iter().map(|(k, _)| format!("'{}'", k)).collect();
                if s.name == "completions" {
                    for sh in ["bash", "zsh", "fish", "powershell", "pwsh"] {
                        cands.push(format!("'{}'", sh));
                    }
                }
                ps_cases.push_str(&format!(
                    "        {} {{ $candidates = @({}) }}\n",
                    names.join(", "),
                    cands.join(", ")
                ));
            }
            format!(
                "# PowerShell completion for yacrypt\n\
Register-ArgumentCompleter -Native -CommandName yacrypt -ScriptBlock {{\n\
    param($wordToComplete, $commandAst, $cursorPosition)\n\
    $tokens = $commandAst.CommandElements | ForEach-Object {{ $_.Extent.Text }}\n\
    $subcmd = $null\n\
    for ($i = 1; $i -lt $tokens.Count; $i++) {{\n\
        $tok = $tokens[$i]\n\
        if ($tok -eq $wordToComplete) {{ continue }}\n\
        if ($tok -eq '--keystore-dir') {{ $i++; continue }}\n\
        if ($tok.StartsWith('-')) {{ continue }}\n\
        $subcmd = $tok\n\
        break\n\
    }}\n\
    $candidates = @({top})\n\
    switch ($subcmd) {{\n\
{cases}    }}\n\
    $candidates | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{\n\
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)\n\
    }}\n\
}}\n",
                top = top_quoted.join(", "),
                cases = ps_cases,
            )
        }
    }
}
