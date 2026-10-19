/// CLI 结构定义与终端交互适配模块
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Password};
use std::path::{Path, PathBuf};
use yacrypt_core::{
    constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH},
    file_ops::{decrypt_file_symmetric, encrypt_file_symmetric, encrypt_file_with_key},
    keystore::{
        decrypt_backup_with_password, generate_and_store_keys_in_dir,
        load_signing_key_with_password, scan_keystore, GeneratedKeys,
    },
    password::generate_strong_password,
    workflow::{
        decrypt_workflow_with_password, encrypt_workflow_with_existing_key,
        encrypt_workflow_with_new_keys, inspect_file, resolve_signer_fingerprint, InspectedFile,
    },
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Launch interactive 4-in-1 TUI workbench (default when no subcommand is given)
    Tui,
    /// Inspect an encrypted file (.pubenc, .enc, or .asc.enc) without a password
    Inspect {
        /// Path to the encrypted file or key backup to inspect
        file: PathBuf,
    },
    /// List all Ed25519 + X25519 keypairs stored in the local keystore/ directory
    #[command(visible_alias = "keys")]
    KeyList,
    /// Generate a new Ed25519 and X25519 keypair with encrypted private key backup
    GenKeypair {
        /// human name
        name: String,
        /// email (used in metadata)
        #[arg(default_value = "secure@example.com")]
        email: String,
    },
    /// Generate a strong password (print to stdout)
    GenPassword {
        /// Number of characters in the output password (default: 32)
        #[arg(short, long, default_value_t = 32)]
        length: usize,
    },
    /// Decrypt an encrypted Ed25519 private key backup file to produce plaintext private key (PKCS#8 DER format)
    DecryptPrivateKey {
        enc_path: PathBuf,
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
        /// X25519 public key file (Base64 encoded, from keystore/x25519_public_*.asc)
        #[arg(short, long)]
        public_key: PathBuf,
        /// Output encrypted file (default: input with .pubenc extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Optional encrypted Ed25519 private key file (from keystore/private_*.asc.enc) to sign the file
        #[arg(long)]
        sign_key: Option<PathBuf>,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Encrypt file: generate keypair (or reuse existing via --key, or use password-only via --symmetric).
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,
        /// Human name for the keypair (used in metadata, ignored if --key or --symmetric is specified)
        #[arg(default_value = "user")]
        name: String,
        /// Email (used in metadata, ignored if --key or --symmetric is specified)
        #[arg(default_value = "secure@example.com")]
        email: String,
        /// Output encrypted file (default: <input>.pubenc, or <input>.enc when --symmetric is used)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Reuse existing X25519 public key file instead of generating a new keypair.
        /// The file should be from keystore/x25519_public_*.asc
        #[arg(short, long)]
        key: Option<PathBuf>,
        /// Optional encrypted Ed25519 private key file (from keystore/private_*.asc.enc) to sign when using --key
        #[arg(long)]
        sign_key: Option<PathBuf>,
        /// Encrypt directly with a password (Argon2id + XChaCha20-Poly1305, SGPGv1 format) without public/private keys
        #[arg(short = 'c', long)]
        symmetric: bool,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Decrypt file: supports both .pubenc (hybrid public-key) and .enc (symmetric password-encrypted) files.
    Decrypt {
        /// Input encrypted file to decrypt (.pubenc or .enc)
        input: PathBuf,
        /// Encrypted X25519 private key file (required for .pubenc files, omitted for --symmetric / .enc files)
        #[arg(short, long)]
        private_key: Option<PathBuf>,
        /// Output decrypted file (default: input without .pubenc / .enc extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Expected signer Ed25519 fingerprint (64 hex chars) or public key file (keystore/public_*.asc).
        #[arg(short, long)]
        signer: Option<String>,
        /// Require the encrypted file to carry a valid Ed25519 signature
        #[arg(long)]
        require_signature: bool,
        /// Force symmetric password decryption mode (auto-detected for SGPGv1 .enc files)
        #[arg(short = 'c', long)]
        symmetric: bool,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
}

/// 提示用户输入并确认密码，验证长度
pub fn prompt_password_confirm(prompt: &str) -> Option<Zeroizing<String>> {
    loop {
        let p = Zeroizing::new(
            Password::new()
                .with_prompt(prompt)
                .with_confirmation("Confirm password", "Passwords mismatched")
                .interact()
                .ok()?,
        );

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

/// 交互式询问是否自动生成备份口令，否则读取用户确认口令
fn prompt_backup_password_choice() -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>>
{
    let auto_backup_pass = Confirm::new()
        .with_prompt("Auto-generate backup encryption password?")
        .default(false)
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

/// 打印自动生成口令（若启用）与身份回显
fn print_generated_keys_notice(keys: &GeneratedKeys, name: &str, email: &str) {
    if let Some(ref backup_pass) = keys.auto_generated_password {
        println!("✅ Backup password generated:");
        println!("   {}", backup_pass.as_str());
        println!("   ⚠️  IMPORTANT: Save this password securely! You will need it to decrypt your private key backup.");
    }
    println!("👤 Key owner: {} <{}> (not stored in any file — keep your own record)", name, email);
}

pub fn cmd_inspect_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let info = inspect_file(path)?;
    let keyring = scan_keystore(Path::new("keystore")).unwrap_or_default();

    println!("🔍 File Inspection: {}", path.display());
    println!("========================================");
    match info {
        InspectedFile::Pubenc(p) => {
            println!("Format:             SCFv1 (Hybrid Public-Key Encrypted File)");
            println!("Algorithm Suite:    X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305");
            println!("Ephemeral X25519:   {}", p.ephemeral_pub_hex);
            println!("Ciphertext Size:    {} bytes", p.ciphertext_len);
            if let Some(fp) = p.signer_fingerprint {
                println!("Embedded Signature: ✅ Present (Ed25519)");
                println!("Signer Fingerprint: {}", fp);
                let matched = keyring.iter().any(|k| k.fingerprint.eq_ignore_ascii_case(&fp));
                if matched {
                    println!("Local Keyring:      ✅ Matching keypair found in keystore/");
                } else {
                    println!("Local Keyring:      ℹ️  No matching keypair in local keystore/");
                }
            } else {
                println!("Embedded Signature: ⚠️  None (Unsigned)");
            }
        }
        InspectedFile::Sgpg(s) => {
            let kind_desc = match s.blob_type.as_deref() {
                Some("file") => "Symmetric Password-Encrypted File (type=file)",
                Some("ed25519") => "Encrypted Ed25519 Signing Private Key Backup (type=ed25519)",
                Some("x25519") => "Encrypted X25519 Decryption Private Key Backup (type=x25519)",
                Some(other) => other,
                None => "Unknown SGPGv1 payload",
            };
            println!("Format:             SGPGv1 (Password-Based Encrypted Container)");
            println!("Payload Type:       {}", kind_desc);
            println!("Algorithm Suite:    Argon2id + XChaCha20-Poly1305");
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
                let matched = keyring.iter().any(|k| k.fingerprint.eq_ignore_ascii_case(&fp));
                if matched {
                    println!("Local Keyring:      ✅ Present in local keystore/");
                }
            }
        }
    }
    Ok(())
}

pub fn cmd_key_list() -> Result<(), Box<dyn std::error::Error>> {
    let entries = scan_keystore(Path::new("keystore"))?;
    if entries.is_empty() {
        println!("📭 No keypairs found in keystore/ directory.");
        println!("   Run 'yacrypt gen-keypair <name> <email>' to generate one.");
        return Ok(());
    }

    println!("🔑 Local Keystore ({} keypair(s) found):", entries.len());
    println!("========================================");
    for (idx, entry) in entries.iter().enumerate() {
        println!("[{}] Fingerprint: {}", idx + 1, entry.fingerprint);
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

pub fn cmd_generate_strong_password(length: usize) -> Result<(), Box<dyn std::error::Error>> {
    let pw = generate_strong_password(length)?;
    println!("{}", pw.as_str());
    Ok(())
}

pub fn cmd_generate_protected_key(
    name: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let user_pass = prompt_backup_password_choice()?;
    let keys = generate_and_store_keys_in_dir(
        Path::new("keystore"),
        user_pass.as_deref().map(|s| s.as_str()),
    )?;
    print_generated_keys_notice(&keys, name, email);

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

pub fn cmd_decrypt_backup(
    enc_path: &Path,
    out: Option<&Path>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !enc_path.exists() {
        return Err(format!("Encrypted file not found: {}", enc_path.display()).into());
    }

    let pass = Zeroizing::new(Password::new().with_prompt("Enter backup password").interact()?);
    let out_path = decrypt_backup_with_password(enc_path, &pass, out, force)?;

    println!("✅ Decrypted private key written to: {}", out_path.display());
    Ok(())
}

pub fn cmd_encrypt_file_with_key_cli(
    input: &Path,
    public_key: &Path,
    output: Option<&Path>,
    sign_key: Option<&Path>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let loaded_sk = match sign_key {
        Some(sk_path) => {
            if !sk_path.exists() {
                return Err(format!("Signing key file not found: {}", sk_path.display()).into());
            }
            let pass = Zeroizing::new(
                Password::new().with_prompt("Enter signing private key password").interact()?,
            );
            Some(load_signing_key_with_password(sk_path, &pass)?)
        }
        None => None,
    };

    let out_path = encrypt_file_with_key(input, public_key, output, loaded_sk.as_ref(), force)?;
    println!("✅ File encrypted with public key: {}", out_path.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_encrypt_workflow(
    input: &Path,
    name: &str,
    email: &str,
    output: Option<&Path>,
    existing_key: Option<&Path>,
    sign_key: Option<&Path>,
    symmetric: bool,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !input.exists() {
        return Err(format!("Input file not found: {}", input.display()).into());
    }

    if symmetric {
        println!("🔐 Encrypting file in symmetric password mode (SGPGv1)...");
        let pass = match prompt_password_confirm("Enter encryption password") {
            Some(p) => p,
            None => return Err("Failed to read encryption password".into()),
        };
        let out_path = encrypt_file_symmetric(input, &pass, output, force)?;
        println!("✅ File symmetrically encrypted: {}", out_path.display());
        println!("📋 To decrypt, run: yacrypt decrypt {}", out_path.display());
        return Ok(());
    }

    if let Some(key_path) = existing_key {
        if !key_path.exists() {
            return Err(format!("Public key file not found: {}", key_path.display()).into());
        }
        let loaded_sk = match sign_key {
            Some(sk_path) => {
                if !sk_path.exists() {
                    return Err(format!("Signing key file not found: {}", sk_path.display()).into());
                }
                let pass = Zeroizing::new(
                    Password::new().with_prompt("Enter signing private key password").interact()?,
                );
                Some(load_signing_key_with_password(sk_path, &pass)?)
            }
            None => None,
        };

        println!("🔐 Encrypting file with existing key: {}", key_path.display());
        let outcome =
            encrypt_workflow_with_existing_key(input, key_path, output, loaded_sk.as_ref(), force)?;
        println!("✅ File encrypted with public key: {}", outcome.encrypted_file.display());

        if !outcome.instructions_written {
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
            "   yacrypt decrypt {} --private-key <x25519_private_*.asc.enc>",
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
        println!("🔐 Step 1/2: Generating keypair and encrypting keys...");
        let user_pass = prompt_backup_password_choice()?;
        let outcome = encrypt_workflow_with_new_keys(
            Path::new("keystore"),
            input,
            user_pass.as_deref().map(|s| s.as_str()),
            output,
            force,
        )?;

        print_generated_keys_notice(&outcome.keys, name, email);
        println!("✅ Keys generated and encrypted. Fingerprint: {}", outcome.keys.fingerprint);
        println!("🔐 Step 2/2: Signing and encrypting file...");
        println!("✅ File encrypted with public key: {}", outcome.encrypted_file.display());

        if !outcome.instructions_written {
            eprintln!(
                "⚠️  Failed to write decryption instructions to {} (already exists? use --force to overwrite)",
                outcome.instructions_file.display()
            );
        }

        println!("✅ Complete encryption workflow finished!");
        println!();
        println!("📦 Generated files:");
        println!("   - Encrypted file:       {}", outcome.encrypted_file.display());
        println!("   - Public key:           {}", outcome.keys.x25519_pub_path.display());
        println!("   - Encrypted private key: {}", outcome.keys.x25519_enc_path.display());
        println!("   - Fingerprint:          {}", outcome.keys.fingerprint);
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

pub fn cmd_decrypt_workflow(
    input: &Path,
    private_key_path: Option<&Path>,
    output: Option<&Path>,
    signer: Option<&str>,
    require_signature: bool,
    symmetric: bool,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !input.exists() {
        return Err(format!("Encrypted file not found: {}", input.display()).into());
    }

    // 自动检测是否为 SGPGv1 对称加密容器（当未显式传入 --private-key 或显式指定 --symmetric 时）
    let is_sgpg = symmetric
        || (private_key_path.is_none()
            && matches!(inspect_file(input), Ok(InspectedFile::Sgpg(_))));

    if is_sgpg {
        println!("🔓 Decrypting symmetric password-protected file...");
        let pass =
            Zeroizing::new(Password::new().with_prompt("Enter decryption password").interact()?);
        let out_path = decrypt_file_symmetric(input, &pass, output, force)?;
        println!("✅ Complete decryption workflow finished!");
        println!("   - Decrypted file: {}", out_path.display());
        return Ok(());
    }

    let Some(priv_key) = private_key_path else {
        return Err(
            "Missing --private-key <x25519_private_*.asc.enc> (required for .pubenc public-key encrypted files)"
                .into(),
        );
    };

    if !priv_key.exists() {
        return Err(format!("Private key file not found: {}", priv_key.display()).into());
    }
    if let Some(s) = signer {
        let _ = resolve_signer_fingerprint(s)?;
    }

    println!("🔓 Step 1/2: Decrypting private key...");
    let pass =
        Zeroizing::new(Password::new().with_prompt("Enter private key password").interact()?);

    println!("🔓 Step 2/2: Decrypting and verifying file...");
    let outcome = decrypt_workflow_with_password(
        input,
        priv_key,
        &pass,
        output,
        signer,
        require_signature,
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
