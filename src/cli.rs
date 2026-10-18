/// CLI 结构定义与终端交互适配模块
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Password};
use std::path::{Path, PathBuf};
use yacrypt_core::{
    constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH},
    file_ops::encrypt_file_with_key,
    keystore::{
        decrypt_backup_with_password, generate_and_store_keys_in_dir,
        load_signing_key_with_password, GeneratedKeys,
    },
    password::generate_strong_password,
    workflow::{
        decrypt_workflow_with_password, encrypt_workflow_with_existing_key,
        encrypt_workflow_with_new_keys, resolve_signer_fingerprint,
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
    /// Encrypt file: generate keypair (or reuse existing), encrypt keys, encrypt file, sign file.
    /// By default generates a new keypair. Use --key to reuse an existing keypair.
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,
        /// Human name for the keypair (used in metadata, ignored if --key is specified)
        #[arg(default_value = "user")]
        name: String,
        /// Email (used in metadata, ignored if --key is specified)
        #[arg(default_value = "secure@example.com")]
        email: String,
        /// Output encrypted file (default: input with .pubenc extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Reuse existing X25519 public key file instead of generating a new keypair.
        /// The file should be from keystore/x25519_public_*.asc
        #[arg(short, long)]
        key: Option<PathBuf>,
        /// Optional encrypted Ed25519 private key file (from keystore/private_*.asc.enc) to sign when using --key
        #[arg(long)]
        sign_key: Option<PathBuf>,
        /// Overwrite output file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// Decrypt file: decrypt key, decrypt file, verify signature and signer identity.
    /// This command decrypts the private key, decrypts the encrypted file, and verifies
    /// the file signature against the expected signer fingerprint before writing to disk.
    Decrypt {
        /// Input encrypted file to decrypt (usually with .pubenc extension)
        input: PathBuf,
        /// Encrypted X25519 private key file (from keystore/x25519_private_*.asc.enc)
        #[arg(short, long)]
        private_key: PathBuf,
        /// Output decrypted file (default: input without .pubenc extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Expected signer Ed25519 fingerprint (64 hex chars) or public key file (keystore/public_*.asc).
        /// Defaults to the fingerprint bound to the recipient's keypair.
        #[arg(short, long)]
        signer: Option<String>,
        /// Require the encrypted file to carry a valid Ed25519 signature
        #[arg(long)]
        require_signature: bool,
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
    let keys =
        generate_and_store_keys_in_dir(Path::new("keystore"), user_pass.as_deref().map(|s| s.as_str()))?;
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

    let out_path =
        encrypt_file_with_key(input, public_key, output, loaded_sk.as_ref(), force)?;
    println!("✅ File encrypted with public key: {}", out_path.display());
    Ok(())
}

pub fn cmd_encrypt_workflow(
    input: &Path,
    name: &str,
    email: &str,
    output: Option<&Path>,
    existing_key: Option<&Path>,
    sign_key: Option<&Path>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !input.exists() {
        return Err(format!("Input file not found: {}", input.display()).into());
    }

    if let Some(key_path) = existing_key {
        if !key_path.exists() {
            return Err(format!("Public key file not found: {}", key_path.display()).into());
        }
        let loaded_sk = match sign_key {
            Some(sk_path) => {
                if !sk_path.exists() {
                    return Err(
                        format!("Signing key file not found: {}", sk_path.display()).into()
                    );
                }
                let pass = Zeroizing::new(
                    Password::new().with_prompt("Enter signing private key password").interact()?,
                );
                Some(load_signing_key_with_password(sk_path, &pass)?)
            }
            None => None,
        };

        println!("🔐 Encrypting file with existing key: {}", key_path.display());
        let outcome = encrypt_workflow_with_existing_key(
            input,
            key_path,
            output,
            loaded_sk.as_ref(),
            force,
        )?;
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
    private_key_path: &Path,
    output: Option<&Path>,
    signer: Option<&str>,
    require_signature: bool,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !input.exists() {
        return Err(format!("Encrypted file not found: {}", input.display()).into());
    }
    if !private_key_path.exists() {
        return Err(format!("Private key file not found: {}", private_key_path.display()).into());
    }
    if let Some(s) = signer {
        let _ = resolve_signer_fingerprint(s)?;
    }

    println!("🔓 Step 1/2: Decrypting private key...");
    let pass = Zeroizing::new(
        Password::new().with_prompt("Enter private key password").interact()?,
    );

    println!("🔓 Step 2/2: Decrypting and verifying file...");
    let outcome = decrypt_workflow_with_password(
        input,
        private_key_path,
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
