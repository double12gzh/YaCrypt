/// CLI 结构定义模块
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new Ed25519 and X25519 keypair with encrypted private key backup
    GenKeypair {
        /// human name (echoed for your records only — never stored in any file)
        name: String,
        /// email (echoed for your records only — never stored in any file)
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
        /// Human name for the keypair (echoed for your records only; ignored if --key is specified)
        #[arg(default_value = "user")]
        name: String,
        /// Email (echoed for your records only; ignored if --key is specified)
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
