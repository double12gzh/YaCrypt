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
    /// Decrypt an encrypted private key backup file to produce plaintext private key (DER format)
    DecryptPrivateKey {
        enc_path: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Encrypt a file using an existing X25519 public key (hybrid encryption: X25519 + XChaCha20-Poly1305)
    EncryptFileWithKey {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        /// X25519 public key file (Base64 encoded, from keystore/x25519_public_*.asc)
        #[arg(short, long)]
        public_key: PathBuf,
        /// Output encrypted file (default: input.pubenc)
        #[arg(short, long)]
        output: Option<PathBuf>,
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
        /// Output encrypted file (default: input.pubenc)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Reuse existing X25519 public key file instead of generating a new keypair.
        /// The file should be from keystore/x25519_public_*.asc
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Decrypt file: decrypt key, decrypt file, verify signature.
    /// This command decrypts the private key, decrypts the encrypted file, and verifies
    /// the file signature if available.
    Decrypt {
        /// Input encrypted file to decrypt (usually with .pubenc extension)
        input: PathBuf,
        /// Encrypted X25519 private key file (from keystore/x25519_private_*.asc.enc)
        #[arg(short, long)]
        private_key: PathBuf,
        /// Output decrypted file (default: input without .pubenc extension)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}
