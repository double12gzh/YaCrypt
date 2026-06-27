//! YaCrypt — secure key generator & encrypted backup
//! - Ed25519 keypair (PKCS#8 for private key storage)
//! - Argon2id KDF with stored params+salt
//! - XChaCha20-Poly1305 AEAD with random nonce (24 bytes)
//! - mlockall attempt
//! - strict file permissions
//! - zeroize secrets
//! - AAD stored in blob header and used during decrypt

mod cli;
mod constants;
mod crypto;
mod error;
mod file_ops;
mod keystore;
mod password;
mod utils;
mod workflow;

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenPassword { length } => password::cmd_generate_strong_password(*length),
        Commands::GenKeypair { name, email } => keystore::cmd_generate_protected_key(name, email),
        Commands::DecryptPrivateKey { enc_path, out } => {
            keystore::cmd_decrypt_backup(enc_path, out.as_deref())
        }
        Commands::EncryptFileWithKey { input, public_key, output } => {
            file_ops::cmd_encrypt_file_with_key(input, public_key, output.as_deref(), None)
        }
        Commands::Encrypt { input, name, email, output, key } => {
            workflow::cmd_encrypt_workflow(input, name, email, output.as_deref(), key.as_deref())
        }
        Commands::Decrypt { input, private_key, output } => {
            workflow::cmd_decrypt_workflow(input, private_key, output.as_deref())
        }
    }
}
