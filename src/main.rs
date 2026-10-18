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
    utils::try_mlockall();

    let cli = Cli::parse();

    match &cli.command {
        Commands::GenPassword { length } => password::cmd_generate_strong_password(*length),
        Commands::GenKeypair { name, email } => keystore::cmd_generate_protected_key(name, email),
        Commands::DecryptPrivateKey { enc_path, out, force } => {
            keystore::cmd_decrypt_backup(enc_path, out.as_deref(), *force)
        }
        Commands::EncryptFileWithKey { input, public_key, output, sign_key, force } => {
            let loaded_sk = match sign_key {
                Some(sk_path) => Some(keystore::load_signing_key_from_backup(sk_path)?),
                None => None,
            };
            file_ops::cmd_encrypt_file_with_key(
                input,
                public_key,
                output.as_deref(),
                loaded_sk.as_ref(),
                *force,
            )
        }
        Commands::Encrypt { input, name, email, output, key, sign_key, force } => {
            workflow::cmd_encrypt_workflow(
                input,
                name,
                email,
                output.as_deref(),
                key.as_deref(),
                sign_key.as_deref(),
                *force,
            )
        }
        Commands::Decrypt { input, private_key, output, signer, require_signature, force } => {
            workflow::cmd_decrypt_workflow(
                input,
                private_key,
                output.as_deref(),
                signer.as_deref(),
                *require_signature,
                *force,
            )
        }
    }
}
