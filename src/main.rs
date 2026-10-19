//! YaCrypt — secure key generator, hybrid file encryption CLI & interactive TUI workbench
//! - Ed25519 keypair (PKCS#8 for private key storage)
//! - Argon2id KDF with stored params+salt
//! - XChaCha20-Poly1305 AEAD with random nonce (24 bytes)
//! - mlockall attempt
//! - strict file permissions
//! - zeroize secrets
//! - AAD stored in blob header and used during decrypt

mod cli;
mod tui;

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    yacrypt_core::utils::try_mlockall();

    let cli = Cli::parse();

    match &cli.command {
        None | Some(Commands::Tui) => tui::run(),
        Some(Commands::Inspect { file }) => cli::cmd_inspect_file(file),
        Some(Commands::KeyList) => cli::cmd_key_list(),
        Some(Commands::GenPassword { length }) => cli::cmd_generate_strong_password(*length),
        Some(Commands::GenKeypair { name, email }) => cli::cmd_generate_protected_key(name, email),
        Some(Commands::DecryptPrivateKey { enc_path, out, force }) => {
            cli::cmd_decrypt_backup(enc_path, out.as_deref(), *force)
        }
        Some(Commands::EncryptFileWithKey { input, public_key, output, sign_key, force }) => {
            cli::cmd_encrypt_file_with_key_cli(
                input,
                public_key,
                output.as_deref(),
                sign_key.as_deref(),
                *force,
            )
        }
        Some(Commands::Encrypt { input, name, email, output, key, sign_key, symmetric, force }) => {
            cli::cmd_encrypt_workflow(
                input,
                name,
                email,
                output.as_deref(),
                key.as_deref(),
                sign_key.as_deref(),
                *symmetric,
                *force,
            )
        }
        Some(Commands::Decrypt {
            input,
            private_key,
            output,
            signer,
            require_signature,
            symmetric,
            force,
        }) => cli::cmd_decrypt_workflow(
            input,
            private_key.as_deref(),
            output.as_deref(),
            signer.as_deref(),
            *require_signature,
            *symmetric,
            *force,
        ),
    }
}
