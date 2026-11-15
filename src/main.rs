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

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use std::{
    io::{self, IsTerminal},
    process::ExitCode,
};
use yacrypt_core::keystore::resolve_keystore_dir;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {}", err);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    yacrypt_core::utils::try_mlockall();

    let cli = Cli::parse();
    let keystore_dir = resolve_keystore_dir(cli.keystore_dir.as_deref());

    match &cli.command {
        None => {
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                let mut cmd = Cli::command();
                cmd.print_help()?;
                println!();
                return Ok(());
            }
            tui::run(keystore_dir)
        }
        Some(Commands::Tui) => {
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                return Err(
                    "Interactive TUI requires a terminal (TTY); run 'yacrypt --help' for CLI subcommands."
                        .into(),
                );
            }
            tui::run(keystore_dir)
        }
        Some(Commands::Inspect { file }) => cli::cmd_inspect_file(file, &keystore_dir),
        Some(Commands::KeyList) => cli::cmd_key_list(&keystore_dir),
        Some(Commands::GenPassword { length }) => cli::cmd_generate_strong_password(*length),
        Some(Commands::GenKeypair { label }) => {
            cli::cmd_generate_protected_key(&keystore_dir, label.as_deref())
        }
        Some(Commands::KeyLabel { key, label, clear }) => {
            cli::cmd_key_label(&keystore_dir, key, label.as_deref(), *clear)
        }
        Some(Commands::KeyExport { key, output, force }) => {
            cli::cmd_key_export(&keystore_dir, key.as_deref(), output.as_deref(), *force)
        }
        Some(Commands::KeyImport { bundle, label, force }) => {
            cli::cmd_key_import(&keystore_dir, bundle, label.as_deref(), *force)
        }
        Some(Commands::ChangeKeyPassword { key }) => {
            cli::cmd_change_key_password(&keystore_dir, key.as_deref())
        }
        Some(Commands::DecryptPrivateKey { enc_path, out, force }) => {
            cli::cmd_decrypt_backup(&keystore_dir, enc_path.as_deref(), out.as_deref(), *force)
        }
        Some(Commands::EncryptFileWithKey { input, public_key, output, sign_key, force }) => {
            cli::cmd_encrypt_file_with_key_cli(
                &keystore_dir,
                input,
                public_key.as_deref(),
                output.as_deref(),
                sign_key.as_deref(),
                *force,
            )
        }
        Some(Commands::Encrypt {
            input,
            output,
            key,
            sign_key,
            label,
            symmetric,
            instructions,
            no_instructions: _,
            force,
        }) => cli::cmd_encrypt_workflow(
            &keystore_dir,
            input,
            output.as_deref(),
            key.as_deref(),
            sign_key.as_deref(),
            label.as_deref(),
            *symmetric,
            *instructions,
            *force,
        ),
        Some(Commands::Decrypt {
            input,
            private_key,
            output,
            signer,
            require_signature,
            allow_unsigned,
            symmetric,
            force,
        }) => cli::cmd_decrypt_workflow(
            &keystore_dir,
            input,
            private_key.as_deref(),
            output.as_deref(),
            signer.as_deref(),
            *require_signature,
            *allow_unsigned,
            *symmetric,
            *force,
        ),
        Some(Commands::Completions { shell }) => cli::cmd_completions(*shell),
    }
}
