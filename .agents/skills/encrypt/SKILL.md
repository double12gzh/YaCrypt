---
name: encrypt
description: >-
  Use this skill when the user wants to encrypt a file interactively using YaCrypt,
  by generating a new Ed25519/X25519 keypair, reusing an existing X25519 public key,
  or using symmetric password-only (-c / --symmetric) encryption.
---

# Interactive File Encryption Workflow (`encrypt`)

Guide the user through encrypting a file with `yacrypt`:

1. **Gather Parameters**:
   - Ask for the input file path to encrypt.
   - Determine which encryption mode the user wants:
     - **New keypair**: Optional `--label <alias>` (stored only in local `0600` `labels.tsv`, never in ciphertexts).
     - **Existing key**: Ask for the recipient X25519 public key path, local label, or `>=16`-char fingerprint prefix (`--key`, inspectable via `cargo run -- key-list`) and optional own signing key (`--sign-key`).
     - **Symmetric password-only (`-c / --symmetric`)**: No public/private keys needed; encrypts directly into an anonymous `<random>.enc` (`SGPGv2`, padded to hide exact length) unless `-o` is specified.
2. **Execute Encryption**:
   - With a new keypair (outputs anonymous `<random>.pubenc` by default, and skips `.decrypt.txt` for privacy unless `--instructions` is passed):
     ```bash
     cargo run -- encrypt <input_file> [--label <alias>] [-o <output_path>] [--instructions]
     ```
   - With an existing X25519 public key or local label (values optional on an interactive TTY):
     ```bash
     cargo run -- encrypt <input_file> --key [<pubkey_path_or_label>] [--sign-key [<sign_key_path_or_label>]] [-o <output_path>] [--instructions]
     ```
   - With symmetric password-only mode:
     ```bash
     cargo run -- encrypt <input_file> -c [-o <output_path>]
     ```
3. **Confirm Output**:
   - Verify the generated `.pubenc` or `.enc` encrypted output file and keystore files (if newly generated).
   - Provide the exact `decrypt` command (including `-o <original_filename>` when using the anonymous default output name) the recipient will need to decrypt the file.
