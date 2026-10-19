---
name: encrypt
description: >-
  Use this skill when the user wants to encrypt a file interactively using YaCrypt,
  either by generating a new Ed25519/X25519 keypair or reusing an existing X25519 public key.
---

# Interactive File Encryption Workflow (`encrypt`)

Guide the user through encrypting a file with `yacrypt`:

1. **Gather Parameters**:
   - Ask for the input file path to encrypt.
   - Determine which encryption mode the user wants:
     - **New keypair**: Ask for `name` (key owner metadata) and optional `email` (defaults to `secure@example.com`).
     - **Existing key**: Ask for the X25519 public key file path (`--key`, or inspect local keys with `cargo run -- key-list`) and optional signing key (`--sign-key`).
     - **Symmetric password-only (`-c / --symmetric`)**: No public/private keys needed; encrypts directly into `<input>.enc` (`SGPGv1`).
2. **Execute Encryption**:
   - With a new keypair:
     ```bash
     cargo run -- encrypt <input_file> <name> [email]
     ```
   - With an existing X25519 public key:
     ```bash
     cargo run -- encrypt <input_file> --key <public_key_path> [--sign-key <signing_key_path>]
     ```
   - With symmetric password-only mode:
     ```bash
     cargo run -- encrypt <input_file> -c
     ```
3. **Confirm Output**:
   - Verify the `.pubenc` or `.enc` encrypted output file and `keystore/` files (if newly generated).
   - Provide the exact `decrypt` command the recipient will need to decrypt the file.
