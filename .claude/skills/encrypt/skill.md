---
name: encrypt
description: Interactive file encryption workflow with key generation
---
Guide the user through encrypting a file:

1. Ask for: input file path, name (for key metadata), email (optional, default: secure@example.com)
2. If the user wants to use an existing key, ask for the X25519 public key path
3. Run the appropriate command:
   - With new keypair: `cargo run -- encrypt <input> <name> [email]`
   - With existing key: `cargo run -- encrypt <input> --key <public_key_path>`
4. Confirm the output and show the decryption command the user will need
