---
name: decrypt
description: Interactive file decryption workflow with signature verification
---
Guide the user through decrypting a file:

1. Ask for: input encrypted file path (.pubenc), encrypted X25519 private key path
2. Run: `cargo run -- decrypt <input> --private-key <private_key_path>`
3. Tell the user they will be prompted for their encryption password
4. After success, confirm the decrypted output path
