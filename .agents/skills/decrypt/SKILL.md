---
name: decrypt
description: >-
  Use this skill when the user wants to decrypt a .pubenc file using YaCrypt
  and verify its embedded Ed25519 signature.
---

# Interactive File Decryption Workflow (`decrypt`)

Guide the user through decrypting a `.pubenc` file and verifying its signature:

1. **Gather Parameters**:
   - Ask for the encrypted input file path (`.pubenc`).
   - Ask for the password-protected X25519 private key file path (in `keystore/`).
2. **Execute Decryption**:
   - Inform the user they will be prompted interactively for their key protection password.
   - Run:
     ```bash
     cargo run -- decrypt <input_pubenc_path> --private-key <private_key_path>
     ```
3. **Confirm Output**:
   - Confirm that signature verification succeeded prior to file write and report the decrypted output file path.
