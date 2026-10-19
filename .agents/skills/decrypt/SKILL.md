---
name: decrypt
description: >-
  Use this skill when the user wants to inspect or decrypt a .pubenc or .enc file using YaCrypt
  and verify its embedded Ed25519 signature.
---

# Interactive File Decryption Workflow (`decrypt`)

Guide the user through inspecting and decrypting a `.pubenc` or `.enc` file:

1. **Inspect Header (Optional / Recommended)**:
   - Run passwordless header inspection first to check container format (`SCFv1` vs `SGPGv1`), signer fingerprint, and matching local keys:
     ```bash
     cargo run -- inspect <encrypted_file>
     ```
2. **Execute Decryption**:
   - For `.pubenc` (`SCFv1` hybrid public-key encrypted file):
     ```bash
     cargo run -- decrypt <input_pubenc_path> --private-key <private_key_path> [--signer <fp_or_pub_path>] [--require-signature]
     ```
   - For `.enc` (`SGPGv1` symmetric password-encrypted file, auto-detected without `--private-key`):
     ```bash
     cargo run -- decrypt <input_enc_path>
     ```
3. **Confirm Output**:
   - Confirm that signature verification (for `.pubenc`) succeeded prior to file write and report the decrypted output file path.
