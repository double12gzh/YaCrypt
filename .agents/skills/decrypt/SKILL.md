---
name: decrypt
description: >-
  Use this skill when the user wants to inspect or decrypt a .pubenc or .enc file using YaCrypt
  and verify its embedded Ed25519 signature.
---

# Interactive File Decryption Workflow (`decrypt`)

Guide the user through inspecting and decrypting a `.pubenc` or `.enc` file:

1. **Inspect Header (Optional / Recommended)**:
   - Run streaming passwordless header inspection first to check container format (`SCFv2`/`SCFv1` vs `SGPGv2`/`SGPGv1`), payload subtype, padding status, legacy `SCFv1` signer fingerprint (or AEAD-concealed `SCFv2` status), and matching local keys:
     ```bash
     cargo run -- inspect <encrypted_file>
     ```
2. **Execute Decryption**:
   - For `.pubenc` (`SCFv2` / legacy `SCFv1` hybrid public-key encrypted file; `--private-key` is optional on an interactive TTY and accepts `.asc.enc` path, local label, or `>=16`-char fingerprint prefix; `--signer` accepts full 64-hex fingerprint, local label, or `public_<FP>.asc`; valid Ed25519 signatures are required by default unless `--allow-unsigned` is passed):
     ```bash
     cargo run -- decrypt <input_pubenc_path> [--private-key <priv_key_or_label>] [--signer <full_64hex_or_label_or_pub_path>] [-o <output_path>] [--allow-unsigned]
     ```
   - For `.enc` (`SGPGv2` / legacy `SGPGv1` `type=file` symmetric password-encrypted file, auto-detected without `--private-key`; pass `--require-signature` when rejecting unsigned symmetric `.enc` files is desired):
     ```bash
     cargo run -- decrypt <input_enc_path> [-o <output_path>] [--require-signature]
     ```
3. **Confirm Output**:
   - Confirm that signature verification (for `.pubenc`) succeeded prior to file write and report the decrypted output file path.
