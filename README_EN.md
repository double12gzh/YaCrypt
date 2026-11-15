# YaCrypt

[ZH](README.md)|[EN](README_EN.md)

## Introduction

`YaCrypt` is a secure file encryption/decryption CLI tool and interactive terminal workbench (TUI) built with modern cryptographic primitives, structured as a `yacrypt-core` (pure data-driven cryptographic library) + `yacrypt` (CLI & Ratatui TUI dual frontend) Cargo workspace.

**Tech Stack:**
- **Key Derivation**: Argon2id (GPU/ASIC resistant)
- **Symmetric Encryption**: XChaCha20-Poly1305 (AEAD, 24-byte nonce)
- **Key Exchange**: X25519 ECDH + HKDF-SHA256
- **Digital Signature**: Ed25519
- **Interactive Frontends**: Clap CLI + Ratatui / Crossterm TUI
- **Memory Protection**: zeroize + mlockall (Linux)

## Requirements

- Rust 1.70+ (Edition 2021)
- Linux / macOS

## Installation

### Build from Source

```bash
git clone https://github.com/double12gzh/YaCrypt.git
cd YaCrypt
cargo build --release

# Binary located at
target/release/yacrypt
```

### Install to System Path (Optional)

```bash
cargo install --path .
```

---

## Interactive TUI Workbench (4-in-1)

Run `yacrypt` without arguments (or `yacrypt tui`) to launch the full-screen interactive terminal workbench:

```bash
yacrypt
# or
yacrypt tui
```

Includes 4 integrated views and global shortcuts (switch views with `1`-`4` or `Tab` / `Shift+Tab`, press `?` / `F1` to open the built-in File Guide explaining every file's role, audience, secrecy level, and cross-machine usage, press `Shift+L` / `F2` to toggle **English / 中文** live with preference persisted, quit safely and zeroize password buffers with `q` / `Ctrl+C`, close modals or exit edit mode with `Esc`):
- **`[1] Keyring`**: Automatically scans `keystore/`, displaying all keypair fingerprints, local labels, and Ed25519/X25519 file completeness with **inline role & secrecy annotations**; press `n` / `Enter` to generate a new keypair in a modal, `l` to set/clear a local key label, `p` to rotate the local private keypair backup password, or `r` to refresh.
- **`[2] Encrypt`**: Supports **generating a new keypair & signing**, **encrypting with an existing public key (optional signing)**, and **symmetric password-only encryption (`.enc` / `SGPGv2`)**; fresh `.pubenc` (`SCFv2`) and `.enc` (`SGPGv2`) ciphertexts conceal signatures inside AEAD and apply length-hiding padding by default; displays a centered completion summary dialog upon finishing (showing output file, signature/key fingerprint, and secrecy/cross-machine guidance); press `f` / `Ctrl+O` on path fields to open the built-in File Browser modal, or `Tab` while editing for path auto-completion.
- **`[3] Decrypt & Verify`**: Automatically inspects `.pubenc` (`SCFv2` / legacy `SCFv1`) or `.enc` (`SGPGv2` / legacy `SGPGv1`) headers without a password as you type or select via `f` / `Ctrl+O`, cross-references local `keystore/` and pins explicit signer trust anchors (never blindly trusting unauthenticated headers to alter key selection), enforces signature verification prior to writing output, and displays a centered completion & verification summary dialog.
- **`[4] Password Gen`**: Adjust password length in real time (`←` / `→`) and press `Enter` / `g` to generate rejection-sampled high-entropy passwords without modulo bias.

---

## Quick Start: Encrypt → Decrypt Complete Workflow

Below is the most common end-to-end usage flow.

### Step 1: Encrypt a File

```bash
yacrypt encrypt secret.txt --label alice
```

Example output (anonymous output name to hide original filename, skips `.decrypt.txt` by default, and defaults to auto-generating a high-entropy backup password):
```
🔐 Step 1/2: Generating keypair and encrypting keys...
? Auto-generate backup encryption password? (Y/n) › yes
✅ Backup password generated:
   ...
🏷️  Local key label: [alice] (stored only in local 0600 keystore index)
✅ Keys generated and encrypted. Fingerprint: A1B2C3D4...
🔐 Step 2/2: Signing and encrypting file...
✅ File encrypted with public key: 8f3a1c90e4b27d15.pubenc
✅ Complete encryption workflow finished!

📦 Generated files:
   - Encrypted file:        8f3a1c90e4b27d15.pubenc
   - Public key:            ~/.yacrypt/keystore/x25519_public_A1B2C3D4....asc
   - Encrypted private key: ~/.yacrypt/keystore/x25519_private_A1B2C3D4....asc.enc
   - Fingerprint:           A1B2C3D4...

📋 To decrypt this file, run:
   yacrypt decrypt 8f3a1c90e4b27d15.pubenc \
       --private-key ~/.yacrypt/keystore/x25519_private_A1B2C3D4....asc.enc

⚠️  Keep your encryption password safe! It is required for decryption.
```

### Step 2: Decrypt the File

Decrypt using the local label (or private key path / `>=16`-char fingerprint prefix) and specify `-o` to restore `secret.txt`:

```bash
yacrypt decrypt 8f3a1c90e4b27d15.pubenc --private-key alice -o secret.txt
```

Enter the backup password set during encryption to decrypt and automatically enforce & verify the Ed25519 signature and signer fingerprint prior to writing `secret.txt` to disk.

---

## All Commands

> Supports global `--keystore-dir <DIR>` and `YACRYPT_KEYSTORE` (prioritizing an existing `./keystore` in CWD for backward compatibility, otherwise defaulting to `0700` `~/.yacrypt/keystore`).

### 1. `tui` (or run with no arguments) — Launch Interactive Terminal Workbench

```bash
yacrypt
# or
yacrypt tui
```

### 2. `encrypt` — Encrypt a File (Recommended)

One-click: Generate keypair → Encrypt keys → Sign → Encrypt file (outputs anonymous `<16hex>.pubenc` and skips `.decrypt.txt` by default):

```bash
yacrypt encrypt <file> [--label <alias>] [--output <out>] [--instructions] [--force]
```

Encrypt with an existing recipient key or local label (optionally sign with your own `--sign-key`):

```bash
yacrypt encrypt <file> --key <x25519_public.asc | label | fp_prefix> [--sign-key <private.asc.enc | label | fp_prefix>] [--output <out>] [--instructions] [--force]
```

Encrypt directly with a password in symmetric mode (`SGPGv2` padded format, no public/private keys needed, outputs anonymous `<16hex>.enc` by default):

```bash
yacrypt encrypt <file> -c [--output <out.enc>] [--force]
```

### 3. `decrypt` — Decrypt a File (Recommended)

Decrypt hybrid public-key encrypted file (`.pubenc`: supports `SCFv2` & legacy `SCFv1`; requires valid Ed25519 signature by default unless `--allow-unsigned` is passed):

```bash
yacrypt decrypt <file.pubenc> \
    --private-key <x25519_private_*.asc.enc | label | fp_prefix> \
    [--signer <64-hex-fingerprint | label | public_fp.asc>] \
    [--allow-unsigned] \
    [--output <out>] \
    [--force]
```

Decrypt symmetric password-encrypted file (`.enc`: auto-detects `SGPGv2` and legacy `SGPGv1` headers without `--private-key`):

```bash
yacrypt decrypt <file.enc> [-o <out>] [--force]
```

### 4. `inspect` — Inspect Encrypted File or Key Backup Without a Password

Inspect `.pubenc` (`SCFv2`/`SCFv1`) or `.enc` / `.asc.enc` (`SGPGv2`/`SGPGv1`) header metadata, algorithm suite, padding status, Argon2id parameters, and legacy `SCFv1` embedded signer fingerprint (`SCFv2` signatures are concealed inside AEAD) without a password, cross-referencing local `keystore/`:

```bash
yacrypt inspect <file.pubenc | file.enc | keystore/private_*.asc.enc>
```

### 5. `key-list` (alias `keys`) — List Local Keyring

Scan and display all keypair fingerprints, local labels, and Ed25519 / X25519 key file statuses in `keystore/`:

```bash
yacrypt key-list
# or
yacrypt keys
```

### 6. `gen-keypair` — Generate Keypair

```bash
yacrypt gen-keypair [--label <alias>]
```

Generated files:

| File | Description |
|------|-------------|
| `keystore/public_<fp>.asc` | Ed25519 public key (for signature verification) |
| `keystore/x25519_public_<fp>.asc` | X25519 public key (for encryption) |
| `keystore/private_<fp>.asc.enc` | Encrypted Ed25519 private key |
| `keystore/x25519_private_<fp>.asc.enc` | Encrypted X25519 private key |
| `keystore/recovery_instructions_<fp>.txt` | Recovery instructions (with decryption commands) |
| `keystore/labels.tsv` | Local key label index (written when `--label` is set, `0600` permissions, never in ciphertexts) |

### 7. `key-label` — Set or Clear Local Key Label

Set or clear a local key alias stored only in `keystore/labels.tsv` (`0600` permissions, never written into ciphertexts or exported key bundles; `<key>` accepts an existing label, `>=16`-char fingerprint prefix, or key file path):

```bash
yacrypt key-label <key> [label] [--clear]
```

### 8. `key-export` (alias `export-key`) — Export Self-Signed Public Key Bundle

Sign and export a combined Ed25519 + X25519 public key bundle using your local Ed25519 private key (outputs `yacrypt_pubkey_<FP16>.asc` by default; `<key>` accepts a local label, `>=16`-char fingerprint prefix, or key file path, and may be omitted on an interactive TTY to select from your keyring):

```bash
yacrypt key-export <key> [-o <bundle.asc>] [--force]
# or
yacrypt export-key <key> [-o <bundle.asc>] [--force]
```

### 9. `key-import` (alias `import-key`) — Verify and Import Peer Public Key Bundle

Verify the Ed25519 self-signature binding and X25519 low-order point check, then import a peer's public keys into `keystore/` (optionally assigning a local `--label`):

```bash
yacrypt key-import <bundle.asc> [--label <alias>] [--force]
# or
yacrypt import-key <bundle.asc> [--label <alias>] [--force]
```

### 10. `change-key-password` — Rotate Local Private Keypair Password

Synchronously rotate the backup encryption password for both local Ed25519 and X25519 encrypted private keys with fresh random salts and nonces (`[key]` accepts a local label, `>=16`-char fingerprint prefix, or key file path, and may be omitted on an interactive TTY to select from your keyring):

```bash
yacrypt change-key-password [key]
```

### 11. `gen-password` — Generate Strong Password

```bash
yacrypt gen-password [--length 32]
```

Generate a random password of specified length (default 32 characters) using rejection sampling to eliminate modulo bias.

### 12. `encrypt-file-with-key` — Encrypt with Existing Public Key

`--public-key` and `--sign-key` accept key file paths, local labels, or `>=16`-char fingerprint prefixes (outputs `<input>.pubenc` by default):

```bash
yacrypt encrypt-file-with-key \
    --input document.txt \
    --public-key <x25519_public_*.asc | label | fp_prefix> \
    [--sign-key <private_*.asc.enc | label | fp_prefix>] \
    [--output document.txt.pubenc] \
    [--force]
```

### 13. `decrypt-private-key` — Export Raw Ed25519 Private Key

Decrypt a local Ed25519 private key backup and export its PKCS#8 DER file (accepts `.asc.enc` path, local label, or `>=16`-char fingerprint prefix; omit on an interactive TTY to select from your keyring):

```bash
yacrypt decrypt-private-key <keystore/private_<fp>.asc.enc | label | fp_prefix> [-o output.der] [--force]
```

### 14. `completions` — Generate Shell Auto-Completion Script

Print the auto-completion script for your target shell to stdout (`powershell` also accepts alias `pwsh`):

```bash
yacrypt completions <bash|zsh|fish|powershell>
```

---

## Security Design

- Encrypted files (`.pubenc`: `SCFv2`/legacy `SCFv1`) and password-based containers (`.enc` / `.asc.enc`: `SGPGv2`/`SGPGv1`) contain distinct magic headers + version numbers and enforce cryptographic domain separation via the AAD `type` field (`type=file`, `type=ed25519`, `type=x25519`) to prevent format or key-role confusion
- **Offline known-plaintext comparison resistance (`SCFv2`)**: Fresh `.pubenc` files keep Ed25519 signatures enabled by default, but move both signature and verifying key inside the AEAD ciphertext (Sign-then-Encrypt over a transcript bound to `ephemeral_pub || recipient_pub || SHA256(plaintext)`), keeping outer `flags = 0x00` with no plaintext signature or signer fingerprint exposed
- **Length-hiding padding by default**: Both `SCFv2` (`.pubenc`) and `SGPGv2` (`.enc`) apply a minimum size floor + `OsRng` random jitter + Padmé alignment before encryption so exact original plaintext byte counts cannot be inferred from ciphertext size
- The AAD binds only protocol-critical fields (`v`, `ephemeral_pub`, key fingerprint `fp`, payload `type`, plus legacy `SCFv1` `flags`/`sig_vk`); any header tampering causes AEAD authentication failure. The AAD carries no filename/identity metadata (not even low-entropy digests, which are dictionary-recoverable — removed entirely in the 2026-10-18 review closure)
- Ed25519 signature verification and signer fingerprint trust anchor matching are performed **before** writing the file; output is rejected if verification fails or the signer is untrusted
- All sensitive memory is zeroized immediately after use (including TUI password input buffers and temporary CLI passwords)
- Output and private key files are written using `create_new` + `O_NOFOLLOW` + `0o600` permissions by default, refusing to follow symlinks, write to non-regular files, or silently overwrite existing files
- When receiving files over untrusted channels, prefer `--require-signature` together with `--signer <fingerprint | label>` to pin the expected signer
