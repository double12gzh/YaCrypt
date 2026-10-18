# YaCrypt

[ZH](README.md)|[EN](README_EN.md)

## Introduction

`YaCrypt` is a secure file encryption/decryption CLI tool built with modern cryptographic primitives.

**Tech Stack:**
- **Key Derivation**: Argon2id (GPU/ASIC resistant)
- **Symmetric Encryption**: XChaCha20-Poly1305 (AEAD, 24-byte nonce)
- **Key Exchange**: X25519 ECDH + HKDF-SHA256
- **Digital Signature**: Ed25519
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

## Quick Start: Encrypt → Decrypt Complete Workflow

Below is the most common end-to-end usage flow.

### Step 1: Encrypt a File

```bash
yacrypt encrypt secret.txt "Alice" "alice@example.com"
```

Example output:
```
🔐 Step 1/2: Generating keypair and encrypting keys...
? Auto-generate backup encryption password? (y/N) › no
? Enter backup encryption password › (input hidden)
? Confirm password › (input hidden)
👤 Key owner: Alice <alice@example.com> (not stored in any file — keep your own record)
✅ Keys generated and encrypted. Fingerprint: A1B2C3D4...
🔐 Step 2/2: Signing and encrypting file...
✅ File encrypted with public key: secret.pubenc
✅ Complete encryption workflow finished!

📦 Generated files:
   - Encrypted file:       secret.pubenc
   - Public key:           keystore/x25519_public_A1B2C3D4.asc
   - Encrypted private key: keystore/x25519_private_A1B2C3D4.asc.enc
   - Fingerprint:          A1B2C3D4...

📋 To decrypt this file, run:
   yacrypt decrypt secret.pubenc \
       --private-key keystore/x25519_private_A1B2C3D4.asc.enc

⚠️  Keep your encryption password safe! It is required for decryption.
```

### Step 2: Decrypt the File

Copy the command from the previous step's output:

```bash
yacrypt decrypt secret.pubenc \
    --private-key keystore/x25519_private_A1B2C3D4.asc.enc
```

Enter the backup password generated (or set) during encryption to decrypt and automatically verify the Ed25519 signature and signer fingerprint prior to writing to disk.

---

## All Commands

### 1. `encrypt` — Encrypt a File (Recommended)

One-click: Generate keypair → Encrypt keys → Sign → Encrypt file:

```bash
yacrypt encrypt <file> [name] [email] [--output <out>] [--force]
```

Encrypt with an existing key (skip key generation, optionally sign with `--sign-key`):

```bash
yacrypt encrypt <file> --key keystore/x25519_public_<fingerprint>.asc [--sign-key keystore/private_<signer_fp>.asc.enc] [--force]
```

### 2. `decrypt` — Decrypt a File (Recommended)

Decrypt key → Decrypt file → Verify signature & signer fingerprint trust anchor:

```bash
yacrypt decrypt <file.pubenc> \
    --private-key <x25519_private_*.asc.enc> \
    [--signer <64-hex-fingerprint-or-public_fp.asc>] \
    [--require-signature] \
    [--output <out>] \
    [--force]
```

### 3. `gen-keypair` — Generate Keypair

```bash
yacrypt gen-keypair "Your Name" "your.email@example.com"
```

Generated files:

| File | Description |
|------|-------------|
| `keystore/public_<fp>.asc` | Ed25519 public key (for signature verification) |
| `keystore/x25519_public_<fp>.asc` | X25519 public key (for encryption) |
| `keystore/private_<fp>.asc.enc` | Encrypted Ed25519 private key |
| `keystore/x25519_private_<fp>.asc.enc` | Encrypted X25519 private key |
| `keystore/recovery_instructions_<fp>.txt` | Recovery instructions (with decryption commands) |

### 4. `gen-password` — Generate Strong Password

```bash
yacrypt gen-password [--length 32]
```

Generate a random password of specified length (default 32 characters) using rejection sampling to eliminate modulo bias.

### 5. `encrypt-file-with-key` — Encrypt with Existing Public Key

```bash
yacrypt encrypt-file-with-key \
    --input document.txt \
    --public-key keystore/x25519_public_<fp>.asc \
    [--sign-key keystore/private_<signer_fp>.asc.enc] \
    [--output document.pubenc] \
    [--force]
```

### 6. `decrypt-private-key` — Export Raw Ed25519 Private Key

```bash
yacrypt decrypt-private-key keystore/private_<fp>.asc.enc [-o output.der] [--force]
```

---

## Security Design

- Encrypted files (`.pubenc`) and encrypted key backups (`.asc.enc`) contain distinct magic headers + version numbers to prevent format confusion
- The AAD binds only protocol-critical fields (`flags`, ephemeral public key `ephemeral_pub`, signing public key `sig_vk`, key fingerprint `fp`, key `type`); any header tampering or signature stripping causes AEAD authentication failure. The AAD carries no filename/identity metadata (not even low-entropy digests, which are dictionary-recoverable — removed entirely in the 2026-10-18 review closure)
- Ed25519 signature verification and signer fingerprint trust anchor matching are performed **before** writing the file; output is rejected if verification fails or the signer is untrusted
- All sensitive memory is zeroized immediately after use
- Output and private key files are written using `create_new` + `O_NOFOLLOW` + `0o600` permissions by default, refusing to follow symlinks, write to non-regular files, or silently overwrite existing files
- When receiving files over untrusted channels, prefer `--require-signature` together with `--signer <fingerprint>` to pin the expected signer
