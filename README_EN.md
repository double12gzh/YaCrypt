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
Enter backup password: ********
Confirm password: ********
✅ Keys generated and encrypted. Fingerprint: A1B2C3D4...
🔐 Step 2/2: Signing and encrypting file...
✅ Complete encryption workflow finished!

📦 Generated files:
   - Encrypted file:       secret.txt.pubenc
   - Public key:           keystore/x25519_public_A1B2C3D4.asc
   - Encrypted private key: keystore/x25519_private_A1B2C3D4.asc.enc
   - Fingerprint:          A1B2C3D4...

📋 To decrypt this file, run:
   yacrypt decrypt secret.txt.pubenc \
       --private-key keystore/x25519_private_A1B2C3D4.asc.enc

⚠️  Keep your encryption password safe! It is required for decryption.
```

### Step 2: Decrypt the File

Copy the command from the previous step's output:

```bash
yacrypt decrypt secret.txt.pubenc \
    --private-key keystore/x25519_private_A1B2C3D4.asc.enc
```

Enter the password set during encryption to decrypt and automatically verify the signature.

---

## All Commands

### 1. `encrypt` — Encrypt a File (Recommended)

One-click: Generate keypair → Encrypt keys → Sign → Encrypt file:

```bash
yacrypt encrypt <file> <name> [email] [--output <out>]
```

Encrypt with an existing key (skip key generation, no signature):

```bash
yacrypt encrypt <file> --key keystore/x25519_public_<fingerprint>.asc
```

### 2. `decrypt` — Decrypt a File (Recommended)

Decrypt key → Decrypt file → Verify signature:

```bash
yacrypt decrypt <file.pubenc> --private-key <x25519_private_*.asc.enc> [--output <out>]
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

Generate a random password of specified length (default 32 characters), using letters, numbers, and special characters.

### 5. `encrypt-file-with-key` — Encrypt with Existing Public Key

```bash
yacrypt encrypt-file-with-key \
    --input document.txt \
    --public-key keystore/x25519_public_<fp>.asc \
    [--output document.txt.pubenc]
```

### 6. `decrypt-file-with-key` — Decrypt with Existing Private Key

```bash
yacrypt decrypt-file-with-key \
    --input document.txt.pubenc \
    --private-key keystore/x25519_private_<fp>.asc.enc \
    [--output document.txt]
```

### 7. `decrypt-private-key` — Export Raw Private Key

```bash
yacrypt decrypt-private-key keystore/private_<fp>.asc.enc [-o output.der]
```

---

## Security Design

- Encrypted files (`.pubenc`) contain a magic header + version number to prevent format confusion
- Ed25519 signatures are embedded inside the encrypted file, cryptographically bound to the ciphertext
- Signature verification is performed **before** writing the file; output is rejected if verification fails
- All sensitive memory is zeroized immediately after use
- Private key files are written with `0o600` permissions to avoid TOCTOU race conditions
