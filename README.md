# YaCrypt

Ultra-secure encryption/decryption tool built with Rust. Features zero secret leakage through memory locking, zeroization, and strict file permissions.

## Features

- **Ed25519** signing keypair (PKCS#8 private key storage)
- **X25519** encryption keypair (hybrid encryption)
- **Argon2id** key derivation with configurable parameters
- **XChaCha20-Poly1305** AEAD encryption with 24-byte nonce
- **HKDF** with salt for key independence (SGPGv2 format)
- **Memory protection** via `mlockall` (Linux)
- **Strict file permissions** (0o600) with TOCTOU-safe creation
- **Zeroize** all secrets after use
- **AAD** (Additional Authenticated Data) stored in blob header
- **Digital signatures** with Ed25519 for file integrity verification

## Requirements

- Rust 1.70+ (Edition 2021)
- Linux / macOS

## Installation

### Build from source

```bash
git clone https://github.com/double12gzh/YaCrypt.git
cd YaCrypt

# Build release binary
cargo build --release

# Binary located at:
target/release/YaCrypt
```

### Install to system path (optional)

```bash
cargo install --path .
```

### Using Makefile

```bash
make build      # Build release binary
make test       # Run tests
make clippy     # Run lints
make security   # Run security audit
make all        # Full pipeline: fmt + clippy + test + security + rebuild
```

## Usage

### 1. Generate Keypair

Generate Ed25519 (signing) + X25519 (encryption) keypairs with encrypted private key backup:

```bash
YaCrypt gen-keypair "Your Name" "your.email@example.com"
```

This creates:

| File | Description |
|------|-------------|
| `keystore/public_<fp>.asc` | Ed25519 public key (Base64) |
| `keystore/x25519_public_<fp>.asc` | X25519 public key (Base64) |
| `keystore/private_<fp>.asc.enc` | Encrypted Ed25519 private key |
| `keystore/x25519_private_<fp>.asc.enc` | Encrypted X25519 private key |
| `keystore/recovery_instructions_<fp>.txt` | Recovery instructions |

Use `--keystore-dir` to specify a custom keystore location:

```bash
YaCrypt --keystore-dir /path/to/keystore gen-keypair "Your Name" "email@example.com"
```

### 2. Generate Strong Password

Generate a cryptographically secure password (default 32 bytes, Base64-encoded):

```bash
YaCrypt gen-password [--length 48]
```

### 3. Encrypt a File (Full Workflow)

One command to: generate keypair → encrypt keys → sign file → encrypt file:

```bash
YaCrypt encrypt document.txt "Your Name" "your.email@example.com" [-o output.pubenc]
```

This will:

1. Generate Ed25519 and X25519 keypairs
2. Encrypt private keys with a password and save to keystore
3. Sign the file with Ed25519
4. Encrypt the file with X25519 public key (hybrid: X25519 + XChaCha20-Poly1305)

### 4. Decrypt a File (Full Workflow)

One command to: decrypt key → decrypt file → verify signature:

```bash
YaCrypt decrypt document.txt.pubenc -p keystore/x25519_private_<fp>.asc.enc [-o document.txt]
```

If the signature verification fails, the decrypted file is automatically removed to prevent using tampered data.

### 5. Decrypt Private Key Backup

Decrypt an encrypted private key backup to plaintext DER format:

```bash
YaCrypt decrypt-private-key keystore/private_<fp>.asc.enc [-o private_key.der]
```

## File Format (SGPGv2)

### Encrypted Key Blob

```
MAGIC           6 bytes   "SGPGv2"
mem_kib         4 bytes   Argon2 memory cost (BE)
t_cost          4 bytes   Argon2 time cost (BE)
p_cost          4 bytes   Argon2 parallelism (BE)
salt_len        1 byte
salt            N bytes
nonce_len       1 byte
nonce           N bytes   (24 bytes for XChaCha20)
aad_len         2 bytes   (BE)
aad             N bytes
ciphertext_len  8 bytes   (BE)
ciphertext      N bytes
```

### Encrypted File (`.pubenc`)

```
ephemeral_pub   32 bytes  X25519 ephemeral public key
nonce           24 bytes  XChaCha20 nonce
aad_len         2 bytes   (BE)
aad             N bytes
ciphertext_len  8 bytes   (BE)
ciphertext      N bytes   XChaCha20-Poly1305 AEAD
```

## Security Design

| Feature | Implementation |
|---------|---------------|
| Key derivation | Argon2id (64 MiB, 2 iterations) |
| Symmetric encryption | XChaCha20-Poly1305 (AEAD) |
| Key exchange | X25519 ECDH + HKDF-SHA256 with salt |
| Signing | Ed25519 |
| Memory protection | `mlockall` on Linux |
| Secret cleanup | `zeroize` on all sensitive data |
| File permissions | Atomic 0o600 creation (no TOCTOU) |
| Parameter validation | Argon2 params capped to prevent DoS |
| Low-order point check | X25519 shared secret zero-check |

## License

MIT
