# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                    # Debug build
cargo build --release          # Release build (optimized, stripped, panic=abort)
cargo test                     # Run all tests
cargo test crypto::tests::     # Run crypto module tests
cargo test <test_name>         # Run a single test
cargo clippy                   # Lint check
cargo fmt -- --check           # Check formatting
cargo deny check               # License/vulnerability audit
```

`pre-commit` hook runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test`.

## Architecture

### Module Dependency Flow

```
main.rs (dispatch)
  ├── cli.rs        — Clap CLI definition (Commands enum)
  ├── workflow.rs   — High-level encrypt/decrypt orchestrations
  │     ├── file_ops.rs   — X25519-hybrid file encryption + Ed25519 signing
  │     └── keystore.rs   — Keypair generation, encrypted key storage
  ├── crypto.rs     — Core crypto primitives
  ├── password.rs   — Random password generation
  └── utils.rs      — I/O helpers, fingerprint, AAD escaping
```

### Two Encryption Modes

**Password-based** (`SGPGv1` blob): Argon2id KDF → XChaCha20-Poly1305 AEAD. Used to encrypt private keys for storage. Format: MAGIC(6) + Argon2 params(12) + salt + nonce + AAD + ciphertext.

**Public-key-based** (`SCFv1`/`.pubenc` blob): X25519 ECDH + HKDF → XChaCha20-Poly1305 AEAD. Ephemeral key exchange per file, no long-term encryption key stored. Optional Ed25519 signature embedded in blob. Format: MAGIC(5) + flags(1) + [vk(32)+sig(64)] + ephemeral_pub(32) + nonce(24) + AAD + ciphertext.

### Key Generation Flow

`generate_and_store_keys()` creates two keypairs:
- **Ed25519** — for file signing; private key encrypted with password, public key stored as Base64
- **X25519** — for ECDH encryption; private key encrypted with same password, public key stored as Base64

All keys go into `keystore/` directory (mode 0700). Fingerprint = SHA256(Ed25519 pubkey) as uppercase hex.

### Security Invariants

- Signature verification happens **before** writing decrypted output; failure rejects output entirely
- All secret material (`zeroize::Zeroize`) zeroized immediately after use
- File writes use `mode(0o600)` with `sync_all()` to prevent TOCTOU races
- Argon2 params validated against hard caps before use (prevents OOM from malicious blobs)
- AAD (Associated Authenticated Data) binds metadata to ciphertext; mismatch causes AEAD decrypt to fail
- `try_mlockall()` prevents memory swap on Linux

### CLI Entry Points

| Command | Function | Description |
|---------|----------|-------------|
| `encrypt` | `workflow::cmd_encrypt_workflow` | Full: gen keys → encrypt → sign. Or reuse existing key (--key) |
| `decrypt` | `workflow::cmd_decrypt_workflow` | Decrypt key → decrypt file → verify signature |
| `gen-keypair` | `keystore::cmd_generate_protected_key` | Generate Ed25519 + X25519 keypairs |
| `gen-password` | `password::cmd_generate_strong_password` | Random password with rejection sampling |
| `encrypt-file-with-key` | `file_ops::cmd_encrypt_file_with_key` | Encrypt with existing X25519 public key |
| `decrypt-private-key` | `keystore::cmd_decrypt_backup` | Export raw private key DER |