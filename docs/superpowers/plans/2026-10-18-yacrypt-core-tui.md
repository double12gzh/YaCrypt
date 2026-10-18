# YaCrypt Core Workspace Split & TUI Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split YaCrypt into a Cargo Workspace with a UI-agnostic `crates/yacrypt-core` library crate and a unified `yacrypt` binary crate providing both 100% backward-compatible CLI subcommands and a 4-in-1 Ratatui TUI workbench.

**Architecture:** Root hybrid Cargo Workspace where `crates/yacrypt-core` encapsulates all cryptographic primitives, keystore management (including `scan_keystore`), and file encryption/decryption workflows (including `inspect_pubenc_file`) with zero CLI/TUI dependencies. The root `yacrypt` binary crate depends on `yacrypt-core`, routing CLI subcommands through `clap` + `dialoguer` and launching the Ratatui + Crossterm 4-tab TUI workbench when invoked without arguments or via `yacrypt tui`.

**Tech Stack:** Rust 2021, `argon2`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `sha2`, `zeroize`, `clap` 4.5, `dialoguer` 0.12, `ratatui` 0.29, `crossterm` 0.28.

## Global Constraints

- **Security Invariant 1 (Verify-Before-Write):** Ed25519 signature verification and AAD header integrity checks MUST complete before writing any plaintext bytes to disk.
- **Security Invariant 2 (Zeroize Secrets):** All passwords, private keys, derived keys, shared secrets, and TUI password buffers MUST use `zeroize::Zeroize` or `zeroize::Zeroizing` and be cleared immediately after use or modal dismissal.
- **Security Invariant 3 (Strict Permissions):** Output files and private keys MUST be written with `mode(0o600)`, `O_NOFOLLOW`, and `sync_all()`; keystore directories with `mode(0o700)`.
- **Security Invariant 4 (Argon2 Hard Limits):** Enforce `MIN_ARGON_M_COST_KIB..=MAX_ARGON_M_COST_KIB`, `1..=MAX_ARGON_T_COST`, `1..=MAX_ARGON_P_COST` before Argon2 derivation.
- **Security Invariant 5 (AAD Binding):** Bind identity/file metadata hashes, `ephemeral_pub`, `flags`, and `sig_vk` in AEAD AAD.
- **Security Invariant 6 (Memory Lock):** Call `try_mlockall()` at process startup on Linux.
- **Dependency & License Gate:** Only allow licenses in `deny.toml` (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-3.0`); never run `cargo clean`.
- **Git Commit Convention:** Never use bare `cat`; always use 3 `-m` flags (`<type>(<scope>): <subject>`, bulleted body, and `Co-Authored-By: Gemini <noreply@google.com>`).

---

### Task 1: Create `crates/yacrypt-core` & Migrate Foundation Modules (`constants`, `error`, `crypto`, `password`, `utils`)

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/yacrypt-core/Cargo.toml`
- Create: `crates/yacrypt-core/src/lib.rs`
- Create: `crates/yacrypt-core/src/constants.rs`
- Create: `crates/yacrypt-core/src/error.rs`
- Create: `crates/yacrypt-core/src/crypto.rs`
- Create: `crates/yacrypt-core/src/password.rs`
- Create: `crates/yacrypt-core/src/utils.rs`

**Interfaces:**
- Consumes: Standard cryptographic crates (`argon2`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize`, `hex`, `libc`, `rand`).
- Produces:
  - `yacrypt_core::constants::*`
  - `yacrypt_core::error::CryptError`
  - `yacrypt_core::crypto::{derive_key, pack_encrypted_blob, unpack_encrypted_blob, EncryptedBlob, encrypt_with_aad, decrypt_with_aad, derive_symmetric_key_from_shared_secret, PubencSignature, UnpackedPubenc, pack_pubenc_blob, unpack_pubenc_blob}`
  - `yacrypt_core::password::generate_strong_password(length: usize) -> Result<Zeroizing<String>, CryptError>`
  - `yacrypt_core::utils::{try_mlockall, write_file_strict, write_file_strict_with_options, compute_fingerprint, hash_metadata_field, parse_aad_map, escape_aad_field, validate_password_length}`

- [ ] **Step 1: Configure root `Cargo.toml` workspace and create `crates/yacrypt-core/Cargo.toml`**

Update root `Cargo.toml` to register `[workspace] members = ["crates/yacrypt-core"]` and add `yacrypt-core = { path = "crates/yacrypt-core" }`:

```toml
[workspace]
members = ["crates/yacrypt-core"]

[package]
name = "yacrypt"
version = "0.0.1"
edition = "2021"
authors = ["double12gzh"]
license = "MIT"
description = "Secure file encryption/decryption CLI tool using Argon2id, XChaCha20-Poly1305, X25519, and Ed25519."
categories = ["security", "cryptography", "command-line-utilities"]
keywords = ["encryption", "cryptography", "x25519", "ed25519", "xchacha20poly1305"]
repository = "https://github.com/double12gzh/YaCrypt"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"

[dependencies]
yacrypt-core = { path = "crates/yacrypt-core" }
argon2 = "0.5"
base64 = "0.22"
chacha20poly1305 = "0.10"
clap = { version = "4.5", features = ["derive"] }
crossterm = "0.28"
dialoguer = "0.12.0"
ed25519-dalek = { version = "2.1", features = ["pkcs8", "zeroize"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
hex = "0.4"
hkdf = "0.12"
libc = "0.2"
pkcs8 = { version = "0.10", features = ["alloc"] }
rand = "0.8.0"
ratatui = { version = "0.29", default-features = false, features = ["crossterm"] }
sha2 = "0.10"
zeroize = { version = "1.7", features = ["zeroize_derive"] }

[features]
default = []

[lints.clippy]
# 允许的 clippy 检查
module_inception = "allow"
new_without_default = "allow"
```

Create `crates/yacrypt-core/Cargo.toml`:

```toml
[package]
name = "yacrypt-core"
version = "0.0.1"
edition = "2021"
authors = ["double12gzh"]
license = "MIT"
description = "Core cryptographic primitives, keystore management, and encryption workflows for YaCrypt."

[dependencies]
argon2 = "0.5"
base64 = "0.22"
chacha20poly1305 = "0.10"
ed25519-dalek = { version = "2.1", features = ["pkcs8", "zeroize"] }
hex = "0.4"
hkdf = "0.12"
libc = "0.2"
pkcs8 = { version = "0.10", features = ["alloc"] }
rand = "0.8.0"
sha2 = "0.10"
x25519-dalek = { version = "2", features = ["static_secrets"] }
zeroize = { version = "1.7", features = ["zeroize_derive"] }

[lints.clippy]
module_inception = "allow"
new_without_default = "allow"
```

- [ ] **Step 2: Create `constants.rs`, `error.rs`, `crypto.rs`, `password.rs`, `utils.rs`, and `lib.rs` in `crates/yacrypt-core/src/`**

Create `crates/yacrypt-core/src/constants.rs` (migrated verbatim from `src/constants.rs`), `crates/yacrypt-core/src/error.rs` (migrated from `src/error.rs`), and `crates/yacrypt-core/src/crypto.rs` (migrated verbatim from `src/crypto.rs`).

Create `crates/yacrypt-core/src/password.rs` with pure data-driven `generate_strong_password`:

```rust
/// 密码生成模块
use crate::error::CryptError;
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// 可用于密码的字符集（字母、数字、特殊字符，排除容易混淆的字符）
const PASSWORD_CHARSET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";

/// 生成指定字符长度的强随机密码，使用拒绝采样消除模偏差，并以 Zeroizing<String> 返回
pub fn generate_strong_password(length: usize) -> Result<Zeroizing<String>, CryptError> {
    if length == 0 || length > 4096 {
        return Err(CryptError::Key("password length must be between 1 and 4096".into()));
    }

    let charset_len = PASSWORD_CHARSET.len();
    let mut password = Vec::with_capacity(length);

    for _ in 0..length {
        loop {
            let mut byte = [0u8; 1];
            OsRng.fill_bytes(&mut byte);
            let idx = byte[0] as usize;
            if idx < (256 / charset_len) * charset_len {
                password.push(PASSWORD_CHARSET[idx % charset_len]);
                break;
            }
        }
    }

    match String::from_utf8(password) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err(CryptError::Crypto("Internal error: invalid password bytes".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_length_matches_request() {
        let p = generate_strong_password(32).unwrap();
        assert_eq!(p.len(), 32);
        assert!(p.chars().all(|c| PASSWORD_CHARSET.contains(&(c as u8))));
    }

    #[test]
    fn password_rejects_zero_length() {
        assert!(generate_strong_password(0).is_err());
    }

    #[test]
    fn password_rejects_excessive_length() {
        assert!(generate_strong_password(4097).is_err());
    }
}
```

Create `crates/yacrypt-core/src/utils.rs` (migrated from `src/utils.rs`, replacing `dialoguer::Password` with pure `validate_password_length`):

```rust
/// 工具函数模块
use crate::constants::{MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH};
use crate::error::CryptError;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io, io::Write, path::Path};

/// 校验用户口令长度是否符合安全范围 [MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH]
pub fn validate_password_length(password: &str) -> Result<(), CryptError> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(CryptError::Key(format!(
            "Password too short; must be >= {} chars",
            MIN_PASSWORD_LENGTH
        )));
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(CryptError::Key(format!(
            "Password too long; must be <= {} chars",
            MAX_PASSWORD_LENGTH
        )));
    }
    Ok(())
}
```
(Along with `try_mlockall`, `write_file_strict`, `write_file_strict_with_options`, `compute_fingerprint`, `hash_metadata_field`, `parse_aad_map`, `escape_aad_field`, and all existing unit tests).

Create `crates/yacrypt-core/src/lib.rs`:

```rust
pub mod constants;
pub mod crypto;
pub mod error;
pub mod password;
pub mod utils;
```

- [ ] **Step 3: Run `cargo test -p yacrypt-core` to verify all foundation tests pass**

Run: `cargo test -p yacrypt-core`
Expected: PASS (all `crypto`, `password`, and `utils` tests pass).

- [ ] **Step 4: Commit Task 1**

```bash
git add Cargo.toml Cargo.lock crates/yacrypt-core/
git commit -m "refactor(crypto): extract yacrypt-core workspace crate with foundation modules" \
  -m "- Configure root hybrid Cargo workspace with crates/yacrypt-core member
- Migrate constants, error, crypto, password, and utils into yacrypt-core without UI dependencies
- Expose generate_strong_password returning Zeroizing<String> and validate_password_length" \
  -m "Co-Authored-By: Gemini <noreply@google.com>"
```

---

### Task 2: Migrate & Extend `keystore`, `file_ops`, and `workflow` in `crates/yacrypt-core`

**Files:**
- Create: `crates/yacrypt-core/src/keystore.rs`
- Create: `crates/yacrypt-core/src/file_ops.rs`
- Create: `crates/yacrypt-core/src/workflow.rs`
- Modify: `crates/yacrypt-core/src/lib.rs`

**Interfaces:**
- Consumes: `yacrypt_core::{constants, crypto, error::CryptError, utils}`
- Produces:
  - `yacrypt_core::keystore::{GeneratedKeys, KeyringEntry, generate_and_store_keys_in_dir, load_signing_key_with_password, decrypt_backup_with_password, scan_keystore}`
  - `yacrypt_core::file_ops::encrypt_file_with_key`
  - `yacrypt_core::workflow::{PubencInfo, EncryptOutcome, DecryptOutcome, inspect_pubenc_file, resolve_signer_fingerprint, verify_pubenc_aad_and_signature, encrypt_workflow_with_existing_key, encrypt_workflow_with_new_keys, decrypt_workflow_with_password}`

- [ ] **Step 1: Create `crates/yacrypt-core/src/keystore.rs` with `scan_keystore` and pure password inputs**

Implement `generate_and_store_keys_in_dir(keystore_dir: &Path, name: &str, email: &str, password: Option<&str>) -> Result<GeneratedKeys, CryptError>`, `load_signing_key_with_password(enc_path: &Path, password: &str) -> Result<SigningKey, CryptError>`, `decrypt_backup_with_password(enc_path: &Path, password: &str, out: Option<&Path>, force: bool) -> Result<PathBuf, CryptError>`, and `scan_keystore(keystore_dir: &Path) -> Result<Vec<KeyringEntry>, CryptError>` along with unit tests testing key generation, `scan_keystore` metadata extraction, and backup decryption roundtrips.

- [ ] **Step 2: Create `crates/yacrypt-core/src/file_ops.rs` and `crates/yacrypt-core/src/workflow.rs`**

Implement `encrypt_file_with_key` in `file_ops.rs`, and `inspect_pubenc_file`, `resolve_signer_fingerprint`, `verify_pubenc_aad_and_signature`, `encrypt_workflow_with_existing_key`, `encrypt_workflow_with_new_keys`, and `decrypt_workflow_with_password` in `workflow.rs`, plus unit tests for `inspect_pubenc_file` and full E2E encrypt/decrypt workflows.

- [ ] **Step 3: Export `keystore`, `file_ops`, and `workflow` in `crates/yacrypt-core/src/lib.rs` and run tests**

Run: `cargo test -p yacrypt-core`
Expected: PASS (all unit and E2E workflow tests in `yacrypt-core` pass).

- [ ] **Step 4: Commit Task 2**

```bash
git add crates/yacrypt-core/
git commit -m "feat(keystore): add pure workflow APIs, scan_keystore, and inspect_pubenc_file to yacrypt-core" \
  -m "- Migrate keystore, file_ops, and workflow logic into yacrypt-core with explicit password parameters
- Add scan_keystore to discover and aggregate local Ed25519/X25519 keypairs by fingerprint
- Add inspect_pubenc_file for passwordless SCFv1 header and signer fingerprint inspection" \
  -m "Co-Authored-By: Gemini <noreply@google.com>"
```

---

### Task 3: Rewire Root CLI (`src/cli.rs`, `src/main.rs`) & Add TUI Routing

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `src/tui/mod.rs` (initial stub for Task 3 compilation, completed in Task 4)
- Delete: `src/constants.rs`, `src/crypto.rs`, `src/error.rs`, `src/file_ops.rs`, `src/keystore.rs`, `src/password.rs`, `src/utils.rs`, `src/workflow.rs`

**Interfaces:**
- Consumes: `yacrypt_core::*`
- Produces:
  - `Cli { command: Option<Commands> }` with `Commands::Tui` and all 6 existing subcommands
  - CLI interactive wrappers (`prompt_password`, `prompt_password_confirm`, `Confirm`) in `src/cli.rs`

- [ ] **Step 1: Update `src/cli.rs` and `src/main.rs` to delegate to `yacrypt_core` and remove duplicated `src/*.rs` modules**

Update `src/cli.rs` to hold `pub command: Option<Commands>`, `Commands::Tui`, and the CLI interactive command handlers (`run_cli_command`) that prompt via `dialoguer` and print identical status messages to stdout. Remove the migrated core files from root `src/`.

- [ ] **Step 2: Run `cargo test` and verify CLI compilation**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 3: Commit Task 3**

```bash
git add -A src/
git commit -m "refactor(cli): rewire CLI subcommands to yacrypt-core and add TUI routing" \
  -m "- Delegate all 6 existing CLI subcommands to yacrypt-core while preserving terminal prompts and output
- Make CLI subcommand optional so running yacrypt without arguments or with 'yacrypt tui' launches TUI
- Remove duplicated core modules from root binary package" \
  -m "Co-Authored-By: Gemini <noreply@google.com>"
```

---

### Task 4: Implement 4-in-1 Ratatui TUI Workbench (`src/tui/`)

**Files:**
- Modify: `src/tui/mod.rs`
- Create: `src/tui/app.rs`
- Create: `src/tui/ui.rs`

**Interfaces:**
- Consumes: `yacrypt_core::{keystore::*, file_ops::*, workflow::*, password::*, utils::*}`, `ratatui`, `crossterm`, `zeroize::Zeroizing`
- Produces:
  - `tui::run() -> Result<(), Box<dyn std::error::Error>>`
  - `TuiApp` state machine supporting 4 tabs (`Keyring`, `Encrypt`, `Decrypt`, `Password`), modal dialogs (`NewKeypair`, `PasswordPrompt`, `GeneratedPasswordDisplay`), `Zeroizing<String>` secret buffers, and headless rendering tests.

- [ ] **Step 1: Implement `src/tui/app.rs` with 4-tab state machine, `Zeroizing` secret buffers, and unit tests**

Include state & event handling for:
- Tab switching (`1`-`4`, `Tab`, `BackTab`)
- Keyring tab: scanning `keystore/`, selecting entries, opening `NewKeypair` modal, generating keypairs, displaying auto-generated passwords in a `Zeroizing<String>` modal that zeroizes on close.
- Encrypt tab: editing input/output paths, cycling recipient keys or `<Generate New Keypair>`, toggling signature & force flags, prompting for password when needed, calling `yacrypt_core`.
- Decrypt tab: editing `.pubenc` input path with live `inspect_pubenc_file` preview, auto-selecting matching local private key when signer fingerprint matches, prompting for password in a `Zeroizing<String>` modal, calling `decrypt_workflow_with_password`, and displaying signature verification result.
- Password tab: adjusting length, generating new password into `Zeroizing<String>`, toggling mask/reveal (`*` vs plaintext), and zeroizing on tab switch or quit.

- [ ] **Step 2: Implement `src/tui/ui.rs` and `src/tui/mod.rs` with Ratatui rendering and panic-safe terminal restoration**

Render the header tabs, the 4 tab bodies, the status bar, and centered modal overlays. Install a panic hook in `src/tui/mod.rs` that restores terminal raw mode and alternate screen before propagating any panic.

- [ ] **Step 3: Run `cargo test --workspace` including TUI state machine and `TestBackend` rendering tests**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 4: Commit Task 4**

```bash
git add src/tui/
git commit -m "feat(cli): implement 4-in-1 Ratatui TUI workbench prototype" \
  -m "- Add Keyring, Encrypt, Decrypt & Verify, and Password Generator tabs in src/tui/
- Enforce Zeroizing<String> for all TUI password inputs and generated secret buffers
- Add panic recovery hook for terminal raw mode and unit tests using Ratatui TestBackend" \
  -m "Co-Authored-By: Gemini <noreply@google.com>"
```

---

### Task 5: Run Full Pre-Commit Quality Gate (`/check`)

**Files:**
- Verify all workspace crates (`yacrypt` and `yacrypt-core`)

- [ ] **Step 1: Execute formatting, clippy, unit tests, and cargo-deny checks**

Run:
```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo deny check
```
Expected: All 4 checks pass with 0 warnings and 0 errors.
