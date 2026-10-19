# YaCrypt Inspect, Key-List & Symmetric Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add universal passwordless file inspection (`inspect`), local keyring listing (`key-list` / `keys`), and symmetric password-only file encryption/decryption (`--symmetric` / `-c`) across `yacrypt-core`, CLI, and TUI.

**Architecture:** Extend `yacrypt-core` with `encrypt_file_symmetric` and `decrypt_file_symmetric` (using `SGPGv1` with `type=file` AAD domain separation) and `inspect_file` (detecting both `SCFv1` and `SGPGv1` headers). Expose these capabilities in `src/cli.rs` and `src/tui/`.

**Tech Stack:** Rust 2021, `yacrypt-core`, `clap`, `dialoguer`, `ratatui`, `zeroize`.

---

### Task 1: Add Symmetric File Encryption/Decryption & Universal `inspect_file` to `yacrypt-core`

**Files:**
- Modify: `crates/yacrypt-core/src/file_ops.rs`
- Modify: `crates/yacrypt-core/src/workflow.rs`

- [ ] **Step 1: Implement `encrypt_file_symmetric` and `decrypt_file_symmetric` in `crates/yacrypt-core/src/file_ops.rs` with unit tests**
- [ ] **Step 2: Implement `SgpgInfo`, `InspectedFile`, and `inspect_file` in `crates/yacrypt-core/src/workflow.rs` with unit tests**
- [ ] **Step 3: Run `cargo test -p yacrypt-core` and commit**

---

### Task 2: Expose `inspect`, `key-list`, and `--symmetric (-c)` in CLI & TUI

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `src/tui/app.rs`
- Modify: `src/tui/ui.rs`
- Modify: `tests/cli_e2e.rs`

- [ ] **Step 1: Update `src/cli.rs` and `src/main.rs` to add `Inspect`, `KeyList`, and `--symmetric (-c)` support**
- [ ] **Step 2: Update `src/tui/app.rs` and `src/tui/ui.rs` to support symmetric mode and universal `inspect_file` preview**
- [ ] **Step 3: Add CLI E2E tests in `tests/cli_e2e.rs` for `inspect`, `key-list`, and `--symmetric` roundtrip & domain separation**
- [ ] **Step 4: Run full quality gate (`cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`) and commit**
