---
name: check
description: >-
  Use this skill when the user asks to run the pre-commit quality gate, verify code quality,
  or check formatting, clippy lints, unit tests, and cargo-deny audits before committing.
---

# Pre-Commit Quality Gate (`check`)

Run the full pre-commit quality gate in strict sequence:

1. **Formatting Check**:
   ```bash
   cargo fmt -- --check
   ```
2. **Clippy Lint Check**:
   ```bash
   cargo clippy --all-targets -- -D warnings
   ```
3. **Test Suite**:
   ```bash
   cargo test
   ```
4. **Dependency & Vulnerability Audit**:
   ```bash
   cargo deny check
   ```
   If `cargo-deny` is missing (`cargo deny` → `no such command`), install it with `cargo install cargo-deny --locked`, or run `make security`, which auto-installs it before checking.

## Validation Rules
- Execute each step sequentially.
- If any step fails, immediately report the error output and stop. Do not proceed to the next step until the failure is resolved.
