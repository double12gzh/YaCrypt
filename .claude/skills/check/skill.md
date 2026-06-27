---
name: check
description: Run full pre-commit quality check (fmt + clippy + test + deny)
---
Run the full pre-commit quality gate in sequence:
1. `cargo fmt -- --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. `cargo deny check`

If any step fails, report the error and stop. Do not proceed to the next step on failure.
