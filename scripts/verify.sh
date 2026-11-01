#!/usr/bin/env bash
# The single full quality gate. Run from any directory; stop at the first failure.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if (( $# )); then
    echo "Usage: bash scripts/verify.sh (no arguments)" >&2
    exit 2
fi
run() {
    printf '\n>>> %s\n' "$*"
    "$@"
}
run python3 scripts/test_verify.py
run python3 scripts/test_agentctl.py
run python3 scripts/test_agy_runner.py
run python3 scripts/test_runtime_adapters.py
run python3 scripts/test_evolution.py
run python3 scripts/test_quality_intake.py
run cargo fmt --all -- --check
run cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
run cargo test --locked --workspace --all-features
run cargo build --locked --workspace --all-features
run cargo deny --locked check
echo 'VERIFY PASS'
