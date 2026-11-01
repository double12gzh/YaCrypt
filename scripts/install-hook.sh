#!/usr/bin/env bash
# Install in Git's resolved hooks directory (also works in a linked worktree).
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hook=$(git rev-parse --git-path hooks/pre-commit)
if [[ -e "$hook" || -L "$hook" ]]; then
    if cmp -s .githooks/pre-commit "$hook"; then
        chmod +x "$hook"
        echo "YaCrypt pre-commit hook already installed: $hook"
        exit 0
    fi
    echo "Existing hook preserved: $hook. Migrate it manually to call bash scripts/verify.sh, or use pre-commit with .pre-commit-config.yaml." >&2
    exit 1
fi
mkdir -p "$(dirname "$hook")"
cp .githooks/pre-commit "$hook"
chmod +x "$hook"
echo "Installed YaCrypt pre-commit hook: $hook"
