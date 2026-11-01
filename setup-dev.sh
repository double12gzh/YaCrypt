#!/bin/bash
# setup-dev.sh - 设置开发环境

set -e

echo "Setting up Rust development environment..."

# 安装开发工具
TOOLS=(
    "cargo-audit"
    "cargo-deny"
    "cargo-outdated"
    "cargo-watch"
    "cargo-expand"
    "cargo-udeps"
    "cargo-bloat"
)

for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Installing $tool..."
        cargo install "$tool" || echo "⚠️ Failed to install $tool"
    else
        echo "✅ $tool already installed"
    fi
done

# Resolve the repository from this script, including when invoked from a worktree.
bash "$(dirname "${BASH_SOURCE[0]}")/scripts/install-hook.sh"

echo "Development environment ready!"
