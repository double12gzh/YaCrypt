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

# 创建 git hooks
echo "Setting up git hooks..."
if [ -d .git ]; then
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
set -e
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test --locked
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
fi
EOF
    chmod +x .git/hooks/pre-commit
    echo "✅ Git hooks configured"
fi

echo "Development environment ready!"