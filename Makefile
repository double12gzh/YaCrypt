# Makefile for YaCrypt

# 确保 cargo 在 PATH 中
export PATH := $(HOME)/.cargo/bin:$(PATH)

# 项目名称
PROJECT_NAME = yacrypt
BINARY = target/release/$(PROJECT_NAME)
BINARY_DEBUG = target/debug/$(PROJECT_NAME)

# 默认目标
.DEFAULT_GOAL := help

# 构建发布版本
.PHONY: build release
build: $(BINARY) ## 构建发布版本
release: $(BINARY) ## 构建发布版本（与 build 相同）

$(BINARY):
	@echo "构建发布版本..."
	cargo build --release
	@echo "构建完成: $(BINARY)"

# 构建调试版本
.PHONY: debug
debug: $(BINARY_DEBUG) ## 构建调试版本

$(BINARY_DEBUG):
	@echo "构建调试版本..."
	cargo build
	@echo "构建完成: $(BINARY_DEBUG)"

# 清理构建产物
.PHONY: clean
clean: ## 清理构建产物
	@echo "清理构建产物..."
	cargo clean
	@echo "清理完成"

# 运行测试
.PHONY: test
test: ## 运行测试
	@echo "运行测试..."
	cargo test
	@echo "测试完成"

# 检查代码（不构建）
.PHONY: check
check: ## 检查代码（不构建）
	@echo "检查代码..."
	cargo check
	@echo "检查完成"

# 代码格式化
.PHONY: fmt
fmt: ## 格式化代码
	@echo "格式化代码..."
	cargo fmt
	@echo "格式化完成"

# 运行 clippy 检查
.PHONY: clippy
clippy: ## 运行 clippy 检查
	@echo "运行 clippy 检查..."
	cargo clippy -- -D warnings
	@echo "clippy 检查完成"

# 安装到系统路径
.PHONY: install
install: $(BINARY) ## 安装到系统路径
	@echo "安装到系统路径..."
	cargo install --path .
	@echo "安装完成"

# 完整构建流程（清理 + 构建）
.PHONY: rebuild
rebuild: clean build ## 清理并重新构建

audit:
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "Installing cargo-audit..."; \
		cargo install cargo-audit; \
		cargo audit; \
	fi

.PHONY: security
security: audit ## 安全扫描
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cargo deny check advisories; \
	else \
		echo "Installing cargo-deny..."; \
		cargo install cargo-deny; \
		cargo deny check advisories; \
	fi

.PHONY: dev
dev: ## 设置开发环境
	@echo "Setting up development environment..."
	@sh setup-dev.sh
	@echo "Development environment ready!"

.PHONY: all
all: fmt clippy test security rebuild

# 显示帮助信息
.PHONY: help
help: ## 显示此帮助信息
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
