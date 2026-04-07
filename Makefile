# Makefile for YaCrypt

# Ensure cargo is in PATH
export PATH := $(HOME)/.cargo/bin:$(PATH)

# Project name
PROJECT_NAME = YaCrypt
BINARY = target/release/$(PROJECT_NAME)
BINARY_DEBUG = target/debug/$(PROJECT_NAME)

# Default target
.DEFAULT_GOAL := help

# Build release binary
.PHONY: build release
build: $(BINARY) ## Build release binary
release: $(BINARY) ## Build release binary (alias for build)

$(BINARY):
	@echo "Building release binary..."
	cargo build --release
	@echo "Build complete: $(BINARY)"

# Build debug binary
.PHONY: debug
debug: $(BINARY_DEBUG) ## Build debug binary

$(BINARY_DEBUG):
	@echo "Building debug binary..."
	cargo build
	@echo "Build complete: $(BINARY_DEBUG)"

# Clean build artifacts
.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	@echo "Clean complete"

# Run tests
.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	cargo test
	@echo "Tests complete"

# Check code (no build)
.PHONY: check
check: ## Check code without building
	@echo "Checking code..."
	cargo check
	@echo "Check complete"

# Format code
.PHONY: fmt
fmt: ## Format code
	@echo "Formatting code..."
	cargo fmt
	@echo "Format complete"

# Run clippy lints
.PHONY: clippy
clippy: ## Run clippy lints
	@echo "Running clippy..."
	cargo clippy -- -D warnings
	@echo "Clippy complete"

# Install to system path
.PHONY: install
install: $(BINARY) ## Install to system path
	@echo "Installing to system path..."
	cargo install --path .
	@echo "Install complete"

# Full rebuild (clean + build)
.PHONY: rebuild
rebuild: clean build ## Clean and rebuild

audit:
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "Installing cargo-audit..."; \
		cargo install cargo-audit; \
		cargo audit; \
	fi

.PHONY: security
security: audit ## Security scan
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cargo deny check advisories; \
	else \
		echo "Installing cargo-deny..."; \
		cargo install cargo-deny; \
		cargo deny check advisories; \
	fi

.PHONY: dev
dev: ## Set up development environment
	@echo "Setting up development environment..."
	@sh setup-dev.sh
	@echo "Development environment ready!"

.PHONY: all
all: fmt clippy test security rebuild

# Show help
.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'