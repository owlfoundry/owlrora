SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

.PHONY: install
install: ## Install locked dependencies
	@cargo fetch --locked
	@pnpm install --frozen-lockfile

.PHONY: format
format: ## Format all source files
	@cargo fmt --all
	@pnpm format

.PHONY: check
check: web-build ## Run formatting, linting, and static checks
	@cargo fmt --all --check
	@cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	@pnpm check

.PHONY: test
test: web-build ## Run all tests
	@cargo test --workspace --all-features --locked
	@pnpm test

.PHONY: build
build: web-build ## Build the production server
	@cargo build --release --locked --package owlrora-server

.PHONY: package-check
package-check: web-build ## Build and verify the publishable server crate
	@scripts/test-server-package.sh

.PHONY: web-build
web-build: ## Build the embedded frontend
	@pnpm build

.PHONY: web-dev
web-dev: ## Run the Vite development server
	@pnpm dev

.PHONY: dev
dev: web-build ## Build the frontend and run the server
	@cargo run --locked --package owlrora-server

.PHONY: docs
docs: ## Run the documentation development server
	@pnpm docs:dev

.PHONY: docs-build
docs-build: ## Build documentation for deployment
	@pnpm docs:build

.PHONY: docs-deploy
docs-deploy: ## Deploy documentation to Cloudflare Workers
	@pnpm docs:deploy

.PHONY: docker-build
docker-build: ## Build and smoke-test the production image
	@docker build --tag owlrora:dev .
	@scripts/docker/smoke-server-image.sh owlrora:dev

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
