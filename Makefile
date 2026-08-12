SHELL := /usr/bin/env bash
DEV_ENV_FILE := $(if $(wildcard dev/.env),--env-file dev/.env,)
DEV_COMPOSE := docker compose $(DEV_ENV_FILE) --file dev/compose.yml
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
build: web-build ## Build the production CLI and server
	@cargo build --release --locked --package owlrora-cli --package owlrora-server

.PHONY: package-check
package-check: web-build ## Build and verify publishable crates and release preparation
	@scripts/test-cli-package.sh
	@scripts/test-server-package.sh
	@python3 scripts/release/test-prepare-release.py

.PHONY: web-build
web-build: ## Build the embedded frontend
	@pnpm build

.PHONY: web-dev
web-dev: ## Run the Vite development server
	@pnpm dev

.PHONY: dev
dev: dev-check web-build ## Start local infrastructure and run the server with the local environment
	@$(DEV_COMPOSE) up --detach --wait
	@set -euo pipefail; \
		for key in $$(env | sed -n 's/^\(OWLRORA_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$$key"; done; \
		set -a; . ./.env; set +a; \
		exec cargo run --locked --package owlrora-server

.PHONY: dev-check
dev-check: ## Check the local application environment and required tools without starting services
	@test -f .env || { echo "Missing .env; run: cp .env.example .env" >&2; exit 1; }
	@bash -n .env
	@set -euo pipefail; \
		template_keys="$$(sed -n 's/^[[:space:]]*\(OWLRORA_[A-Z0-9_]*\)=.*/\1/p' .env.example | sort -u)"; \
		local_keys="$$(sed -n 's/^[[:space:]]*\(OWLRORA_[A-Za-z0-9_]*\)=.*/\1/p' .env | sort -u)"; \
		missing="$$(comm -23 <(printf '%s\n' "$$template_keys") <(printf '%s\n' "$$local_keys"))"; \
		unknown="$$(comm -13 <(printf '%s\n' "$$template_keys") <(printf '%s\n' "$$local_keys"))"; \
		if [[ -n "$$missing" || -n "$$unknown" ]]; then \
			echo "Local .env is out of date with .env.example." >&2; \
			if [[ -n "$$missing" ]]; then printf 'Missing settings:\n%s\n' "$$missing" >&2; fi; \
			if [[ -n "$$unknown" ]]; then printf 'Unknown or obsolete settings:\n%s\n' "$$unknown" >&2; fi; \
			exit 1; \
		fi; \
		for key in $$(env | sed -n 's/^\(OWLRORA_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$$key"; done; \
		set -a; . ./.env; set +a; \
		for key in $$template_keys; do \
			if [[ -z "$${!key:-}" ]]; then echo "Empty setting: $$key" >&2; exit 1; fi; \
		done
	@command -v cargo >/dev/null || { echo "cargo is required; install the pinned Rust toolchain" >&2; exit 1; }
	@command -v pnpm >/dev/null || { echo "pnpm is required; run: make install" >&2; exit 1; }
	@test -d node_modules || { echo "Development dependencies are missing; run: make install" >&2; exit 1; }
	@command -v docker >/dev/null || { echo "Docker with Compose v2 is required by make dev" >&2; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required by make dev" >&2; exit 1; }
	@$(DEV_COMPOSE) config --quiet
	@docker info >/dev/null 2>&1 || { echo "Docker is not running; start Docker Desktop or the Docker daemon" >&2; exit 1; }

.PHONY: dev-up
dev-up: ## Start healthy local PostgreSQL and Redis services
	@$(DEV_COMPOSE) up --detach --wait

.PHONY: dev-down
dev-down: ## Stop local development infrastructure
	@$(DEV_COMPOSE) down --remove-orphans

.PHONY: dev-reset
dev-reset: ## Recreate local infrastructure and remove all local data
	@$(DEV_COMPOSE) down --volumes --remove-orphans
	@$(DEV_COMPOSE) up --detach --wait

.PHONY: dev-logs
dev-logs: ## Follow local infrastructure logs
	@$(DEV_COMPOSE) logs --follow --tail=100

.PHONY: dev-status
dev-status: ## Show local infrastructure status and health
	@$(DEV_COMPOSE) ps

.PHONY: dev-postgres
dev-postgres: ## Open psql in the local PostgreSQL container
	@$(DEV_COMPOSE) exec postgres sh -c 'exec psql --username "$$POSTGRES_USER" --dbname "$$POSTGRES_DB"'

.PHONY: dev-redis
dev-redis: ## Open redis-cli in the local Redis container
	@$(DEV_COMPOSE) exec redis redis-cli

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
