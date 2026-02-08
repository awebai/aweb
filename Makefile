# aweb (Agent Web) - development helpers
#
# This repo uses uv; these targets are convenience wrappers.

.PHONY: help sync serve test conformance fmt lint typecheck check clean \
        dev-backend dev-check dev-setup dev-stop dev-seed

# Default env file (can be overridden)
ENV_FILE ?= .env.dev

# Load env file if it exists
ifneq (,$(wildcard $(ENV_FILE)))
include $(ENV_FILE)
export
endif

# Fallback defaults
AWEB_PORT ?= 8023
POSTGRES_HOST ?= localhost
POSTGRES_PORT ?= 5432
REDIS_PORT ?= 6379
POSTGRES_DB ?= aweb
POSTGRES_APP_USER ?= beadhub
POSTGRES_ADMIN_DB ?= postgres
POSTGRES_ADMIN_URL ?= postgresql://$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_ADMIN_DB)
AWEB_DATABASE_URL ?= postgresql://$(POSTGRES_APP_USER)@localhost:$(POSTGRES_PORT)/$(POSTGRES_DB)
AWEB_REDIS_URL ?= redis://localhost:$(REDIS_PORT)/0

help:
	@echo "aweb Commands:"
	@echo ""
	@echo "  Local Development (uses local postgres/redis via brew services):"
	@echo "    make dev-setup      - Set up local dev environment (postgres database)"
	@echo "    make dev-check      - Verify local dev prerequisites are met"
	@echo "    make dev-backend    - Run backend server on port $(AWEB_PORT)"
	@echo "    make dev-seed       - Seed project + agents for conformance tests"
	@echo "    make dev-stop       - Kill local dev server"
	@echo ""
	@echo "  Testing:"
	@echo "    make test           - Run unit/integration tests"
	@echo "    make conformance    - Run black-box conformance tests (requires AWEB_URL + AWEB_CONFORMANCE=1)"
	@echo ""
	@echo "  Code Quality:"
	@echo "    make fmt            - Format (black + isort)"
	@echo "    make lint           - Lint (ruff)"
	@echo "    make typecheck      - Typecheck (mypy)"
	@echo "    make check          - fmt + lint + typecheck + test"
	@echo ""
	@echo "  Utilities:"
	@echo "    make sync           - Install dependencies (uv sync)"
	@echo "    make serve          - Run aweb server (bare, uses env for DB/Redis)"
	@echo "    make health         - Check API health endpoint"
	@echo "    make clean          - Remove cache directories"
	@echo ""

#
# Local Development
#

dev-backend: dev-check
	@echo ""
	@echo "Starting aweb backend on port $(AWEB_PORT)..."
	@echo "  API:       http://localhost:$(AWEB_PORT)/v1"
	@echo "  Health:    http://localhost:$(AWEB_PORT)/health"
	@echo "  Postgres:  localhost:$(POSTGRES_PORT)/$(POSTGRES_DB) (local)"
	@echo "  Redis:     localhost:$(REDIS_PORT) (local)"
	@echo ""
	AWEB_DATABASE_URL="$(AWEB_DATABASE_URL)" \
	AWEB_REDIS_URL="$(AWEB_REDIS_URL)" \
	uv run aweb serve --host 0.0.0.0 --port $(AWEB_PORT) --reload

dev-check:
	@echo "Checking local dev prerequisites..."
	@FAILED=0; \
	echo ""; \
	echo "  PostgreSQL:"; \
	if pg_isready -q -h $(POSTGRES_HOST) -p $(POSTGRES_PORT) 2>/dev/null; then \
		echo "    [OK] Running on port $(POSTGRES_PORT)"; \
	else \
		echo "    [MISSING] Not running on port $(POSTGRES_PORT)"; \
		echo "             Fix: brew services start postgresql@14"; \
		FAILED=1; \
	fi; \
	echo ""; \
	echo "  Redis:"; \
	if redis-cli -p $(REDIS_PORT) ping >/dev/null 2>&1; then \
		echo "    [OK] Running on port $(REDIS_PORT)"; \
	else \
		echo "    [MISSING] Not running on port $(REDIS_PORT)"; \
		echo "             Fix: brew services start redis"; \
		FAILED=1; \
	fi; \
	echo ""; \
	echo "  PostgreSQL role '$(POSTGRES_APP_USER)':"; \
	if psql "$(POSTGRES_ADMIN_URL)" -tAc "SELECT 1 FROM pg_roles WHERE rolname='$(POSTGRES_APP_USER)'" 2>/dev/null | grep -q 1; then \
		echo "    [OK] Role exists"; \
	else \
		echo "    [MISSING] Role does not exist"; \
		echo "             Fix: make dev-setup"; \
		FAILED=1; \
	fi; \
	echo ""; \
	echo "  PostgreSQL database '$(POSTGRES_DB)':"; \
	if psql "$(POSTGRES_ADMIN_URL)" -tAc "SELECT 1 FROM pg_database WHERE datname='$(POSTGRES_DB)'" 2>/dev/null | grep -q 1; then \
		echo "    [OK] Database exists"; \
	else \
		echo "    [MISSING] Database does not exist"; \
		echo "             Fix: make dev-setup"; \
		FAILED=1; \
	fi; \
	echo ""; \
	if [ "$$FAILED" = "1" ]; then \
		echo "Some prerequisites are missing. Run 'make dev-setup' to fix."; \
		exit 1; \
	else \
		echo "All prerequisites OK!"; \
	fi

dev-setup:
	@echo "Setting up local dev environment..."
	@echo ""
	@echo "1. Checking PostgreSQL..."
	@if pg_isready -q -h $(POSTGRES_HOST) -p $(POSTGRES_PORT) 2>/dev/null; then \
		echo "   Already running."; \
	else \
		brew services start postgresql@14 2>/dev/null || brew services start postgresql 2>/dev/null || \
			(echo "   Failed to start PostgreSQL. Please install with: brew install postgresql@14" && exit 1); \
		sleep 2; \
		if pg_isready -q -h $(POSTGRES_HOST) -p $(POSTGRES_PORT) 2>/dev/null; then \
			echo "   Started."; \
		else \
			echo "   Failed to start PostgreSQL."; \
			exit 1; \
		fi; \
	fi
	@echo ""
	@echo "2. Checking Redis..."
	@if redis-cli -p $(REDIS_PORT) ping >/dev/null 2>&1; then \
		echo "   Already running."; \
	else \
		brew services start redis 2>/dev/null || \
			(echo "   Failed to start Redis. Please install with: brew install redis" && exit 1); \
		sleep 1; \
		if redis-cli -p $(REDIS_PORT) ping >/dev/null 2>&1; then \
			echo "   Started."; \
		else \
			echo "   Failed to start Redis."; \
			exit 1; \
		fi; \
	fi
	@echo ""
	@echo "3. Creating PostgreSQL role '$(POSTGRES_APP_USER)'..."
	@if psql "$(POSTGRES_ADMIN_URL)" -tAc "SELECT 1 FROM pg_roles WHERE rolname='$(POSTGRES_APP_USER)'" 2>/dev/null | grep -q 1; then \
		echo "   Already exists."; \
	else \
		psql "$(POSTGRES_ADMIN_URL)" -c "CREATE ROLE $(POSTGRES_APP_USER) WITH LOGIN CREATEDB;" && \
		echo "   Created."; \
	fi
	@echo ""
	@echo "4. Creating PostgreSQL database '$(POSTGRES_DB)'..."
	@if psql "$(POSTGRES_ADMIN_URL)" -tAc "SELECT 1 FROM pg_database WHERE datname='$(POSTGRES_DB)'" 2>/dev/null | grep -q 1; then \
		echo "   Already exists."; \
	else \
		psql "$(POSTGRES_ADMIN_URL)" -c "CREATE DATABASE $(POSTGRES_DB) OWNER $(POSTGRES_APP_USER);" && \
		echo "   Created."; \
	fi
	@echo ""
	@echo "Setup complete! Run 'make dev-backend' to start the server."

dev-seed:
	@echo "Seeding aweb dev database for conformance tests..."
	AWEB_DATABASE_URL="$(AWEB_DATABASE_URL)" \
	uv run aweb seed \
		--project-slug test-project \
		--agent-1-alias agent-1 \
		--agent-2-alias agent-2 \
		--aweb-url http://localhost:$(AWEB_PORT) \
		--other-project-slug test-other \
		--other-agent-alias other-agent

dev-stop:
	@echo "Stopping aweb dev server..."
	-@lsof -ti :$(AWEB_PORT) | xargs kill 2>/dev/null || true
	@echo "Done."

#
# Testing
#

sync:
	uv sync

serve:
	uv run aweb serve --host 0.0.0.0 --port 8000 --reload

test:
	uv run pytest

conformance:
	AWEB_CONFORMANCE=1 uv run pytest -q tests/aweb_conformance

#
# Code Quality
#

fmt:
	uv run black src tests
	uv run isort src tests

lint:
	uv run ruff check src tests

typecheck:
	uv run mypy

check: fmt lint typecheck test

#
# Utilities
#

health:
	@echo "Checking health..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if curl -sf http://localhost:$(AWEB_PORT)/health > /dev/null 2>&1; then \
			curl -s http://localhost:$(AWEB_PORT)/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('  Status:', d['status']); [print(f'    {k}: {v}') for k,v in d.get('checks',{}).items()]" 2>/dev/null || curl -s http://localhost:$(AWEB_PORT)/health; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "  Health check failed after 10s"; \
	exit 1

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache
