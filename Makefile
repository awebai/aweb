# aweb (Agent Web) - development helpers
#
# This repo uses uv; these targets are convenience wrappers.

.PHONY: help sync serve test conformance fmt lint typecheck check clean

help:
	@echo "aweb Commands:"
	@echo ""
	@echo "  make sync        - Install dependencies (uv sync)"
	@echo "  make serve       - Run aweb server (uses env for DB/Redis)"
	@echo "  make test        - Run unit/integration tests"
	@echo "  make conformance - Run black-box conformance tests (requires AWEB_URL + AWEB_CONFORMANCE=1)"
	@echo "  make fmt         - Format (black + isort)"
	@echo "  make lint        - Lint (ruff)"
	@echo "  make typecheck   - Typecheck (mypy)"
	@echo "  make check       - fmt + lint + typecheck + test"
	@echo ""

sync:
	uv sync

serve:
	uv run aweb serve --host 0.0.0.0 --port 8000 --reload

test:
	uv run pytest

conformance:
	AWEB_CONFORMANCE=1 uv run pytest -q tests/aweb_conformance

fmt:
	uv run black src tests
	uv run isort src tests

lint:
	uv run ruff check src tests

typecheck:
	uv run mypy

check: fmt lint typecheck test

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache
