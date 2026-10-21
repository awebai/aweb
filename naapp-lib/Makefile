# The candidate gate covers each naapp package through `make lint` and
# `make test` (the root Makefile's NAAPP_PACKAGES).

.PHONY: lint test

lint:
	uv run ruff check .
	uv run mypy src

test:
	uv run pytest -q
