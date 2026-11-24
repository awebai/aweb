# Pull-request CI type-checks each naapp package through `make typecheck`, and
# the candidate gate runs `make test` (the root Makefile's NAAPP_PACKAGES).

.PHONY: lint typecheck test

lint: typecheck
	uv run ruff check .

typecheck:
	uv run mypy src

test:
	uv run pytest -q
