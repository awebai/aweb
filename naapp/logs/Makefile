.PHONY: test lint typecheck

test:
	uv run pytest -q

lint: typecheck
	uv run ruff check .

typecheck:
	uv run mypy src
