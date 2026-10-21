.PHONY: test lint

test:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run mypy src e2e
