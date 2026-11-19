.PHONY: check test

check:
	uv run --frozen ruff check src tests
	uv run --frozen ruff format --check src tests
	uv run --frozen mypy

# Dependencies are prepared by the caller; native fixtures use its private services.
# PYTEST_ADDOPTS and TEST_DB_*/REDIS_URL pass through unchanged.
test:
	uv run --frozen --offline --no-sync pytest -q tests
