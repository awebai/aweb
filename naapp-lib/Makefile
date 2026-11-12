# The candidate gate covers each naapp package through `make lint` and
# `make test` (the root Makefile's NAAPP_PACKAGES).

.PHONY: lint test

lint:
	uv run ruff check .
	uv run mypy src

test:
	$(if $(AWEB_UNIT_REPORT_DIR),python3 "$(abspath ../scripts/unit_report.py)" pytest naapp-lib --) uv run pytest -q
