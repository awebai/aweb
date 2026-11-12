.PHONY: test lint

test:
	$(if $(AWEB_UNIT_REPORT_DIR),python3 "$(abspath ../../scripts/unit_report.py)" pytest naapp-logs --) uv run pytest -q

lint:
	uv run ruff check .
	uv run mypy src
