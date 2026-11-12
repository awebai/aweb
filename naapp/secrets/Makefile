.PHONY: test lint

SECRETS_REPORT_NAME ?= naapp-secrets
SECRETS_PYTEST_ARGS ?=

test:
	@if [ -n "$${AWEB_UNIT_REPORT_DIR:-}" ]; then \
		case "$${AWEB_UNIT_REPORTER:-}" in /*) ;; *) echo "AWEB_UNIT_REPORTER must be an absolute path when reporting" >&2; exit 2;; esac; \
		uv run python "$$AWEB_UNIT_REPORTER" pytest "$(SECRETS_REPORT_NAME)" -- uv run pytest -q $(SECRETS_PYTEST_ARGS); \
	else \
		uv run pytest -q $(SECRETS_PYTEST_ARGS); \
	fi

lint:
	uv run ruff check .
	uv run mypy src e2e
