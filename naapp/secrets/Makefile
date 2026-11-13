.PHONY: test lint e2e

SECRETS_REPORT_NAME ?= naapp-secrets
SECRETS_PYTEST_ARGS ?=

test:
	@if [ -n "$${AWEB_UNIT_REPORT_DIR:-}" ]; then \
		case "$${AWEB_UNIT_REPORTER:-}" in /*) ;; *) echo "AWEB_UNIT_REPORTER must be an absolute path when reporting" >&2; exit 2;; esac; \
		uv run python "$$AWEB_UNIT_REPORTER" pytest "$(SECRETS_REPORT_NAME)" -- uv run pytest -q -m "not e2e" $(SECRETS_PYTEST_ARGS); \
	else \
		uv run pytest -q -m "not e2e" $(SECRETS_PYTEST_ARGS); \
	fi

# The H owner-acts journey: the real aw against AWID, aweb and this app's
# production image, with the holder's human key in a real Secret Service.
# It starts Docker containers, so it runs only in an assigned slot.
e2e:
	SECRETS_E2E=1 uv run pytest -q -m e2e tests/test_e2e_owner_acts.py

lint:
	uv run ruff check .
	uv run mypy src e2e
