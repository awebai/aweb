.PHONY: test lint e2e

test:
	uv run pytest -q -m "not e2e"

# The H owner-acts journey: the real aw against AWID, aweb and this app's
# production image, with the holder's human key in a real Secret Service.
# It starts Docker containers, so it runs only in an assigned slot.
e2e:
	SECRETS_E2E=1 uv run pytest -q -m e2e tests/test_e2e_owner_acts.py

lint:
	uv run ruff check .
	uv run mypy src e2e
