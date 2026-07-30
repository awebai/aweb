.PHONY: test test-server lint compile run e2e e2e-up e2e-down api-serve api-stop

API_PORT ?= 8765

test:
	uv run pytest -q

test-server:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run mypy src

e2e:
	set -e; \
	trap 'docker compose -p folio-e2e -f docker-compose.e2e.yml down -v --remove-orphans' EXIT; \
	docker compose -p folio-e2e -f docker-compose.e2e.yml down -v --remove-orphans >/dev/null 2>&1 || true; \
	docker compose -p folio-e2e -f docker-compose.e2e.yml up --build -d; \
	FOLIO_E2E=1 uv run pytest -q -m e2e

e2e-up:
	docker compose -p folio-e2e -f docker-compose.e2e.yml up --build -d

e2e-down:
	docker compose -p folio-e2e -f docker-compose.e2e.yml down -v --remove-orphans

compile:
	uv run python -m compileall -q src tests

run:
	uv run python -m uvicorn folio.api:app --host 127.0.0.1 --port $(API_PORT) --reload

api-serve:
	@[ ! -f .api.pid ] || { echo "api server already running (pid $$(cat .api.pid)); make api-stop first"; exit 1; }
	@nohup uv run python -m uvicorn folio.api:app --host 127.0.0.1 --port $(API_PORT) > .api.log 2>&1 & echo $$! > .api.pid
	@echo "api serving at http://127.0.0.1:$(API_PORT)/ (pid $$(cat .api.pid))"

api-stop:
	@[ -f .api.pid ] && { kill $$(cat .api.pid) 2>/dev/null || true; rm -f .api.pid; echo "api server stopped"; } || echo "api server not running"
