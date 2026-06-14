.PHONY: test test-server lint compile run e2e e2e-up e2e-down site site-serve site-stop api-serve api-stop

HUGO_VERSION ?= 0.160.1
SITE_PORT ?= 7333
API_PORT ?= 8765

test:
	PYTHONPATH=src:../aweb/awid/src:../pgdbm/src python3 -m pytest -q

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

site:
	@hugo version | grep -q "v$(HUGO_VERSION)" || { echo "Expected Hugo v$(HUGO_VERSION); install/pin that version or update HUGO_VERSION intentionally."; exit 1; }
	hugo --source site --destination public --minify

compile:
	PYTHONPATH=src:../aweb/awid/src:../pgdbm/src python3 -m compileall -q src tests

run:
	PYTHONPATH=src:../aweb/awid/src:../pgdbm/src python3 -m uvicorn folio.api:app --host 127.0.0.1 --port $(API_PORT) --reload

site-serve: site
	@[ ! -f site/.serve.pid ] || { echo "site server already running (pid $$(cat site/.serve.pid)); make site-stop first"; exit 1; }
	@nohup python3 -m http.server $(SITE_PORT) --bind 127.0.0.1 --directory site/public > site/.serve.log 2>&1 & echo $$! > site/.serve.pid
	@echo "site serving at http://127.0.0.1:$(SITE_PORT)/ (pid $$(cat site/.serve.pid))"

site-stop:
	@[ -f site/.serve.pid ] && { kill $$(cat site/.serve.pid) 2>/dev/null || true; rm -f site/.serve.pid; echo "site server stopped"; } || echo "site server not running"

api-serve:
	@[ ! -f .api.pid ] || { echo "api server already running (pid $$(cat .api.pid)); make api-stop first"; exit 1; }
	@nohup env PYTHONPATH=src:../aweb/awid/src:../pgdbm/src python3 -m uvicorn folio.api:app --host 127.0.0.1 --port $(API_PORT) > .api.log 2>&1 & echo $$! > .api.pid
	@echo "api serving at http://127.0.0.1:$(API_PORT)/ (pid $$(cat .api.pid))"

api-stop:
	@[ -f .api.pid ] && { kill $$(cat .api.pid) 2>/dev/null || true; rm -f .api.pid; echo "api server stopped"; } || echo "api server not running"
