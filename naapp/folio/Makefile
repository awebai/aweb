.PHONY: test test-server test-record-table-ui lint compile run e2e e2e-up e2e-down api-serve api-stop \
	prod-status prod-deploy prod-wait prod-verify prod-rollback

API_PORT ?= 8765
# The e2e stack's compose project; a gate passes its own with the NAAPP_E2E_* ports.
export NAAPP_E2E_PROJECT ?= folio-e2e
PROD_CONFIG ?= ops/render-production.json

test:
	node --test tests/*.test.mjs
	uv run pytest -q -m "not e2e"

test-server:
	uv run pytest -q

# Uses the shared renderer's locked browser-test dependencies (npm ci --prefix ../../naapp-lib/renderer).
test-record-table-ui:
	env -u NO_COLOR ../../naapp-lib/renderer/node_modules/.bin/playwright test tests/browser/record-table.spec.mjs

lint:
	uv run ruff check .
	uv run mypy src

e2e:
	set -e; \
	network="$(NAAPP_E2E_PROJECT)_default"; connected=; \
	cleanup() { \
		status=$$?; trap - EXIT; \
		if [ -n "$$connected" ]; then \
			docker network disconnect "$$network" "$$CANDIDATE_RUNNER_NAME" || status=1; \
		fi; \
		docker compose -p $(NAAPP_E2E_PROJECT) -f docker-compose.e2e.yml down -v --remove-orphans || status=1; \
		exit "$$status"; \
	}; trap cleanup EXIT; \
	docker compose -p $(NAAPP_E2E_PROJECT) -f docker-compose.e2e.yml down -v --remove-orphans >/dev/null 2>&1 || true; \
	docker compose -p $(NAAPP_E2E_PROJECT) -f docker-compose.e2e.yml up --build -d; \
	if [ -n "$${CANDIDATE_RUNNER_NAME:-}" ]; then \
		runner_label=$$(docker inspect --format '{{index .Config.Labels "aweb.candidate-gate"}}' "$$CANDIDATE_RUNNER_NAME"); \
		test "$$runner_label" = "$${AWEB_CANDIDATE_RESOURCE_LABEL:?}"; \
		docker network connect "$$network" "$$CANDIDATE_RUNNER_NAME"; connected=1; \
		export NAAPP_E2E_CONTAINER_NETWORK=1; \
	fi; \
	FOLIO_E2E=1 uv run pytest -q -m e2e

e2e-up:
	docker compose -p $(NAAPP_E2E_PROJECT) -f docker-compose.e2e.yml up --build -d

e2e-down:
	docker compose -p $(NAAPP_E2E_PROJECT) -f docker-compose.e2e.yml down -v --remove-orphans

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

# Production Render operations are Make-only and run the shared aweb_naapp.ops tool
# against ops/render-production.json. status and verify only read; deploy and
# rollback need APPLY=1 and CONFIRM_SERVICE_ID. Inputs come from the environment:
# PROD_COMMIT, PROD_DEPLOY_ID, ROLLBACK_DEPLOY_ID, ROLLBACK_COMMIT,
# CURRENT_DEPLOY_ID, CURRENT_COMMIT, RENDER_ENV_FILE.
prod-status:
	uv run python -m aweb_naapp.ops --config $(PROD_CONFIG) status

prod-deploy:
	uv run python -m aweb_naapp.ops --config $(PROD_CONFIG) deploy --repo-root ../..

prod-wait:
	uv run python -m aweb_naapp.ops --config $(PROD_CONFIG) wait

prod-verify:
	uv run python -m aweb_naapp.ops --config $(PROD_CONFIG) verify

prod-rollback:
	uv run python -m aweb_naapp.ops --config $(PROD_CONFIG) rollback
