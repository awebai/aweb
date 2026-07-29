.PHONY: test test-server lint compile run e2e e2e-up e2e-down api-serve api-stop \
	prod-ops-test prod-status prod-health-client-proof prod-deploy prod-wait prod-verify prod-rollback prod-recovery \
	prod-gate-candidate prod-gate-recovery aatk-predicate-inventory aatk-spec-check aatk-validate-preplan aatk-validate-release

API_PORT ?= 8765
PROD_CONFIG ?= ops/render-production.json
RENDER_ENV_FILE ?= $(HOME)/.aweb-render/env
PROD_COMMIT ?=
PROD_DEPLOY_ID ?=
CURRENT_DEPLOY_ID ?=
CURRENT_COMMIT ?=
ROLLBACK_DEPLOY_ID ?=
ROLLBACK_COMMIT ?=
CONFIRM_SERVICE_ID ?=
AW_SOURCE_HOME ?=
EXPECTED_PROFILE_VERSION ?=
EXPECTED_PROFILE_DIGEST ?=
ALLOW_LEGACY_MISSING_BUILD_FOR ?=
APPLY ?= 0
PROD_EVIDENCE_DIR ?=
AATK_EVIDENCE_INDEX ?=

# Export operational values instead of interpolating them into recipes. This keeps
# operator-provided IDs and paths out of shell parsing; Python performs exact validation.
export PROD_CONFIG RENDER_ENV_FILE PROD_COMMIT PROD_DEPLOY_ID CURRENT_DEPLOY_ID CURRENT_COMMIT
export ROLLBACK_DEPLOY_ID
export ROLLBACK_COMMIT CONFIRM_SERVICE_ID AW_SOURCE_HOME EXPECTED_PROFILE_VERSION
export EXPECTED_PROFILE_DIGEST ALLOW_LEGACY_MISSING_BUILD_FOR APPLY PROD_EVIDENCE_DIR
export AATK_EVIDENCE_INDEX

test:
	uv run pytest -q -m "not e2e"

test-server:
	uv run pytest -q -m "not e2e"

lint:
	uv run ruff check .
	uv run mypy src

compile:
	PYTHONPATH=src:../aweb/awid/src:../pgdbm/src python3 -m compileall -q src tests

run:
	PYTHONPATH=src:../aweb/awid/src:../pgdbm/src python3 -m uvicorn library.api:app --host 127.0.0.1 --port $(API_PORT) --reload

e2e:
	set -e; \
	trap 'docker compose -p library-e2e -f docker-compose.e2e.yml down -v --remove-orphans' EXIT; \
	docker compose -p library-e2e -f docker-compose.e2e.yml down -v --remove-orphans >/dev/null 2>&1 || true; \
	docker compose -p library-e2e -f docker-compose.e2e.yml up --build -d; \
	LIBRARY_E2E=1 uv run pytest -q -m e2e

e2e-up:
	docker compose -p library-e2e -f docker-compose.e2e.yml up --build -d

e2e-down:
	docker compose -p library-e2e -f docker-compose.e2e.yml down -v --remove-orphans

api-serve:
	@[ ! -f .api.pid ] || { echo "api server already running (pid $$(cat .api.pid)); make api-stop first"; exit 1; }
	@nohup env PYTHONPATH=src:../aweb/awid/src:../pgdbm/src python3 -m uvicorn library.api:app --host 127.0.0.1 --port $(API_PORT) > .api.log 2>&1 & echo $$! > .api.pid
	@echo "api serving at http://127.0.0.1:$(API_PORT)/ (pid $$(cat .api.pid))"

api-stop:
	@[ -f .api.pid ] && { kill $$(cat .api.pid) 2>/dev/null || true; rm -f .api.pid; echo "api server stopped"; } || echo "api server not running"

# Production Render operations are intentionally Make-only. Never replace these
# targets with inline curl/shell mutations in a release session.
prod-ops-test:
	uv run pytest -q tests/test_render_ops.py tests/test_library_prod_gate.py

prod-status:
	uv run python scripts/render_ops.py status

prod-health-client-proof:
	uv run python scripts/render_ops.py health-client-proof

prod-deploy:
	git fetch --quiet origin
	uv run python scripts/render_ops.py deploy

prod-wait:
	uv run python scripts/render_ops.py wait

prod-verify:
	uv run python scripts/render_ops.py verify
	uv run python scripts/library_prod_gate.py candidate

prod-rollback:
	uv run python scripts/render_ops.py rollback

# This recovery fingerprint is specific to the pre-aasb rollback artifact. Future
# releases must add and review their own exact recovery gate rather than reusing it.
prod-recovery:
	$(MAKE) prod-rollback
	$(MAKE) prod-gate-recovery

prod-gate-candidate:
	uv run python scripts/library_prod_gate.py candidate

prod-gate-recovery:
	uv run python scripts/library_prod_gate.py legacy-aasb

aatk-predicate-inventory:
	uv run python scripts/aatk.py inventory

aatk-spec-check:
	uv run python scripts/aatk.py spec

aatk-validate-preplan:
	@[ -n "$$AATK_EVIDENCE_INDEX" ] || { echo "AATK_EVIDENCE_INDEX is required"; exit 2; }
	uv run python scripts/aatk.py preplan --index "$$AATK_EVIDENCE_INDEX"

aatk-validate-release:
	@[ -n "$$AATK_EVIDENCE_INDEX" ] || { echo "AATK_EVIDENCE_INDEX is required"; exit 2; }
	uv run python scripts/aatk.py release --index "$$AATK_EVIDENCE_INDEX"
