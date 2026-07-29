.PHONY: help clean test test-server test-awid test-cli test-node-deps test-channel test-channel-core test-channel-core-process-guard test-pi-extension test-ship-ci-contract prepare-oas-test-root check-oas-launch-environment-contract test-oas test-oas-proof-helpers test-oas-attached-principal-e2e test-oas-pi-resident-e2e test-tmux-guard test-a2a test-e2e test-federation-e2e test-a2a-gateway-e2e check-a2a-copy-guardrails build \
	freshness check-go-vulnerability-audit check-node-audit \
	selfhost-up selfhost-down selfhost-logs awid-up awid-down awid-logs \
	e2e-library-stack e2e-library-stack-up e2e-library-stack-seed e2e-library-stack-down \
	awid-prod-verify awid-prod-dump awid-prod-restore awid-prod-migrate \
	release-server-check release-server-tag release-server-push \
	release-awid-check release-awid-tag release-awid-push \
	release-awid-pypi-tag release-awid-pypi-push \
	release-a2a-gateway-check release-a2a-gateway-tag release-a2a-gateway-push \
	release-channel-check release-channel-tag release-channel-push \
	test-release-cli-version release-cli-version-check release-cli-tag release-cli-push \
	list-awid-site-docs sync-awid-site-docs check-awid-site-docs release-awid-site \
	release-all-check release-all-tag release-all-push \
	publish-skills \
	ship

SERVER_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' server/pyproject.toml | head -n 1)
AWID_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' awid/pyproject.toml | head -n 1)
CHANNEL_VERSION := $(shell node -p "require('./channel/package.json').version" 2>/dev/null)
CHANNEL_PLUGIN_VERSION := $(shell node -p "require('./channel/.claude-plugin/plugin.json').version" 2>/dev/null)
# aw CLI releases have independent semver. Derive the next patch from the
# published aw-v* history; the release guard below rejects stale overrides.
CLI_VERSION = $(shell ./scripts/cli-release-version.sh next)
# The A2A gateway workflow requires its tag to match server/pyproject.toml.
A2A_GATEWAY_VERSION := $(SERVER_VERSION)
# OAS seam tests default to an immutable reviewed upstream commit materialized
# under this repository's ignored cache. That makes local and CI runs consume the
# same clean input instead of a colleague's mutable sibling checkout. Deliberate
# early integration remains opt-in: OAS_TEST_ROOT=/path/to/local/oas make test-oas.
OAS_PIN_FILE := $(CURDIR)/oas/upstream-test-pin.json
OAS_PINNED_ROOT := $(CURDIR)/.cache/oas-pinned
OAS_TEST_ROOT ?= $(OAS_PINNED_ROOT)

# Canonical docs mirrored onto the public AWID site. Sync, freshness checks, and
# their negative controls all consume this one list so adding a mirror cannot
# silently bypass the pre-merge gate.
AWID_SITE_DOC_NAMES := identity-guide.md trust-model.md
AWID_SITE_DOC_SOURCE_DIR ?= docs
AWID_SITE_DOC_MIRROR_DIR ?= awid/site/static
AWID_SITE_DOC_MIRRORS := $(addprefix $(AWID_SITE_DOC_MIRROR_DIR)/,$(AWID_SITE_DOC_NAMES))

help:
	@echo "Targets:"
	@echo "  build        Build the aw CLI binary"
	@echo "  test         Run all tests (server + CLI + channel + awid)"
	@echo "  test-server  Run server tests"
	@echo "  test-awid    Run awid service tests"
	@echo "  test-cli     Run CLI tests"
	@echo "  test-channel Run channel tests"
	@echo "  test-channel-core Run channel-core tests"
	@echo "  test-channel-core-process-guard Run the multi-process DeliveryStore guard (release path)"
	@echo "  test-pi-extension Run pi-extension tests"
	@echo "  test-ship-ci-contract Verify the canonical mandatory ship workflow"
	@echo "  prepare-oas-test-root Materialize the clean committed OAS test pin"
	@echo "  check-oas-launch-environment-contract Verify the pinned OAS seam dependency"
	@echo "    opt-in local OAS: make test-oas OAS_TEST_ROOT=/path/to/local/oas"
	@echo "  freshness    Regenerate committed artifacts and fail on drift"
	@echo "  check-node-audit Audit Node dependencies for known vulnerabilities"
	@echo "  check-go-vulnerability-audit Audit Go dependencies (pinned toolchain)"
	@echo "  test-a2a     Run A2A conformance, gateway, AWID lookup, and CLI command gates"
	@echo "  test-oas-proof-helpers Run attached-principal proof filesystem guard tests"
	@echo "  test-oas-attached-principal-e2e Run the real local-stack attach/retire proof"
	@echo "  test-oas-pi-resident-e2e Run the guarded real-Pi wake/reply/retire proof"
	@echo "  test-tmux-guard Run the guarded tmux migration and PATH-alias regressions"
	@echo "  test-e2e     Run the end-to-end user journey and its mutation guard (requires Docker)"
	@echo "  test-federation-e2e Run the OSS federation journey (requires Docker)"
	@echo "  test-a2a-gateway-e2e Run the A2A gateway Docker journey against real aweb+awid"
	@echo "  check-a2a-copy-guardrails Block premature A2A trust/E2EE copy"
	@echo "  selfhost-up / -down / -logs   Manage the OSS docker-compose stack (aweb + awid)"
	@echo "  awid-up / -down / -logs       Manage the standalone awid docker-compose stack"
	@echo "  e2e-library-stack             Bring up awid+aweb+Library, seed aweb.team, verify, tear down (requires Docker + ../library + ../blueprints)"
	@echo "  e2e-library-stack-up / -seed / -down  Drive the combined stack step by step"
	@echo ""
	@echo "  awid-prod-verify    Print awid prod table row counts"
	@echo "  awid-prod-dump      Dump awid prod data to /tmp (--column-inserts)"
	@echo "  awid-prod-restore   Restore a dump into awid prod (DUMP=path)"
	@echo "  awid-prod-migrate   Apply pending migrations to awid prod"
	@echo ""
	@echo "  release-all-check   Validate ALL products before release"
	@echo "  release-all-tag     Commit version bumps and create all tags"
	@echo "  release-all-push    Push main and all tags to trigger CI"
	@echo ""
	@echo "  release-server-check / -tag / -push   aweb server (PyPI)"
	@echo "  release-channel-check / -tag / -push  channel plugin (npm)"
	@echo "  release-awid-check / -tag / -push     awid service (GHCR Docker)"
	@echo "  release-awid-pypi-tag / -push         awid service (PyPI)"
	@echo "  release-a2a-gateway-check / -tag / -push  A2A gateway (GHCR Docker)"
	@echo "  release-cli-version-check / -tag / -push  aw CLI (goreleaser)"
	@echo "  release-awid-site                     deploy awid landing page"
	@echo "  clean        Remove all build artifacts and caches"

build:
	cd cli/go && $(MAKE) build

test: test-server test-awid test-cli test-channel test-channel-core test-pi-extension test-ship-ci-contract test-oas test-oas-proof-helpers test-tmux-guard test-release-cli-version

# Regenerate every committed generated artifact (uv locks, cli reference,
# reserved-app-ids, resource packs, and the claude-channel + pi bundles) and
# fail on drift. Runs as part of release-all-check.
freshness:
	bash scripts/check-freshness.sh

# Both audits describe what a release SHIPS, so they hang off the release path
# rather than `make test`. The Go audit pins itself to the toolchain in
# cli/go/go.mod and refuses to run under any other, which would red `make test`
# on every machine with a newer Go; and both consult an advisory database that
# moves without any repo change, so neither belongs in a suite expected to be
# deterministic.
#
# These run AT RELEASE ONLY. Nothing runs them on a schedule. An advisory
# published between two releases is not seen until the next release, and the
# deferral deadlines in .github/go-vulnerability-exceptions.json are only
# checked when one of these runs. Accepted deliberately on 2026-07-26; see
# default-aaoa.
check-go-vulnerability-audit:
	bash scripts/check-go-vulnerability-audit.sh

check-node-audit:
	bash scripts/check-node-audit.sh

list-awid-site-docs:
	@for name in $(AWID_SITE_DOC_NAMES); do printf '%s\n' "$$name"; done

sync-awid-site-docs:
	@mkdir -p "$(AWID_SITE_DOC_MIRROR_DIR)"
	@set -e; for name in $(AWID_SITE_DOC_NAMES); do \
		cp "$(AWID_SITE_DOC_SOURCE_DIR)/$$name" "$(AWID_SITE_DOC_MIRROR_DIR)/$$name"; \
	done

check-awid-site-docs:
	@status=0; for name in $(AWID_SITE_DOC_NAMES); do \
		source="$(AWID_SITE_DOC_SOURCE_DIR)/$$name"; \
		mirror="$(AWID_SITE_DOC_MIRROR_DIR)/$$name"; \
		if [ ! -f "$$source" ]; then \
			echo "FAIL: canonical AWID site document missing: $$source"; status=1; \
		elif [ ! -f "$$mirror" ]; then \
			echo "FAIL: public AWID site document mirror missing: $$mirror"; status=1; \
		elif ! cmp -s "$$source" "$$mirror"; then \
			echo "FAIL: public AWID site document mirror stale: $$mirror differs from $$source"; status=1; \
		fi; \
	done; \
	if [ "$$status" -eq 0 ]; then echo "AWID site document mirrors are up to date"; fi; \
	exit "$$status"

test-server:
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run --frozen pytest -q

test-awid:
	cd awid && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run --frozen pytest -q

test-cli:
	cd cli/go && GOCACHE=/tmp/go-build go test ./... -count=1

# The Node suites have separate lockfiles and a local file: dependency from the
# host adapters to channel-core. Install all three before any Node test target
# so both `make test` and focused Node targets work from a clean checkout.
test-node-deps:
	cd channel-core && npm ci --no-audit --no-fund
	cd channel && npm ci --no-audit --no-fund
	cd pi-extension && npm ci --no-audit --no-fund

test-channel test-channel-core test-pi-extension: test-node-deps

test-channel:
	cd channel && npm test

# channel-core holds the identity, trust, pinstore and signature-decode logic
# that channel and pi-extension are both built from, so its suite gates them.
test-channel-core:
	cd channel-core && npm test

# The multi-process DeliveryStore guard spawns 16 real subprocesses, enough to
# blow unrelated timing deadlines elsewhere on a shared machine (default-aadj),
# and it leaks all 16 if its parent dies mid-run (default-aaod). So it is kept
# off `make test`, which agents run constantly and interrupt freely, and runs
# from the release path instead.
test-channel-core-process-guard:
	cd channel-core && npm run test:process-guard

test-pi-extension:
	cd pi-extension && npm test

test-ship-ci-contract:
	python3 scripts/e2e/test_ship_ci_contract.py

prepare-oas-test-root:
	@if [ "$(abspath $(OAS_TEST_ROOT))" = "$(abspath $(OAS_PINNED_ROOT))" ]; then \
		node scripts/prepare-pinned-oas.mjs --pin-file "$(OAS_PIN_FILE)" --target "$(OAS_PINNED_ROOT)"; \
	else \
		echo "Using explicit OAS_TEST_ROOT override without modifying it: $(OAS_TEST_ROOT)" >&2; \
	fi

check-oas-launch-environment-contract: prepare-oas-test-root
	@OAS_TEST_ROOT="$(OAS_TEST_ROOT)" node scripts/check-oas-launch-environment-contract.mjs

test-oas: check-oas-launch-environment-contract
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" node --test oas/test/*.test.mjs

test-oas-proof-helpers: prepare-oas-test-root
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" python3 scripts/e2e/test_oas_pinned_checkout.py
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" python3 scripts/e2e/test_oas_principal_proof.py
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" python3 scripts/e2e/test_oas_tmux_safety.py

test-oas-attached-principal-e2e: test-oas-proof-helpers
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" ./scripts/e2e-oas-attached-principal-retire.sh

test-oas-pi-resident-e2e: test-oas-proof-helpers
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" PATH="$(CURDIR)/scripts/guard-bin:$$PATH" OAS_PROOF_MODE=resident-pi ./scripts/e2e-oas-attached-principal-retire.sh

test-tmux-guard:
	PATH="$(CURDIR)/scripts/guard-bin:$$PATH" ./scripts/test-migrate-agent-tmux.sh

test-a2a:
	cd cli/go && GOCACHE=/tmp/go-build go test ./internal/conformance ./a2a ./a2agw ./awid -count=1
	cd cli/go && GOCACHE=/tmp/go-build go test ./cmd/aw ./cmd/aweb-a2a-gw -run A2A -count=1
	cd awid && uv run pytest tests/test_a2a_publication_route.py -q
	./scripts/check-a2a-copy-guardrails.sh

test-e2e:
	./scripts/e2e-oss-user-journey.sh
	./scripts/test-e2e-controller-key-absence-guard.sh

test-federation-e2e:
	./scripts/e2e-oss-federation.sh

test-a2a-gateway-e2e:
	./scripts/e2e-a2a-gateway-docker.sh

check-a2a-copy-guardrails:
	./scripts/check-a2a-copy-guardrails.sh

selfhost-up:
	cd server && docker compose up --build -d

selfhost-down:
	cd server && docker compose down

selfhost-logs:
	cd server && docker compose logs -f aweb awid

awid-up:
	cd awid && POSTGRES_PASSWORD=$${POSTGRES_PASSWORD:-change-me} docker compose up --build -d

awid-down:
	cd awid && POSTGRES_PASSWORD=$${POSTGRES_PASSWORD:-change-me} docker compose down

awid-logs:
	cd awid && POSTGRES_PASSWORD=$${POSTGRES_PASSWORD:-change-me} docker compose logs -f awid

# ---- combined e2e stack: awid + aweb + Library, seeded ----------------------
# Requires Docker and sibling ../library + ../blueprints checkouts.
# See docs/e2e-library-stack.md.
e2e-library-stack:
	./scripts/e2e-library-stack.sh all

e2e-library-stack-up:
	./scripts/e2e-library-stack.sh up

e2e-library-stack-seed:
	./scripts/e2e-library-stack.sh seed

e2e-library-stack-down:
	./scripts/e2e-library-stack.sh down

# ---- awid production DB lifecycle (Neon) ------------------------------------
# All targets default to ./.env.awid-production. Override with ENV_FILE=...
# Override the dump destination with DUMP=... where applicable.

AWID_PROD_ENV_FILE ?= $(CURDIR)/.env.awid-production

awid-prod-verify:
	cd awid && uv run python scripts/prod_db_reset.py verify --env-file $(AWID_PROD_ENV_FILE)

awid-prod-dump:
	cd awid && uv run python scripts/prod_db_reset.py dump --env-file $(AWID_PROD_ENV_FILE) $(if $(DUMP),--output $(DUMP),)

awid-prod-restore:
	@test -n "$(DUMP)" || (echo "DUMP=path/to/dump.sql is required"; exit 1)
	cd awid && uv run python scripts/prod_db_reset.py restore --env-file $(AWID_PROD_ENV_FILE) --dump $(DUMP)

awid-prod-migrate:
	cd awid && uv run python scripts/prod_db_reset.py migrate --env-file $(AWID_PROD_ENV_FILE)

release-server-check:
	./scripts/check-server-version-bump.sh
	rm -rf /tmp/uv-cache /tmp/pycache
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run pytest -q
	rm -rf server/dist/
	cd server && uv build
	test -f server/dist/aweb-$(SERVER_VERSION).tar.gz
	test -f server/dist/aweb-$(SERVER_VERSION)-py3-none-any.whl
	@ls -lh server/dist/aweb-$(SERVER_VERSION).tar.gz server/dist/aweb-$(SERVER_VERSION)-py3-none-any.whl

release-server-tag:
	@git rev-parse --verify "server-v$(SERVER_VERSION)" >/dev/null 2>&1 && (echo "Tag server-v$(SERVER_VERSION) already exists."; exit 1) || true
	git add server/pyproject.toml server/uv.lock Makefile .claude/skills/release-pypi/SKILL.md server/README.md
	git diff --cached --quiet || git commit -m "release: aweb server $(SERVER_VERSION)"
	git tag "server-v$(SERVER_VERSION)"
	@echo "Created tag server-v$(SERVER_VERSION)."

release-server-push:
	git push origin main
	git push origin server-v$(SERVER_VERSION)

release-awid-check:
	cd awid && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv lock
	cd awid && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run pytest -q
	cd awid && uv build
	POSTGRES_PASSWORD=testpass docker compose -f awid/docker-compose.yml config >/dev/null
	docker build -f awid/Dockerfile.release -t awid:release-test .

release-awid-tag:
	@git rev-parse --verify "awid-v$(AWID_VERSION)" >/dev/null 2>&1 && (echo "Tag awid-v$(AWID_VERSION) already exists."; exit 1) || true
	git add awid/pyproject.toml awid/uv.lock awid/README.md awid/Dockerfile.release .github/workflows/awid-release.yml Makefile README.md
	git commit -m "release: awid $(AWID_VERSION)"
	git tag "awid-v$(AWID_VERSION)"
	@echo "Created tag awid-v$(AWID_VERSION)."

release-awid-push:
	git push origin main
	git push origin awid-v$(AWID_VERSION)

# ── Awid PyPI release ───────────────────────────────────────────────

release-awid-pypi-tag:
	@git rev-parse --verify "awid-service-v$(AWID_VERSION)" >/dev/null 2>&1 && (echo "Tag awid-service-v$(AWID_VERSION) already exists."; exit 1) || true
	git tag "awid-service-v$(AWID_VERSION)"
	@echo "Created tag awid-service-v$(AWID_VERSION)."

release-awid-pypi-push:
	git push origin awid-service-v$(AWID_VERSION)

# ── A2A gateway release ─────────────────────────────────────────────

release-a2a-gateway-check:
	./scripts/check-a2a-copy-guardrails.sh
	cd cli/go && GOCACHE=/tmp/go-build go test ./a2a ./a2agw ./awid ./cmd/aweb-a2a-gw -count=1
	docker build -f cli/go/Dockerfile.a2a-gw \
		--build-arg VERSION=$(A2A_GATEWAY_VERSION) \
		--build-arg RELEASE_TAG=a2a-gw-v$(A2A_GATEWAY_VERSION) \
		--build-arg COMMIT=$$(git rev-parse HEAD) \
		--build-arg DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t a2a-gateway:release-test cli/go
	docker run --rm \
		--user "$$(id -u):$$(id -g)" \
		-v "$(CURDIR)/docs/examples/a2a-gateway.yaml:/config/gateway.yaml:ro" \
		-v "$(CURDIR):/workspace:ro" \
		a2a-gateway:release-test \
		sh -c 'aweb-a2a-gw -config /config/gateway.yaml -workspace-dir /workspace -check'
	./scripts/e2e-a2a-gateway-docker.sh

release-a2a-gateway-tag:
	@git rev-parse --verify "a2a-gw-v$(A2A_GATEWAY_VERSION)" >/dev/null 2>&1 && (echo "Tag a2a-gw-v$(A2A_GATEWAY_VERSION) already exists."; exit 1) || true
	git tag "a2a-gw-v$(A2A_GATEWAY_VERSION)"
	@echo "Created tag a2a-gw-v$(A2A_GATEWAY_VERSION)."

release-a2a-gateway-push:
	git push origin a2a-gw-v$(A2A_GATEWAY_VERSION)

# ── Awid site deploy ────────────────────────────────────────────────

release-awid-site:
	@echo "Syncing docs into awid site..."
	$(MAKE) sync-awid-site-docs
	git add $(AWID_SITE_DOC_MIRRORS)
	@if ! git diff --cached --quiet -- $(AWID_SITE_DOC_MIRRORS); then \
		git commit -m "Sync identity-guide and trust-model into awid site"; \
	fi
	git checkout deploy-awid-landing
	git merge main -m "Deploy awid site from main"
	git push origin deploy-awid-landing
	git checkout main
	@echo "Awid site deployed via deploy-awid-landing."

# ── Channel release ──────────────────────────────────────────────────

release-channel-check:
	@test "$(CHANNEL_VERSION)" = "$(CHANNEL_PLUGIN_VERSION)" || \
		(echo "ERROR: channel package.json ($(CHANNEL_VERSION)) != plugin.json ($(CHANNEL_PLUGIN_VERSION))"; exit 1)
	cd channel-core && npm ci && npm run build
	cd channel && npm ci
	cd channel && npm test
	cd channel && npm run build
	cd channel && npm pack --dry-run
	@echo "Channel $(CHANNEL_VERSION) ready."

release-channel-tag:
	@git rev-parse --verify "channel-v$(CHANNEL_VERSION)" >/dev/null 2>&1 && (echo "Tag channel-v$(CHANNEL_VERSION) already exists."; exit 1) || true
	git add channel/package.json channel/package-lock.json channel/.claude-plugin/plugin.json
	git commit -m "release: @awebai/claude-channel $(CHANNEL_VERSION)"
	git tag "channel-v$(CHANNEL_VERSION)"
	@echo "Created tag channel-v$(CHANNEL_VERSION)."

release-channel-push:
	git push origin main
	git push origin channel-v$(CHANNEL_VERSION)

# ── CLI release ──────────────────────────────────────────────────────

test-release-cli-version:
	bash scripts/check-cli-release-version-test.sh

release-cli-version-check:
	@./scripts/cli-release-version.sh check "$(CLI_VERSION)"

release-cli-tag: release-cli-version-check
	@git rev-parse --verify "aw-v$(CLI_VERSION)" >/dev/null 2>&1 && (echo "Tag aw-v$(CLI_VERSION) already exists."; exit 1) || true
	git tag "aw-v$(CLI_VERSION)"
	@echo "Created tag aw-v$(CLI_VERSION)."

release-cli-push: release-cli-version-check
	git push origin aw-v$(CLI_VERSION)

# ── Claude skills release (bump + tag + push; GH Actions publishes) ─

# Usage: make publish-skills [BUMP=patch|minor|major]
# Bumps packages/claude-skills/package.json, syncs the plugin.json
# version, commits, tags skills-vX.Y.Z, pushes main and tag.
# The skills-release.yml workflow runs on the pushed tag and runs
# `npm publish --access public` against @awebai/claude-skills.
#
# Pre-flight: working tree clean, on main, in sync with origin/main.
# Contract smoke: `npm pack --dry-run` succeeds (catches the
# sync-skills "missing canonical source" foot-gun before the tag fires).
# Hestia owns this lane (release-channel-skill conventions).
publish-skills: BUMP ?= patch
publish-skills:
	@git diff --quiet || (echo "ERROR: working tree has unstaged changes"; exit 1)
	@git diff --cached --quiet || (echo "ERROR: staged changes pending"; exit 1)
	@test "$$(git branch --show-current)" = "main" || (echo "ERROR: not on main"; exit 1)
	git fetch origin
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)" || \
		(echo "ERROR: local main is not in sync with origin/main"; exit 1)
	cd packages/claude-skills && npm pack --dry-run
	cd packages/claude-skills && npm version $(BUMP) --no-git-tag-version
	cd packages/claude-skills && npm run sync-plugin-version
	@NEW_VERSION=$$(node -p "require('./packages/claude-skills/package.json').version") && \
		git add packages/claude-skills/package.json packages/claude-skills/.claude-plugin/plugin.json && \
		git commit -m "release: @awebai/claude-skills $$NEW_VERSION" && \
		git tag "skills-v$$NEW_VERSION" && \
		echo "Created tag skills-v$$NEW_VERSION."
	git push origin main
	@NEW_VERSION=$$(node -p "require('./packages/claude-skills/package.json').version") && \
		git push origin "skills-v$$NEW_VERSION" && \
		echo "" && \
		echo "  Pushed skills-v$$NEW_VERSION. GH Actions will:" && \
		echo "    - publish @awebai/claude-skills@$$NEW_VERSION to npm" && \
		echo "    - attach 5 ZIPs to the GH Release for Claude.ai users" && \
		echo "" && \
		echo "  After GH Actions completes:" && \
		echo "    1) Bump awebai/claude-plugins/.claude-plugin/marketplace.json" && \
		echo "       version field to $$NEW_VERSION so /plugin update finds the" && \
		echo "       new content." && \
		echo "    2) Claude.ai users: ZIPs at" && \
		echo "       https://github.com/awebai/aweb/releases/download/skills-v$$NEW_VERSION/{aweb-coordination,aweb-messaging,aweb-team-membership,aweb-bootstrap,aweb-identity}.zip"

# ── Unified release ──────────────────────────────────────────────────

release-all-check:
	@echo "=== Validating versions ==="
	@echo "  server:  $(SERVER_VERSION)"
	@echo "  awid:    $(AWID_VERSION)"
	@echo "  channel: $(CHANNEL_VERSION) (plugin: $(CHANNEL_PLUGIN_VERSION))"
	@echo "  cli:     $(CLI_VERSION)"
	@test "$(CHANNEL_VERSION)" = "$(CHANNEL_PLUGIN_VERSION)" || \
		(echo "ERROR: channel package.json != plugin.json"; exit 1)
	$(MAKE) release-cli-version-check
	@echo ""
	@echo "=== Running all tests ==="
	$(MAKE) test
	@echo ""
	@echo "=== Building artifacts ==="
	$(MAKE) release-server-check
	$(MAKE) release-channel-check
	@echo ""
	@echo "=== Checking generated-artifact freshness ==="
	$(MAKE) freshness
	@echo ""
# ORDER MATTERS: the audits run AFTER release-channel-check because that target
# is what runs `npm ci` in channel-core and channel. Moved earlier,
# check-node-audit fails on a fresh checkout - its build-provenance step cannot
# resolve the channel-core module before it is installed.
	@echo "=== Running the multi-process DeliveryStore guard ==="
	$(MAKE) test-channel-core-process-guard
	@echo ""
	@echo "=== Running vulnerability audits ==="
	$(MAKE) check-node-audit
	$(MAKE) check-go-vulnerability-audit
	@echo ""
	@echo "=== All checks passed ==="

# `make ship` is the canonical pre-tag-push gate. ALWAYS use this before
# pushing any release tag (server-v*, aw-v*, awid-v*, awid-service-v*,
# channel-v*). Do NOT substitute `make test` alone — it is a strict
# subset and will not catch packaging/build failures or e2e regressions.
#
# This target adds awid build-check + the e2e user journeys on top of
# release-all-check. All are load-bearing for releases:
#  - awid build-check (uv build + Docker image) catches awid packaging
#    issues before the GHCR/PyPI workflows do.
#  - test-e2e catches integration regressions across CLI + server +
#    awid that unit/integration tests miss in isolation.
#  - test-federation-e2e catches cross-server mail/chat federation
#    regressions that single-server user journeys cannot see.
#  - cli e2e (make -C cli e2e) runs the real-stack profile/team/Library net:
#    awid + aweb + Library from source, seeded, driven by the real aw binary.
#    It catches the materialize/team/Library regressions hermetic tests miss
#    (the class of P0s that shipped on green-plus-ACK). Requires Docker and the
#    sibling ../library + ../blueprints checkouts (see docs/e2e-library-stack.md).
#
# Banked discipline: releases 1.18.3 / 1.18.4 / 1.18.5 / 1.18.6 each
# ran `make test` instead of the canonical comprehensive gate. Even
# though GHA caught build failures downstream, the local gate should
# be the source of truth before tag-push.
ship: release-all-check
	@echo ""
	@echo "=== Running awid release check ==="
	$(MAKE) release-awid-check
	@echo ""
	@echo "=== Running federation e2e journey ==="
	$(MAKE) test-federation-e2e
	@echo ""
	@echo "=== Running e2e user journey ==="
	$(MAKE) test-e2e
	@echo ""
	@echo "=== Running profile/team/Library e2e ==="
	COMPOSE_BAKE="$${LIBRARY_E2E_COMPOSE_BAKE:-}" $(MAKE) -C cli e2e
	@echo ""
	@echo "=== ship: ALL pre-release checks passed ==="
	@echo "    server:  $(SERVER_VERSION)"
	@echo "    awid:    $(AWID_VERSION)"
	@echo "    channel: $(CHANNEL_VERSION)"
	@echo "    cli:     $(CLI_VERSION)"
	@echo ""
	@echo "    Ready for tag-push."

release-all-tag: release-cli-version-check
	@echo "=== Tagging all products ==="
	git add server/pyproject.toml server/uv.lock channel/package.json channel/package-lock.json channel/.claude-plugin/plugin.json awid/pyproject.toml awid/uv.lock
	git commit -m "release: aweb $(SERVER_VERSION), channel $(CHANNEL_VERSION), awid $(AWID_VERSION)"
	git tag "server-v$(SERVER_VERSION)"
	git tag "aw-v$(CLI_VERSION)"
	git tag "channel-v$(CHANNEL_VERSION)"
	git tag "awid-v$(AWID_VERSION)"
	git tag "awid-service-v$(AWID_VERSION)"
	@echo "Created tags: server-v$(SERVER_VERSION) aw-v$(CLI_VERSION) channel-v$(CHANNEL_VERSION) awid-v$(AWID_VERSION) awid-service-v$(AWID_VERSION)"

release-all-push: release-cli-version-check
	git push origin main
	git push origin server-v$(SERVER_VERSION)
	git push origin aw-v$(CLI_VERSION)
	git push origin channel-v$(CHANNEL_VERSION)
	git push origin awid-v$(AWID_VERSION)
	git push origin awid-service-v$(AWID_VERSION)
	$(MAKE) release-awid-site
	@echo "All tags pushed and awid site deployed. CI will publish."

clean:
	@echo "Cleaning build artifacts..."
	rm -rf server/dist/
	rm -rf server/build/
	rm -rf server/src/*.egg-info/
	rm -rf server/.pytest_cache/
	rm -rf server/.ruff_cache/
	rm -f  cli/go/aw
	chmod -R u+w cli/go/.cache/ 2>/dev/null; rm -rf cli/go/.cache/
	rm -rf channel/dist/
	rm -rf channel/node_modules/
	find . -type d -name __pycache__ -not -path '*/.venv/*' -not -path '*/node_modules/*' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name playwright-report -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name test-results -exec rm -rf {} + 2>/dev/null || true
	find . -name .DS_Store -delete 2>/dev/null || true
	@echo "Clean."
