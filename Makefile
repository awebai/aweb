.PHONY: help clean test test-server test-awid test-cli test-node-deps test-channel test-channel-name-live-contract test-channel-core test-channel-core-process-guard test-pi-extension test-release-local-gate-contract test-release-train test-release-gate-contract check-release-gate-residue test-sot-source-inventories test-vector-provenance test-federation-error-reference regenerate-federation-error-reference test-cli-reference regenerate-cli-reference test-mcp-tools-reference regenerate-mcp-tools-reference prepare-oas-test-root check-oas-launch-environment-contract check-oas-pi-launch-order test-oas test-oas-proof-helpers test-oas-attached-principal-e2e test-oas-pi-resident-e2e test-tmux-guard test-a2a test-e2e test-federation-harness test-federation-e2e test-a2a-gateway-e2e check-a2a-copy-guardrails check-extension-docs build \
	freshness check-go-vulnerability-audit check-node-audit check-exception-deadlines test-go-vulnerability-audit \
	selfhost-up selfhost-down selfhost-logs awid-up awid-down awid-logs \
	e2e-library-stack e2e-library-stack-up e2e-library-stack-seed e2e-library-stack-down \
	awid-prod-verify awid-prod-dump awid-prod-restore awid-prod-migrate \
	check-aw-commit-repo-stamp check-cli-go-tidy check-cli-release-vcs-stamps check-server-locked-suite \
	check-awid-locked-suite \
	release-a2a-gateway-check release-a2a-gateway-tag release-a2a-gateway-push \
	test-release-cli-version release-cli-version-check release-cli-tag release-cli-push \
	test-channel-integration \
	list-awid-site-docs sync-awid-site-docs check-awid-site-docs release-awid-site \
	release-plan release-run release-receipt test-release-driver test-release-runnerless test-release-receipt-process test-pointer-adapter test-pointer-adapter-ac-pin test-release-repository-measurement test-release-adopted-preplan test-release-federation-skew measure-release-federation-skew-control test-release-channel-pi-skew test-release-persisted-state-skew test-release-receipt-archive test-release-skew-cli-server measure-release-skew-cli-server cli-server-skew-cell test-npm-exact-publish test-pypi-exact-publish test-oci-exact-publish \
	cli-e2e _release-gate-version-authority _release-gate-channel-version _release-node-deps \
	_release-unit-channel _release-unit-channel-core _release-unit-pi _release-oas _release-marketplace-pointer \
	_release-artifact-server _release-artifact-awid-package _release-artifact-awid-image \
	_release-artifact-channel _release-artifact-pi _release-artifact-skills _release-artifact-a2a-image

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
	@echo "  test-sot-source-inventories Verify canonical SOT tables and REST routers against source"
	@echo "  test-vector-provenance Enforce root-only public conformance vectors and consumer paths"
	@echo "  test-federation-error-reference Verify generated stable error/status/retryability reference"
	@echo "  regenerate-federation-error-reference Regenerate the stable federation error reference"
	@echo "  test-cli-reference Verify generated CLI help and root-command completeness"
	@echo "  regenerate-cli-reference Regenerate the CLI reference from live Cobra help"
	@echo "  test-mcp-tools-reference Verify the generated MCP inventory against live registration"
	@echo "  regenerate-mcp-tools-reference Regenerate the MCP inventory from live registration"
	@echo "  prepare-oas-test-root Materialize the clean committed OAS test pin"
	@echo "  check-oas-launch-environment-contract Verify the pinned OAS seam dependency"
	@echo "  check-oas-pi-launch-order Prove pinned Pi command construction; real execution is opt-in"
	@echo "    real execution: OAS_RUN_REAL_PI_LAUNCH_ORDER=1 make test-oas"
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
	@echo "  test-federation-harness Validate the 51-row direct-core historical inventory and mutations"
	@echo "  test-federation-e2e Run the direct/non-ingress historical topology and OSS federation journeys (requires Docker)"
	@echo "  test-a2a-gateway-e2e Run the A2A gateway Docker journey against real aweb+awid"
	@echo "  check-a2a-copy-guardrails Block premature A2A trust/E2EE copy"
	@echo "  check-extension-docs Verify extension docs, source events, vectors, and authority map"
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
	@echo "  RELEASING - one driver owns every artifact:"
	@echo "    Hosted:"
	@echo "      release-plan AUTHORITY=github-workflow-artifacts"
	@echo "      release-run AUTHORITY=github-workflow-artifacts PLAN_ID=.. PLAN_ARTIFACT_ID=.. STAGE_ARTIFACT=.."
	@echo "    Runnerless (explicit human risk acceptance):"
	@echo "      release-plan AUTHORITY=local-runnerless STORE_ROOT=.."
	@echo "      release-run AUTHORITY=local-runnerless STORE_ROOT=.. PLAN_ID=.. PLAN_ARTIFACT_ID=.. LOCAL_ADAPTER='component@sha=/abs/adapter' LOCAL_RISK_AUTHORIZATION=.."
	@echo "    release-receipt                     read a sealed receipt"
	@echo "    See the 'release' skill for exact argument forms and hazards:"
	@echo "    publication is not delivery, publication is immutable."
	@echo ""
	@echo "  Legacy per-artifact checks not yet cut over:"
	@echo "    release-a2a-gateway-check, release-cli-version-check"
	@echo ""
	@echo "  release-awid-site                     deploy awid landing page"
	@echo "  clean        Remove all build artifacts and caches"

build:
	cd cli/go && $(MAKE) build

# ORDER IS LOAD-BEARING FOR THE FIRST FOUR - do not sort this list.
#
# These cheap committed-source controls run first on every ordinary test run.
# The expensive complete release proof is owned by the clean local-Docker gate.
test: check-aw-commit-repo-stamp test-release-local-gate-contract test-release-train test-release-gate-contract check-cli-go-tidy test-python-locks test-sot-source-inventories test-vector-provenance test-federation-error-reference test-federation-authority-mutations test-federation-harness test-cli-reference test-mcp-tools-reference test-server test-awid test-cli test-channel test-channel-name-live-contract test-channel-core test-pi-extension test-oas test-oas-proof-helpers test-tmux-guard test-release-cli-version test-release-driver test-release-runnerless test-release-receipt-process test-pointer-adapter test-release-repository-measurement test-release-skew-cli-server test-npm-exact-publish test-pypi-exact-publish test-oci-exact-publish test-go-vulnerability-audit

# Editable AWID metadata is repeated in both committed Python locks. Check both
# without repair, then prove a missing dependent-lock dependency is rejected.
test-python-locks:
	bash scripts/check-python-locks.sh
	bash scripts/check-python-locks.sh --self-test

# Canonical implementation SOT inventories are derived from ordered migrations
# and FastAPI mounts. The unit suite includes source-addition and stale-doc
# negative controls so this gate proves it can fail rather than only matching
# today's tree.
test-sot-source-inventories:
	python3 scripts/check_sot_source_inventories.py
	python3 -m unittest discover -s scripts -p "test_check_sot_source_inventories.py" -v

# Public protocol vectors have one repository-root authority. The checker also
# inventories explicitly local fixture directories and proves each failure mode.
test-vector-provenance:
	python3 scripts/check_vector_provenance.py
	python3 scripts/check_vector_provenance.py --self-test

# The public support/error table is generated from the canonical code source and
# cross-checked against the selected-policy vector. The focused suite proves
# additions, duplicate reasons, Retry-After drift, and stale output fail closed.
test-federation-error-reference:
	python3 scripts/generate_federation_error_reference.py --check
	python3 -m unittest discover -s scripts -p "test_generate_federation_error_reference.py" -v

regenerate-federation-error-reference:
	python3 scripts/generate_federation_error_reference.py

# The strict authority vector readers must kill the two concrete security
# weakenings found during the independent core review.
test-federation-authority-mutations:
	python3 scripts/test_federation_authority_mutations.py

# The direct-core historical harness inventories all 51 contract rows without
# claiming ingress coverage and kills topology/provenance weakening mutations.
test-federation-harness:
	python3 scripts/check_federation_harness.py
	python3 scripts/check_federation_harness.py --self-test
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run --frozen pytest -q tests/test_federation_preactivation_harness.py

# The public CLI inventory comes from live Cobra help. Root completion is an
# independent exact-set control so grouped and Additional Commands cannot vanish
# while freshness stays green; the self-test also proves add/remove/stale paths.
test-cli-reference:
	bash scripts/regenerate-cli-reference.sh --self-test

regenerate-cli-reference:
	bash scripts/regenerate-cli-reference.sh

# The public MCP inventory comes from an offline FastMCP registration. The
# explicit category map must cover the live tool set exactly, and the unit suite
# proves that both newly registered and removed tools fail closed.
test-mcp-tools-reference:
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run --frozen python ../scripts/regenerate_mcp_reference.py --check
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run --frozen python -m unittest discover -s ../scripts -p "test_regenerate_mcp_reference.py" -v

regenerate-mcp-tools-reference:
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run --frozen python ../scripts/regenerate_mcp_reference.py

# Regenerate every committed generated artifact (uv locks, cli reference,
# reserved-app-ids, resource packs, and the claude-channel + pi bundles) and
# fail on drift. The clean local release gate runs it before publication.
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

# The deadline half of the audit above, split out because it is the only part
# that can run without the pinned toolchain, a govulncheck scan or the advisory
# database. It reads .github/go-vulnerability-exceptions.json and compares dates,
# so it is deterministic and cheap.
#
# It is separate because a deferral lapses on a DATE, not on a commit. The audit
# runs at release; if no release happens across a deadline, the deferral simply
# stops being deferred and nothing says so. This target is what the scheduled
# workflow runs daily. It does NOT run the audit, and the release-only decision
# for that audit is unchanged.
# The audit's own unit suite. It belongs in `make test` where the audit itself
# does not: it runs against fixtures and the checked-in exceptions file, with no
# toolchain, no scanner and no advisory database, and none of its assertions
# depend on today's date. Before this it was invoked by nothing, so the audit's
# ability to fail was asserted in a comment and tested nowhere.
test-go-vulnerability-audit:
	python3 -m unittest discover -s scripts -p "test_check_go_vulnerability_audit.py" -v

check-exception-deadlines:
	python3 scripts/check_go_vulnerability_audit.py \
		--deadlines-only \
		--exceptions .github/go-vulnerability-exceptions.json

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
	if ! python3 scripts/check-awid-site-doc-links.py $(AWID_SITE_DOC_MIRRORS); then status=1; fi; \
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

test-channel-name-live-contract:
	python3 scripts/e2e/test_channel_name_live_contract.py

# channel/package.json excludes test/integration.test.ts from `npm test`, so
# `make test` never ran the one test that drives Channel against a REAL aweb
# server. It was green by absence: the first time it ran it failed on a stale
# assertion that contradicted shipped acknowledgement behaviour. It needs Docker
# and Postgres, so it belongs with the other real-stack journeys rather than in
# `make test` - but it belongs somewhere, and this is somewhere.
# Deliberately NO AWEB_SKEW_DIRECTION. With a direction set the journey emits a
# skew observation, which requires the five exact-server inputs (wheel, wheel
# sha, version, constraints, constraints sha); ship supplies none of them, so a
# clean run would die on "skew observation lacks server runtime inventory"
# rather than exercise the journey. Ship builds the server from source and this
# target exercises Channel against THAT. Measuring against a PUBLISHED server is
# the skew harness's job, with the exact artifacts it resolves itself.
test-channel-integration:
	cd channel && npm run test:integration

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

test-release-local-gate-contract:
	python3 scripts/e2e/test_release_local_gate_contract.py

test-release-train:
	python3 scripts/e2e/test_release_train.py

check-release-gate-residue:
	python3 scripts/check_release_gate_residue.py

test-release-gate-contract:
	python3 scripts/e2e/test_release_gate_contract.py

prepare-oas-test-root:
	@if [ "$(abspath $(OAS_TEST_ROOT))" = "$(abspath $(OAS_PINNED_ROOT))" ]; then \
		node scripts/prepare-pinned-oas.mjs --pin-file "$(OAS_PIN_FILE)" --target "$(OAS_PINNED_ROOT)"; \
	else \
		echo "Using explicit OAS_TEST_ROOT override without modifying it: $(OAS_TEST_ROOT)" >&2; \
	fi

check-oas-launch-environment-contract: prepare-oas-test-root
	@OAS_TEST_ROOT="$(OAS_TEST_ROOT)" node scripts/check-oas-launch-environment-contract.mjs

# Construction always runs. Real Pi execution is explicitly opt-in because it
# consumes network/model tokens; the script reports the omitted layer on stderr.
# Its runtime branch uses a named session on an isolated socket, with the tmux
# guard first on PATH for the entire child process tree.
check-oas-pi-launch-order: prepare-oas-test-root
	@PATH="$(CURDIR)/scripts/guard-bin:$$PATH" OAS_TEST_ROOT="$(OAS_TEST_ROOT)" node scripts/check-oas-pi-launch-order.mjs

# The real spawn seam validates both the aweb capability command and its selected
# Pi runtime even with --no-launch. Use only tools built/locked by this checkout;
# ambient developer installs must not decide whether the release test passes.
test-oas: check-oas-launch-environment-contract check-oas-pi-launch-order build test-node-deps
	PATH="$(CURDIR)/cli/go:$(CURDIR)/pi-extension/node_modules/.bin:$$PATH" OAS_TEST_ROOT="$(OAS_TEST_ROOT)" node --test oas/test/*.test.mjs

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
	cd cli/go && GOCACHE=/tmp/go-build go test ./internal/conformance ./a2a ./a2agw ./awid ./tools/a2a-gateway-check-workspace -count=1
	cd cli/go && GOCACHE=/tmp/go-build go test ./cmd/aw ./cmd/aweb-a2a-gw -run A2A -count=1
	cd awid && uv run pytest tests/test_a2a_publication_route.py -q
	./scripts/check-a2a-copy-guardrails.sh

test-e2e:
	./scripts/e2e-oss-user-journey.sh
	./scripts/test-e2e-controller-key-absence-guard.sh

test-federation-e2e:
	PATH="$(CURDIR)/scripts/guard-bin:$$PATH" ./scripts/e2e-federation-authority.sh
	./scripts/e2e-oss-federation.sh

test-a2a-gateway-e2e:
	./scripts/e2e-a2a-gateway-docker.sh

check-a2a-copy-guardrails:
	./scripts/check-a2a-copy-guardrails.sh

check-extension-docs:
	python3 scripts/check-extension-docs.py
	python3 scripts/check-extension-docs.py --self-test

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

# ── Release-shaped local-gate checks ────────────────────────────────
# PyPI and image publication are thin release-branch workflows. Their expensive
# suites and release-shaped builds are part of scripts/release-local-gate.sh;
# these lock checks remain named inputs to that complete local proof.

# Deterministic, no network, no toolchain: it reads two checked-in files and compares
# them. Safe to run anywhere, which is why it is a target rather than only a release step.
check-aw-commit-repo-stamp:
	./scripts/check-aw-commit-repo-stamp.sh

# goreleaser runs `go mod tidy` as a before hook, and hooks run AFTER its git-state
# validation - so an untidy manifest passes validation, the hook then rewrites go.mod
# and go.sum, and the build stamps vcs.modified=true on a tree goreleaser has already
# called clean. `-diff` asks the same question without writing: a gate that repaired
# the manifest would erase the condition it exists to report.
#
# This is the first target in `test:` to touch the Go module cache, so a module-resolution or
# network failure surfaces here rather than in test-cli - the message will name the tidy check
# for a problem that is not the tidy check's.
check-cli-go-tidy:
	cd cli/go && go mod tidy -diff

# Reproduce GoReleaser's derived repository and pre-build dist/metadata.json,
# then inspect the complete two-product, six-platform artifact matrix. This also
# proves an unrelated unignored file still produces vcs.modified=true.
check-cli-release-vcs-stamps:
	./scripts/check-cli-release-vcs-stamps.sh

check-server-locked-suite:
	cd server && uv lock --check
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run --frozen pytest -q

check-awid-locked-suite:
	cd awid && uv lock --check
	cd awid && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run --frozen pytest -q

# ── A2A gateway release ─────────────────────────────────────────────

release-a2a-gateway-check:
	./scripts/check-a2a-copy-guardrails.sh
	cd cli/go && GOCACHE=/tmp/go-build go test ./a2a ./a2agw ./awid ./cmd/aweb-a2a-gw ./tools/a2a-gateway-check-workspace -count=1
	docker build -f cli/go/Dockerfile.a2a-gw \
		--build-arg VERSION=$(A2A_GATEWAY_VERSION) \
		--build-arg RELEASE_TAG=a2a-gw-v$(A2A_GATEWAY_VERSION) \
		--build-arg COMMIT=$$(git rev-parse HEAD) \
		--build-arg DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t a2a-gateway:release-test cli/go
	@set -eu; workspace="$$(mktemp -d)"; trap 'rm -rf "$$workspace"' EXIT; \
		(cd cli/go && go run ./tools/a2a-gateway-check-workspace -output "$$workspace"); \
		docker run --rm \
			--user "$$(id -u):$$(id -g)" \
			-v "$(CURDIR)/docs/examples/a2a-gateway.yaml:/config/gateway.yaml:ro" \
			-v "$$workspace:/workspace:ro" \
			a2a-gateway:release-test \
			aweb-a2a-gw -config /config/gateway.yaml -workspace-dir /workspace -check
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

# ── CLI release ──────────────────────────────────────────────────────

# What must ship, in what order, from the declared component graph and
# authoritative remote state. Exit 1 when a declared input is unsatisfied.
# AUTHORITY selects an allowlisted digest-authority kind; STORE_ROOT the
# durable artifact store; EXTERNAL_CONTEXT repeatable repository=checkout
# mappings for external pin contexts.
release-plan:
	@python3 scripts/release_driver.py $(if $(AUTHORITY),--authority "$(AUTHORITY)") $(if $(STORE_ROOT),--store-root "$(STORE_ROOT)") $(foreach c,$(EXTERNAL_CONTEXT),--external-context "$(c)") plan $(foreach o,$(ONLY),--only "$(o)")

# Executes an anchored frozen plan over available publish lanes; fails closed
# naming every gap. PLAN_ID and PLAN_ARTIFACT_ID are required.
# STAGE_ARTIFACT (repeatable, space-separated) binds hosted lane references.
# DELIVERY_PROOF (repeatable) carries restart evidence for a component whose
# users keep running old code until a restart. It is NOT required to publish:
# restart evidence cannot exist before the version does, so publication records
# the obligation as OUTSTANDING and this discharges it afterwards. Supply it
# only when the evidence is real and recorded with the authority:
#   DELIVERY_PROOF='component=channel,obligation=delivery-restart-proof,evidence_id=<id>,digest=<sha256>'
# POINTER_ADAPTER (repeatable) performs a forced pointer's effect - the
# marketplace version bump, or the AC pin update - in the target repository:
#   POINTER_ADAPTER='marketplace-pointer=/abs/scripts/pointer-adapter-marketplace-pointer.py'
# Without it a channel or skills release stops at the pointer node, because
# publishing to npm reaches nobody until the marketplace advertises the version.
# G5_AUTHORIZATION records a human accepting unmeasured runtime support for
# this exact release. Accepted on every authority - who may defer is a question
# about the human, not about which runner built the artifact - and bound to the
# source, the frozen plan and exactly the edges being deferred, so it cannot be
# reused for another release:
#   G5_AUTHORIZATION='who=<w>,when=<t>,source=<40hex>,plan=<64hex>,edges=<64hex>[+<64hex>],risk=<text>'
# The edge ids are the canonical identities release-plan prints under
# deferrable_runtime_contracts. They are content hashes, not display
# strings: a<->b would alias the two server<->server edges.
# Runnerless mode is first-class and needs no GitHub identity:
#   AUTHORITY=local-runnerless STORE_ROOT=<durable-dir>
#   LOCAL_ADAPTER='component@<reviewed-source-sha>=/absolute/direct-adapter'
#   LOCAL_RISK_AUTHORIZATION='who,when,risk accepted'
# DEFER_G5 is NOT a companion to that record and never travels with it in
# shorthand: it needs its own G5_AUTHORIZATION below, on any authority.
# See docs/runnerless-release.md.
release-run:
	@python3 scripts/release_driver.py $(if $(AUTHORITY),--authority "$(AUTHORITY)") $(if $(STORE_ROOT),--store-root "$(STORE_ROOT)") $(foreach c,$(EXTERNAL_CONTEXT),--external-context "$(c)") release-run --plan-id "$(PLAN_ID)" --plan-artifact-id "$(PLAN_ARTIFACT_ID)" $(if $(RESUME),--resume) $(if $(MANIFEST_ID),--manifest-id "$(MANIFEST_ID)") $(if $(ALLOW_LOCAL_AUTHORITY),--allow-local-authority) $(foreach a,$(APPROVAL),--approval "$(a)") $(foreach s,$(STAGE_ARTIFACT),--stage-artifact "$(s)") $(foreach d,$(DELIVERY_PROOF),--delivery-proof "$(d)") $(foreach p,$(POINTER_ADAPTER),--pointer-adapter "$(p)") $(foreach a,$(LOCAL_ADAPTER),--local-adapter "$(a)") $(if $(LOCAL_RISK_AUTHORIZATION),--local-risk-authorization "$(LOCAL_RISK_AUTHORIZATION)") $(if $(DEFER_G5),--defer-g5) $(if $(G5_AUTHORIZATION),--g5-authorization "$(G5_AUTHORIZATION)")

# Verifies an anchored receipt against its anchored frozen plan. ARTIFACT_ID,
# PLAN_ID and PLAN_ARTIFACT_ID are required; digests resolve through the
# configured authority, never from caller-presented values.
release-receipt:
	@python3 scripts/release_driver.py $(if $(AUTHORITY),--authority "$(AUTHORITY)") $(if $(STORE_ROOT),--store-root "$(STORE_ROOT)") release-receipt --artifact-id "$(ARTIFACT_ID)" --plan-id "$(PLAN_ID)" --plan-artifact-id "$(PLAN_ARTIFACT_ID)" $(foreach s,$(STAGE_ARTIFACT),--stage-artifact "$(s)") $(foreach p,$(POINTER_ADAPTER),--pointer-adapter "$(p)") $(foreach d,$(DELIVERY_PROOF),--delivery-proof "$(d)") $(if $(OBSERVATION_FILE),--observation-file "$(OBSERVATION_FILE)")

test-release-runnerless:
	python3 scripts/e2e/test_release_runnerless.py

# The official receipt reader across a REAL process boundary. In-process
# rd.main() misses argument serialization, the production parser, and
# process-boundary observer construction - the seam that repeatedly disagreed
# with injected fixtures.
test-release-receipt-process:
	python3 scripts/e2e/test_release_receipt_process.py

# The marketplace pointer adapter against a real local git remote: clone,
# commit, push and read back. Publishing without moving this pointer reaches
# nobody, so the round trip is the thing worth proving.
test-pointer-adapter:
	python3 scripts/e2e/test_pointer_adapter_marketplace.py
	$(MAKE) test-pointer-adapter-ac-pin

test-pointer-adapter-ac-pin:
	python3 scripts/e2e/test_pointer_adapter_ac_pin.py
	python3 -m unittest scripts.e2e.test_release_driver.GraphContractTests.test_a_pointer_advertises_what_its_pin_actually_holds

test-release-repository-measurement:
	python3 scripts/e2e/test_release_repository_measurement.py

test-release-driver: test-release-adopted-preplan test-release-channel-pi-skew test-release-skew-cli-server test-release-receipt-archive test-release-persisted-state-skew test-release-federation-skew
	python3 scripts/e2e/test_release_driver.py
	python3 scripts/e2e/test_release_driver_cli.py
	python3 scripts/e2e/test_release_adapter.py

test-release-federation-skew:
	python3 scripts/e2e/test_release_federation_skew.py

measure-release-federation-skew-control:
	PYTHONPATH=scripts python3 -c 'from release_federation_skew import WheelResolver, prove_route_controls; prove_route_controls(WheelResolver())'

test-release-receipt-archive:
	python3 scripts/e2e/test_release_receipt_archive.py

test-release-adopted-preplan:
	python3 scripts/e2e/test_release_adopted_preplan.py

test-release-channel-pi-skew:
	python3 scripts/e2e/test_release_channel_pi_skew.py

# G5 CLI/server child: exact artifact resolution, registration, evidence, and
# shell parameterization. This focused target never starts Docker or dispatches
# a workflow.
test-release-skew-cli-server:
	python3 scripts/e2e/test_release_skew_cli_server.py
	python3 scripts/e2e/test_cli_server_skew_shell.py
	cd cli/go && go test -tags e2e ./e2e -count=1

# Execute one already-computed SkewCell. The child harness supplies AW_BIN,
# AWEB_E2E_SERVER_WHEEL, and AW_SKEW_DIRECTION; this target does not select a
# matrix cell and never builds either release artifact.
cli-server-skew-cell:
	bash scripts/e2e/run_cli_server_skew_cell.sh

# Measure candidate aw against the published server named by a canonical
# aweb.measurement-input-manifest.v1. The input grants measurement only: it is
# not a release staged manifest and never invents a staged server lane_ref. The
# result still requires independent workflow-artifact anchoring before its
# identity may be declared in release/components.toml.
measure-release-skew-cli-server:
	python3 scripts/release_skew_cli_server.py measure \
		--measurement-input "$(MEASUREMENT_INPUT)" \
		$(foreach v,$(SUPPORTED_SERVER),--supported-server "$(v)") \
		--negative-server "$(or $(NEGATIVE_SERVER),1.26.31)" \
		--output "$(OUTPUT)"

# Channel and Pi measure separately: each edge keeps its own frozen matrix and
# its own evidence root, so one component's reports can never satisfy the
# other's completeness inventory. Neither declares a version floor - Channel/Pi
# has no reviewed negative-only version, and the mark-read mutation control at
# finish is its known-red evidence.
#
# MEASUREMENT_INPUT is an aweb.measurement-input-manifest.v1, NOT a release
# staged manifest: it binds one already-staged candidate client and the
# already-published server it is measured against, grants measurement-only
# authority, and creates no release receipt. The output is
# incomplete-unanchored and still requires independent anchoring before its
# identity may be declared in release/components.toml.
measure-release-channel-skew:
	python3 scripts/release_channel_pi_skew.py measure-channel \
		--measurement-input "$(MEASUREMENT_INPUT)" \
		$(foreach v,$(SUPPORTED_SERVER),--supported-server "$(v)") \
		$(if $(EVIDENCE_ROOT),--evidence-root "$(EVIDENCE_ROOT)") \
		--output "$(OUTPUT)"

measure-release-pi-skew:
	python3 scripts/release_channel_pi_skew.py measure-pi \
		--measurement-input "$(MEASUREMENT_INPUT)" \
		$(foreach v,$(SUPPORTED_SERVER),--supported-server "$(v)") \
		$(if $(EVIDENCE_ROOT),--evidence-root "$(EVIDENCE_ROOT)") \
		--output "$(OUTPUT)"

test-release-persisted-state-skew:
	python3 scripts/e2e/test_release_persisted_state_skew.py

test-npm-exact-publish:
	bash scripts/e2e/test_npm_exact_publish.sh

test-pypi-exact-publish:
	bash scripts/e2e/test_pypi_exact_publish.sh

test-oci-exact-publish:
	bash scripts/e2e/test_oci_exact_publish.sh

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

# ── Unified release ──────────────────────────────────────────────────

# Internal steps consumed only by scripts/release-local-gate.sh's fixed map.
# They are intentionally absent from help; release-prepare will invoke the gate.
_release-gate-version-authority:
	@test -n "$(RELEASE_BASE_SHA)" || (echo "RELEASE_BASE_SHA is required"; exit 2)
	./scripts/check-server-version-bump-test.sh
	./scripts/check-server-version-bump.sh "$(RELEASE_BASE_SHA)"
	./scripts/cli-release-version.sh check "$(CLI_VERSION)"

_release-gate-channel-version:
	@test "$(CHANNEL_VERSION)" = "$(CHANNEL_PLUGIN_VERSION)" || \
		(echo "channel package.json != plugin.json"; exit 1)

_release-node-deps:
	cd channel-core && npm ci --no-audit --no-fund
	cd channel && npm ci --no-audit --no-fund
	cd pi-extension && npm ci --no-audit --no-fund

_release-unit-channel:
	cd channel && npm test

_release-unit-channel-core:
	cd channel-core && npm test

_release-unit-pi:
	cd pi-extension && npm test

_release-oas: check-oas-launch-environment-contract check-oas-pi-launch-order
	PATH="$(CURDIR)/cli/go:$(CURDIR)/pi-extension/node_modules/.bin:$$PATH" OAS_TEST_ROOT="$(OAS_TEST_ROOT)" node --test oas/test/*.test.mjs

_release-oas-proof-helpers:
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" python3 scripts/e2e/test_oas_pinned_checkout.py
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" python3 scripts/e2e/test_oas_principal_proof.py
	OAS_TEST_ROOT="$(OAS_TEST_ROOT)" python3 scripts/e2e/test_oas_tmux_safety.py

_release-marketplace-pointer:
	python3 scripts/e2e/test_pointer_adapter_marketplace.py

_release-artifact-server:
	rm -rf server/dist
	cd server && uv build
	test -f server/dist/aweb-$(SERVER_VERSION).tar.gz
	test -f server/dist/aweb-$(SERVER_VERSION)-py3-none-any.whl

_release-artifact-awid-package:
	rm -rf awid/dist
	cd awid && uv build
	test -f awid/dist/awid_service-$(AWID_VERSION).tar.gz
	test -f awid/dist/awid_service-$(AWID_VERSION)-py3-none-any.whl

_release-artifact-awid-image:
	@mkdir -p /tmp/aweb-release-gate
	docker buildx build --platform linux/amd64,linux/arm64 \
		-f awid/Dockerfile.release --output type=oci,dest=/tmp/aweb-release-gate/awid.oci.tar .
	test -s /tmp/aweb-release-gate/awid.oci.tar

_release-artifact-channel:
	cd channel && npm run build
	cd channel && npm pack --ignore-scripts --pack-destination /tmp/aweb-release-gate

_release-artifact-pi:
	cd pi-extension && npm run build
	cd pi-extension && npm pack --ignore-scripts --pack-destination /tmp/aweb-release-gate

_release-artifact-skills:
	cd packages/claude-skills && npm pack --ignore-scripts --pack-destination /tmp/aweb-release-gate
	cd packages/claude-ai-skills && ./build-zips.sh
	@test "$$(find packages/claude-ai-skills/dist -name 'aweb-*.zip' -type f | wc -l | tr -d ' ')" = 5

_release-artifact-a2a-image:
	@mkdir -p /tmp/aweb-release-gate
	docker buildx build --platform linux/amd64,linux/arm64 \
		-f cli/go/Dockerfile.a2a-gw \
		--build-arg VERSION=$(A2A_GATEWAY_VERSION) \
		--build-arg RELEASE_TAG=a2a-gw-v$(A2A_GATEWAY_VERSION) \
		--build-arg COMMIT=$$(git rev-parse HEAD) \
		--build-arg DATE=1970-01-01T00:00:00Z \
		--output type=oci,dest=/tmp/aweb-release-gate/a2a-gateway.oci.tar cli/go
	test -s /tmp/aweb-release-gate/a2a-gateway.oci.tar

# Real-stack CLI/Library journey retained in the fixed local release gate.
cli-e2e:
	COMPOSE_BAKE="$${LIBRARY_E2E_COMPOSE_BAKE:-}" $(MAKE) -C cli e2e

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
