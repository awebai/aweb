.PHONY: help clean test test-server test-awid test-cli test-channel test-e2e build \
	selfhost-up selfhost-down selfhost-logs awid-up awid-down awid-logs \
	release-server-check release-server-tag release-server-push \
	release-awid-check release-awid-tag release-awid-push \
	release-awid-pypi-tag release-awid-pypi-push \
	release-channel-check release-channel-tag release-channel-push \
	release-cli-tag release-cli-push \
	release-awid-site \
	release-all-check release-all-tag release-all-push

SERVER_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' server/pyproject.toml | head -n 1)
AWID_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' awid/pyproject.toml | head -n 1)
CHANNEL_VERSION := $(shell node -p "require('./channel/package.json').version" 2>/dev/null)
CHANNEL_PLUGIN_VERSION := $(shell node -p "require('./channel/.claude-plugin/plugin.json').version" 2>/dev/null)
CLI_VERSION := $(SERVER_VERSION)

help:
	@echo "Targets:"
	@echo "  build        Build the aw CLI binary"
	@echo "  test         Run all tests (server + CLI + channel + awid)"
	@echo "  test-server  Run server tests"
	@echo "  test-awid    Run awid service tests"
	@echo "  test-cli     Run CLI tests"
	@echo "  test-channel Run channel tests"
	@echo "  test-e2e     Run the end-to-end user journey (requires Docker)"
	@echo "  selfhost-up / -down / -logs   Manage the OSS docker-compose stack (aweb + awid)"
	@echo "  awid-up / -down / -logs       Manage the standalone awid docker-compose stack"
	@echo ""
	@echo "  release-all-check   Validate ALL products before release"
	@echo "  release-all-tag     Commit version bumps and create all tags"
	@echo "  release-all-push    Push main and all tags to trigger CI"
	@echo ""
	@echo "  release-server-check / -tag / -push   aweb server (PyPI)"
	@echo "  release-channel-check / -tag / -push  channel plugin (npm)"
	@echo "  release-awid-check / -tag / -push     awid service (GHCR Docker)"
	@echo "  release-awid-pypi-tag / -push         awid service (PyPI)"
	@echo "  release-cli-tag / -push               aw CLI (goreleaser)"
	@echo "  release-awid-site                     deploy awid landing page"
	@echo "  clean        Remove all build artifacts and caches"

build:
	cd cli/go && $(MAKE) build

test: test-server test-awid test-cli test-channel

test-server:
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run pytest -q

test-awid:
	cd awid && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run pytest -q

test-cli:
	cd cli/go && GOCACHE=/tmp/go-build go test ./cmd/aw ./run -count=1

test-channel:
	cd channel && npm test

test-e2e:
	./scripts/e2e-oss-user-journey.sh

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

release-server-check:
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run pytest -q
	rm -rf server/dist/
	cd server && uv build
	test -f server/dist/aweb-$(SERVER_VERSION).tar.gz
	test -f server/dist/aweb-$(SERVER_VERSION)-py3-none-any.whl
	@ls -lh server/dist/aweb-$(SERVER_VERSION).tar.gz server/dist/aweb-$(SERVER_VERSION)-py3-none-any.whl

release-server-tag:
	@git rev-parse --verify "server-v$(SERVER_VERSION)" >/dev/null 2>&1 && (echo "Tag server-v$(SERVER_VERSION) already exists."; exit 1) || true
	git add server/pyproject.toml server/uv.lock Makefile .claude/skills/release-pypi/SKILL.md server/README.md
	git commit -m "release: aweb server $(SERVER_VERSION)"
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

# ── Awid site deploy ────────────────────────────────────────────────

release-awid-site:
	@echo "Syncing docs into awid site..."
	cp docs/identity-guide.md awid/site/static/identity-guide.md
	cp docs/trust-model.md awid/site/static/trust-model.md
	git add awid/site/static/identity-guide.md awid/site/static/trust-model.md
	@if ! git diff --cached --quiet -- awid/site/static/identity-guide.md awid/site/static/trust-model.md; then \
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

release-cli-tag:
	@git rev-parse --verify "aw-v$(CLI_VERSION)" >/dev/null 2>&1 && (echo "Tag aw-v$(CLI_VERSION) already exists."; exit 1) || true
	git tag "aw-v$(CLI_VERSION)"
	@echo "Created tag aw-v$(CLI_VERSION)."

release-cli-push:
	git push origin aw-v$(CLI_VERSION)

# ── Unified release ──────────────────────────────────────────────────

release-all-check:
	@echo "=== Validating versions ==="
	@echo "  server:  $(SERVER_VERSION)"
	@echo "  awid:    $(AWID_VERSION)"
	@echo "  channel: $(CHANNEL_VERSION) (plugin: $(CHANNEL_PLUGIN_VERSION))"
	@echo "  cli:     $(CLI_VERSION)"
	@test "$(CHANNEL_VERSION)" = "$(CHANNEL_PLUGIN_VERSION)" || \
		(echo "ERROR: channel package.json != plugin.json"; exit 1)
	@echo ""
	@echo "=== Running all tests ==="
	$(MAKE) test
	@echo ""
	@echo "=== Building artifacts ==="
	$(MAKE) release-server-check
	$(MAKE) release-channel-check
	@echo ""
	@echo "=== All checks passed ==="

release-all-tag:
	@echo "=== Tagging all products ==="
	git add server/pyproject.toml server/uv.lock channel/package.json channel/package-lock.json channel/.claude-plugin/plugin.json awid/pyproject.toml awid/uv.lock
	git commit -m "release: aweb $(SERVER_VERSION), channel $(CHANNEL_VERSION), awid $(AWID_VERSION)"
	git tag "server-v$(SERVER_VERSION)"
	git tag "aw-v$(CLI_VERSION)"
	git tag "channel-v$(CHANNEL_VERSION)"
	git tag "awid-v$(AWID_VERSION)"
	git tag "awid-service-v$(AWID_VERSION)"
	@echo "Created tags: server-v$(SERVER_VERSION) aw-v$(CLI_VERSION) channel-v$(CHANNEL_VERSION) awid-v$(AWID_VERSION) awid-service-v$(AWID_VERSION)"

release-all-push:
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
