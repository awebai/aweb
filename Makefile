.PHONY: help clean test test-server test-awid test-cli test-channel test-e2e build release-server-check release-server-tag release-server-push release-awid-check release-awid-tag release-awid-push

SERVER_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' server/pyproject.toml | head -n 1)
AWID_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' awid/pyproject.toml | head -n 1)

help:
	@echo "Targets:"
	@echo "  build        Build the aw CLI binary"
	@echo "  test         Run all tests (server + CLI + channel)"
	@echo "  test-server  Run server tests"
	@echo "  test-awid    Run awid service tests"
	@echo "  test-cli     Run CLI tests"
	@echo "  test-channel Run channel tests"
	@echo "  test-e2e     Run the end-to-end user journey (requires Docker)"
	@echo "  release-server-check  Run server release checks and build PyPI artifacts"
	@echo "  release-server-tag    Commit the server version bump and create server-v<version>"
	@echo "  release-server-push   Push main and server-v<version> to trigger PyPI publish"
	@echo "  release-awid-check    Run awid release checks and validate the release image build"
	@echo "  release-awid-tag      Commit the awid version bump and create awid-v<version>"
	@echo "  release-awid-push     Push main and awid-v<version> to trigger GHCR publish"
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
