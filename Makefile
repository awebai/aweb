.PHONY: help clean test test-server test-cli test-e2e build

help:
	@echo "Targets:"
	@echo "  build       Build the aw CLI binary"
	@echo "  test        Run all tests (server + CLI)"
	@echo "  test-server Run server tests"
	@echo "  test-cli    Run CLI tests"
	@echo "  test-e2e    Run the end-to-end user journey (requires Docker)"
	@echo "  clean       Remove all build artifacts and caches"

build:
	cd cli/go && $(MAKE) build

test: test-server test-cli

test-server:
	cd server && UV_CACHE_DIR=/tmp/uv-cache PYTHONPYCACHEPREFIX=/tmp/pycache uv run pytest -q

test-cli:
	cd cli/go && GOCACHE=/tmp/go-build go test ./cmd/aw ./run -count=1

test-e2e:
	./scripts/e2e-oss-user-journey.sh

clean:
	@echo "Cleaning build artifacts..."
	rm -rf server/dist/
	rm -rf server/build/
	rm -rf server/src/*.egg-info/
	rm -rf server/.pytest_cache/
	rm -rf server/.ruff_cache/
	rm -f  cli/go/aw
	rm -rf cli/go/.cache/
	rm -rf channel/node_modules/
	find . -type d -name __pycache__ -not -path '*/.venv/*' -not -path '*/node_modules/*' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name playwright-report -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name test-results -exec rm -rf {} + 2>/dev/null || true
	find . -name .DS_Store -delete 2>/dev/null || true
	@echo "Clean."
