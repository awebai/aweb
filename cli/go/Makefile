.PHONY: help build test test-a2a tidy fmt clean

GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod
GOENV = env GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)"

help:
	@echo "Targets:"
	@echo "  build   Build ./aw"
	@echo "  test    Run unit tests"
	@echo "  test-a2a Run A2A conformance, gateway, AWID lookup, and CLI command gates"
	@echo "  tidy    go mod tidy"
	@echo "  fmt     gofmt -w ./..."
	@echo "  clean   Remove built binary"

build:
	@source_commit=$$(git rev-parse --verify HEAD) || { \
		echo "Cannot identify the source commit. Build from a Git checkout with a committed HEAD." >&2; exit 1; }; \
	$(GOENV) go build -ldflags "-X main.commit=$$source_commit" -o aw ./cmd/aw

test:
	$(GOENV) go test ./...

test-a2a:
	$(GOENV) go test ./internal/conformance ./a2a ./a2agw ./awid -count=1
	$(GOENV) go test ./cmd/aw ./cmd/aweb-a2a-gw -run A2A -count=1
	cd ../.. && cd awid && uv run pytest tests/test_a2a_publication_route.py -q

tidy:
	$(GOENV) go mod tidy

fmt:
	gofmt -w .

clean:
	rm -f aw

.PHONY: docs-check
docs-check:
	python3 scripts/check_docs_regressions.py
