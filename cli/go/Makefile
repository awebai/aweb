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
	$(GOENV) go build -o aw ./cmd/aw

test:
	$(GOENV) go test ./...

test-a2a:
	$(GOENV) go test ./internal/conformance ./a2a ./a2agw ./awid -count=1
	$(GOENV) go test ./cmd/aw -run A2A -count=1

tidy:
	$(GOENV) go mod tidy

fmt:
	gofmt -w .

clean:
	rm -f aw

.PHONY: docs-check
docs-check:
	python3 scripts/check_docs_regressions.py
