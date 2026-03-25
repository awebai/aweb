.PHONY: help build test tidy fmt clean local-cloud-validate

GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod
GOENV = env GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)"

help:
	@echo "Targets:"
	@echo "  build   Build ./aw"
	@echo "  test    Run unit tests"
	@echo "  tidy    go mod tidy"
	@echo "  fmt     gofmt -w ./..."
	@echo "  clean   Remove built binary"
	@echo "  local-cloud-validate  Boot ../aweb-cloud locally and run endpoint validation"

build:
	$(GOENV) go build -o aw ./cmd/aw

test:
	$(GOENV) go test ./...

tidy:
	$(GOENV) go mod tidy

fmt:
	gofmt -w .

clean:
	rm -f aw

.PHONY: docs-check
docs-check:
	python3 scripts/check_docs_regressions.py

local-cloud-validate:
	python3 scripts/validate_local_cloud.py
