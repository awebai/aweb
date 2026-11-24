.PHONY: help build test tidy fmt clean

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

build:
	@source_commit=$$(git rev-parse --verify HEAD) || { \
		echo "Cannot identify the source commit. Build from a Git checkout with a committed HEAD." >&2; exit 1; }; \
	$(GOENV) go build -ldflags "-X main.commit=$$source_commit" -o aw ./cmd/aw

test:
	$(GOENV) go test ./...

tidy:
	$(GOENV) go mod tidy

fmt:
	gofmt -w .

clean:
	rm -f aw
