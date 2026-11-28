# The Node suites have separate lockfiles and a local file: dependency from the
# host adapters to channel-core. Install all three before any Node test target
# so both `make test` and focused Node targets work from a clean checkout.
test-node-deps:
	cd channel-core && npm ci --no-audit --no-fund
	cd channel && npm ci --no-audit --no-fund
	cd pi-extension && npm ci --no-audit --no-fund

# Local server fixtures consume these Node artifacts before their first test.
.PHONY: prepare-server-node
prepare-server-node: test-node-deps
	cd channel-core && npm run build
	cd channel && npm run build
	cd pi-extension && npm run build
