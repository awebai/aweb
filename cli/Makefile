.PHONY: e2e e2e-up e2e-down

# Real-stack CLI e2e (default-aabq.2): bring up the awid + aweb + Library stack,
# build aw, run the AW_E2E=1 -tags e2e Go suite that drives the real binary,
# then tear down with -v. Requires Docker + sibling ../library and ../blueprints
# checkouts (auto-resolved, including from a git worktree).
# See docs/e2e-library-stack.md.
e2e:
	./scripts/e2e.sh

# Convenience: manage just the stack (the Go suite then runs against it with
# AW_E2E=1; see docs for the exact env). Mirrors the aweb-root stack targets.
e2e-up:
	../scripts/e2e-library-stack.sh up
	../scripts/e2e-library-stack.sh seed

e2e-down:
	../scripts/e2e-library-stack.sh down
