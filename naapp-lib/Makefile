# Pull-request CI type-checks each naapp package through `make typecheck`, and
# the candidate gate runs `make test` (the root Makefile's NAAPP_PACKAGES).

.PHONY: lint typecheck test

lint: typecheck
	uv run ruff check .

typecheck:
	uv run mypy src

# With an owned worker service plan (AWEB_SERVER_TEST_WORKERS, set by the
# candidate gate's isolated runner), each xdist worker gets its own services.
# Worksteal spreads single tests: four history tests in one module take about
# 100 s each, and loadscope would keep them on one worker.
test:
	uv run pytest -q $(if $(filter-out 0,$(AWEB_SERVER_TEST_WORKERS)),-n $(AWEB_SERVER_TEST_WORKERS) --dist worksteal --max-worker-restart=0,)
