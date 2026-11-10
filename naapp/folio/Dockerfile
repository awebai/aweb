# syntax=docker/dockerfile:1
# Build context: the aweb repository root, because folio depends on the in-repo
# awid and naapp-lib:  docker build -f naapp/folio/Dockerfile .
FROM scratch AS candidate-wheels
COPY .candidate-artifacts /

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8765 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv binary from the official image — no pip anywhere in the build.
COPY --from=ghcr.io/astral-sh/uv:0.11.21 /uv /uvx /bin/

# /app mirrors the repository layout, so folio's path sources ../../awid and
# ../../naapp-lib resolve in the image as they do in a checkout. Only the paths the
# service needs are copied, so nothing local to a checkout (.venv, .env) enters
# the image.
COPY awid/pyproject.toml awid/README.md /app/awid/
COPY awid/src /app/awid/src
COPY naapp-lib/pyproject.toml naapp-lib/README.md /app/naapp-lib/
COPY naapp-lib/src /app/naapp-lib/src

COPY --from=candidate-wheels / /candidate-artifacts
COPY scripts/install_release_wheels.py /usr/local/lib/aweb-install-wheels.py
ARG CANDIDATE_WHEEL_MODE=0
ARG CANDIDATE_SOURCE_TREE
RUN python /usr/local/lib/aweb-install-wheels.py --validate-context --directory /candidate-artifacts \
    --wheel-mode "$CANDIDATE_WHEEL_MODE" --source-tree "$CANDIDATE_SOURCE_TREE"

WORKDIR /app/naapp/folio

# Resolve dependencies from the committed lock first (cached layer), then the
# project, with `uv sync --frozen` so the build is reproducible and never re-resolves.
COPY naapp/folio/pyproject.toml naapp/folio/uv.lock naapp/folio/README.md ./
RUN uv sync --frozen --no-install-project --no-dev --no-install-package awid-service --no-install-package aweb-naapp
COPY naapp/folio/src ./src
COPY naapp/folio/skills ./skills
RUN if [ "$CANDIDATE_WHEEL_MODE" = 1 ]; then \
      uv sync --frozen --no-dev --no-editable --no-install-package awid-service --no-install-package aweb-naapp \
      && python /candidate-artifacts/install.py --source-tree "$CANDIDATE_SOURCE_TREE" --directory /candidate-artifacts --python /app/.venv/bin/python awid-service aweb-naapp; \
    else uv sync --frozen --no-dev; fi

RUN useradd --create-home --shell /usr/sbin/nologin folio
USER folio

EXPOSE 8765
COPY scripts/release-wheel-entrypoint.sh /usr/local/bin/release-wheel-entrypoint.sh
ENV RELEASE_WHEEL_DIR=/candidate-artifacts RELEASE_WHEEL_PYTHON=/app/.venv/bin/python \
    RELEASE_WHEEL_PACKAGES="awid-service aweb-naapp"
ENTRYPOINT ["sh", "/usr/local/bin/release-wheel-entrypoint.sh"]
CMD ["sh", "-c", "/app/.venv/bin/uvicorn folio.api:app --host 0.0.0.0 --port ${PORT:-8765}"]
