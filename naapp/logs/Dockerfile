# syntax=docker/dockerfile:1
# Build context: the aweb repository root, because logs depends on the in-repo
# awid and naapp-lib:  docker build -f naapp/logs/Dockerfile .
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

# /app mirrors the repository layout, so logs' path sources ../../awid and
# ../../naapp-lib resolve in the image as they do in a checkout. Only the paths the
# service needs are copied, so nothing local to a checkout (.venv, .env) enters
# the image.
COPY awid/pyproject.toml awid/README.md /app/awid/
COPY awid/src /app/awid/src
COPY naapp-lib/pyproject.toml naapp-lib/README.md /app/naapp-lib/
COPY naapp-lib/src /app/naapp-lib/src

WORKDIR /app/naapp/logs

# Resolve dependencies from the committed lock first (cached layer), then the
# project, with `uv sync --frozen` so the build is reproducible and never re-resolves.
COPY naapp/logs/pyproject.toml naapp/logs/uv.lock naapp/logs/README.md ./
RUN uv sync --frozen --no-install-project --no-dev
COPY naapp/logs/src ./src
RUN uv sync --frozen --no-dev

RUN useradd --create-home --shell /usr/sbin/nologin logs
USER logs

EXPOSE 8765
# Configured by its LOGS_ environment (LOGS_DATABASE_URL, LOGS_PUBLIC_ORIGIN,
# LOGS_APP_ID, LOGS_APP_KEY_FILES); the key files are mounted, never built in.
CMD ["sh", "-c", "/app/.venv/bin/uvicorn aweb_logs.app:serve --factory --host 0.0.0.0 --port ${PORT:-8765}"]
