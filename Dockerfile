# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8765 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

# git is required because awid-service and aweb-naapp are installed from sibling
# aweb repositories (pinned by commit in uv.lock); pgdbm resolves from PyPI.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# uv binary from the official image — no pip anywhere in the build.
COPY --from=ghcr.io/astral-sh/uv:0.11.21 /uv /uvx /bin/

WORKDIR /app

# Resolve dependencies from the committed lock first (cached layer), then the
# project, with `uv sync --frozen` so the build is reproducible and never re-resolves.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev
COPY . /app/
RUN uv sync --frozen --no-dev

RUN useradd --create-home --shell /usr/sbin/nologin folio
USER folio

EXPOSE 8765
CMD ["sh", "-c", "/app/.venv/bin/uvicorn folio.api:app --host 0.0.0.0 --port ${PORT:-8765}"]
