# syntax=docker/dockerfile:1

ARG UV_VERSION=0.9.22

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM python:3.12-slim AS builder

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /app

COPY server/pyproject.toml server/README.md ./
COPY awid/pyproject.toml awid/README.md /awid/
RUN uv sync --no-dev --no-install-project

COPY server/src ./src/
COPY awid/src /awid/src
RUN uv sync --no-dev


FROM python:3.12-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 aweb \
    && useradd --system --uid 1001 --gid 1001 aweb

WORKDIR /app

COPY --from=builder --chown=aweb:aweb /app/.venv /app/.venv
COPY --from=builder --chown=aweb:aweb /app/src /app/src
COPY --from=builder --chown=aweb:aweb /awid /awid

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

USER aweb

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["aweb", "serve", "--host", "0.0.0.0", "--port", "8000"]
