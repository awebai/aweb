# syntax=docker/dockerfile:1

ARG UV_VERSION=0.9.22

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM python:3.12-slim AS builder

COPY --from=uv /uv /usr/local/bin/uv

# Build-time network resilience: on a slow link, uv's default of many
# concurrent wheel downloads starves small requests (build-backend metadata)
# past its 30 s per-request timeout. Fewer streams and a longer timeout make
# the build slow instead of failed. Builder stage only; nothing at runtime.
ENV UV_HTTP_TIMEOUT=300 UV_CONCURRENT_DOWNLOADS=4

WORKDIR /app

COPY awid/pyproject.toml awid/uv.lock awid/README.md ./awid/
COPY server/pyproject.toml server/README.md ./server/
RUN cd awid && uv sync --frozen --no-dev --no-install-project

COPY awid/src ./awid/src
COPY server/src ./server/src
RUN cd awid && uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 awid \
    && useradd --system --uid 1001 --gid 1001 awid

WORKDIR /app

COPY --from=builder --chown=awid:awid /app/awid/.venv /app/awid/.venv
COPY --from=builder --chown=awid:awid /app/awid/src /app/awid/src
COPY --from=builder --chown=awid:awid /app/server /app/server

ENV PATH="/app/awid/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

USER awid

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8010/health || exit 1

CMD ["awid", "--host", "0.0.0.0", "--port", "8010"]
