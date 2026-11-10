# syntax=docker/dockerfile:1

ARG UV_VERSION=0.9.22

FROM scratch AS candidate-wheels
COPY .candidate-artifacts /

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM python:3.12-slim AS builder

COPY --from=uv /uv /usr/local/bin/uv

# Build-time network resilience: on a slow link, uv's default of many
# concurrent wheel downloads starves small requests (build-backend metadata)
# past its 30 s per-request timeout. Fewer streams and a longer timeout make
# the build slow instead of failed. Builder stage only; nothing at runtime.
ENV UV_HTTP_TIMEOUT=300 UV_CONCURRENT_DOWNLOADS=4

WORKDIR /app

COPY --from=candidate-wheels / /candidate-artifacts
COPY scripts/install_release_wheels.py /usr/local/lib/aweb-install-wheels.py
ARG CANDIDATE_WHEEL_MODE=0
ARG CANDIDATE_SOURCE_TREE
RUN python /usr/local/lib/aweb-install-wheels.py --validate-context --directory /candidate-artifacts \
    --wheel-mode "$CANDIDATE_WHEEL_MODE" --source-tree "$CANDIDATE_SOURCE_TREE"

COPY server/pyproject.toml server/uv.lock server/README.md ./
COPY awid/pyproject.toml awid/README.md /awid/
COPY naapp-lib/pyproject.toml naapp-lib/README.md /naapp-lib/
RUN uv sync --frozen --no-dev --no-install-project --no-install-package awid-service --no-install-package aweb-naapp

COPY server/src ./src/
COPY awid/src /awid/src
COPY naapp-lib/src /naapp-lib/src
RUN if [ "$CANDIDATE_WHEEL_MODE" = 1 ]; then \
      python /candidate-artifacts/install.py --source-tree "$CANDIDATE_SOURCE_TREE" --directory /candidate-artifacts --python /app/.venv/bin/python aweb awid-service aweb-naapp; \
    else uv sync --frozen --no-dev; fi


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
COPY --from=builder --chown=aweb:aweb /naapp-lib /naapp-lib

COPY --from=builder /candidate-artifacts /candidate-artifacts

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

USER aweb

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

COPY scripts/release-wheel-entrypoint.sh /usr/local/bin/release-wheel-entrypoint.sh
ENV RELEASE_WHEEL_DIR=/candidate-artifacts RELEASE_WHEEL_PYTHON=/app/.venv/bin/python \
    RELEASE_WHEEL_PACKAGES="aweb awid-service aweb-naapp"
ENTRYPOINT ["sh", "/usr/local/bin/release-wheel-entrypoint.sh"]
CMD ["aweb", "serve", "--host", "0.0.0.0", "--port", "8000"]
