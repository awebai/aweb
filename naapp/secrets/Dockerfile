# syntax=docker/dockerfile:1
# Build from the repository root: docker build -f naapp/secrets/Dockerfile .
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ARG SOURCE_COMMIT
RUN test "${#SOURCE_COMMIT}" -eq 40 \
    && case "$SOURCE_COMMIT" in *[!0-9a-f]*) exit 1;; esac
ENV SECRETS_GIT_SHA=$SOURCE_COMMIT
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_HTTP_TIMEOUT=300 \
    UV_CONCURRENT_DOWNLOADS=4

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 /uv /bin/uv

COPY awid/pyproject.toml awid/README.md /app/awid/
COPY awid/src /app/awid/src
COPY naapp-lib/pyproject.toml naapp-lib/README.md /app/naapp-lib/
COPY naapp-lib/src /app/naapp-lib/src
COPY naapp/secrets/values/pyproject.toml naapp/secrets/values/README.md /app/naapp/secrets/values/
COPY naapp/secrets/values/src /app/naapp/secrets/values/src

WORKDIR /app/naapp/secrets
COPY naapp/secrets/pyproject.toml naapp/secrets/uv.lock naapp/secrets/README.md ./
RUN uv sync --frozen --no-install-project --no-dev
COPY naapp/secrets/src ./src
RUN uv sync --frozen --no-dev \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin secrets

USER secrets
EXPOSE 8770
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD ["/app/.venv/bin/python", "-c", "import os,urllib.request; r=urllib.request.Request('http://127.0.0.1:8770/ready',headers={'Host':__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(os.environ['SECRETS_PUBLIC_ORIGIN']).netloc}); urllib.request.urlopen(r,timeout=4).close()"]
CMD ["/app/.venv/bin/uvicorn", "aweb_secrets.deployment:create_app", "--factory", "--host", "0.0.0.0", "--port", "8770", "--no-access-log", "--no-proxy-headers"]
