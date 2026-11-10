# syntax=docker/dockerfile:1
# Build context: the aweb repository root, because logs depends on the in-repo
# awid and naapp-lib:
#   docker build -f naapp/logs/Dockerfile --build-arg SOURCE_COMMIT=$(git rev-parse HEAD) .
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# The exact commit the image is built from: /health reports it as the build.
ARG SOURCE_COMMIT
RUN test "${#SOURCE_COMMIT}" -eq 40 \
    && case "$SOURCE_COMMIT" in *[!0-9a-f]*) exit 1;; esac
ENV LOGS_GIT_SHA=$SOURCE_COMMIT
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT

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
COPY --from=ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 /uv /uvx /bin/

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

# A fixed UID, so mounted key files can be owned by the service user alone.
RUN groupadd --gid 10001 logs \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin logs
USER 10001:10001

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD ["/app/.venv/bin/python", "-c", "import os,urllib.parse,urllib.request; r=urllib.request.Request('http://127.0.0.1:'+os.environ.get('PORT','8765')+'/ready',headers={'Host':urllib.parse.urlsplit(os.environ['LOGS_PUBLIC_ORIGIN']).netloc}); urllib.request.urlopen(r,timeout=4).close()"]
# Configured by its LOGS_ environment (LOGS_DATABASE_URL, LOGS_PUBLIC_ORIGIN,
# LOGS_CONSOLE_ORIGIN, LOGS_APP_ID, LOGS_APP_KEY_FILES, LOGS_EMAIL_*); the key
# files and the mail password file are mounted, never built in.
CMD ["sh", "-c", "/app/.venv/bin/uvicorn aweb_logs.app:serve --factory --host 0.0.0.0 --port ${PORT:-8765}"]
