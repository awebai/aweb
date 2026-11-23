# The container a standalone (non-gate) run uses to drive the root e2e stack's
# journeys, and the naapp packages' e2e, from inside a stack's network: the
# checkout is mounted at /src, aw is built from it, and the Docker CLI reaches
# the stack's containers through the socket.
# The candidate gate's own runner already sits in the network and needs no image.
FROM docker:28-cli AS docker-cli

FROM golang:1.26.11-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
RUN docker compose version
# The naapp packages' e2e (scripts/e2e/naapp-e2e.sh) sync and run with uv.
COPY --from=ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 /uv /usr/local/bin/uv
ENV PYTHONUNBUFFERED=1 AW_NO_UPDATE_CHECK=1
WORKDIR /src
