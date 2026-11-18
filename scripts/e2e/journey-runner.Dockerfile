# The container a standalone (non-gate) run uses to drive the root e2e stack's
# journeys from inside its network: the checkout is mounted at /src, aw is built
# from it, and the Docker CLI reaches the stack's containers through the socket.
# The candidate gate's own runner already sits in the network and needs no image.
FROM docker:28-cli AS docker-cli

FROM golang:1.26.11-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
ENV PYTHONUNBUFFERED=1 AW_NO_UPDATE_CHECK=1
WORKDIR /src
