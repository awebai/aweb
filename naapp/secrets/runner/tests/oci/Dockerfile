# Linux-only local runtime proofs. This is not the release runner image or launcher.
FROM debian:trixie@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5
RUN apt-get update && apt-get install --no-install-recommends -y \
    python3 python3-venv runc crun umoci busybox-static gcc libc6-dev util-linux \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir /disk && chown 10000:10000 /disk
USER 10000:10000
