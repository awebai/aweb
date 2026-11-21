# Only the hypervisor runs in this image. The gate boots the existing VM disk.
ARG BASE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-system-x86 qemu-utils genisoimage socat \
    && rm -rf /var/lib/apt/lists/*
COPY boot.sh /usr/local/bin/boot-guest
ENTRYPOINT ["/bin/sh", "/usr/local/bin/boot-guest"]
