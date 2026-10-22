# Linux-only local runtime proofs. This is not the release runner image or launcher.
FROM debian:trixie@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5
RUN apt-get update && apt-get install --no-install-recommends -y \
    python3 python3-venv runc crun umoci busybox-static gcc libc6-dev util-linux \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir /disk && chown 10000:10000 /disk
# Install only the runner's locked dependencies, including the existing I/O-free
# pages validators. Named contexts contain explicit source files, not a repo/home.
RUN python3 -m venv /tools && /tools/bin/pip install --no-cache-dir uv==0.13.1
ENV UV_PYTHON_INSTALL_DIR=/opt/pythons
ENV UV_PROJECT_ENVIRONMENT=/venv
COPY --from=runner pyproject.toml uv.lock /source/naapp/secrets/runner/
COPY --from=runner src/ /source/naapp/secrets/runner/src/
COPY --from=values pyproject.toml /source/naapp/secrets/values/
COPY --from=values src/ /source/naapp/secrets/values/src/
COPY --from=naapp pyproject.toml README.md /source/naapp-lib/
COPY --from=naapp src/ /source/naapp-lib/src/
WORKDIR /source/naapp/secrets/runner
RUN /tools/bin/uv sync --locked --python 3.12
ENV PATH=/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 10000:10000
