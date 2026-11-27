# Appended to the gate's image (or to candidate-gate/Dockerfile) by docker.py
# for one image build. Dependencies are fetched during preparation, before any
# test runs. Everything under /src and the runner's home is created by the
# runner's own UID, so nothing changes owner afterwards; only the system
# packages are installed as root.
RUN useradd --uid 1000 --create-home test-runner \
    && install -d -o 1000 -g 1000 /src
# Root preparation and the UID1000 runner resolve uv's default through the same
# HOME. Keep it persistent and owned by the runner; /tmp can be purged by hosts.
ENV HOME=/home/test-runner
WORKDIR /src
COPY --chown=1000:1000 . .
# The isolated runner's Postgres is 17, and pg_dump refuses a newer server, so
# the tests get the client of the same major version from PGDG. Root writes
# nothing under /src.
RUN PYTHONDONTWRITEBYTECODE=1 bash -c 'bash /src/scripts/test-egress/install-postgres-client.sh \
    && rm -rf /var/lib/apt/lists/* \
    && pg_dump --version | grep -q " 17\." \
    && python3 scripts/test-egress/test_pgdg_key.py -v'
# Headless Chromium for the tests comes from the base image: it installs the
# browser naapp-lib's Playwright locks, with its system libraries, into
# PLAYWRIGHT_BROWSERS_PATH. Every project here locks that same version, and
# package-environment's verify launches it. Tests never download a browser.
USER 1000:1000
RUN git init && git fetch source.bundle HEAD && git reset FETCH_HEAD && rm source.bundle
RUN uv sync --frozen --project server && uv sync --frozen --project awid \
    && make production-awid-sync \
    && cd cli/go && go mod download
RUN make naapp-sync
RUN uv build --project server --out-dir /tmp/server-test-build && rm -rf /tmp/server-test-build
RUN cd channel-core && npm ci --no-audit --no-fund \
    && cd ../channel && npm ci --no-audit --no-fund \
    && cd ../pi-extension && npm ci --no-audit --no-fund
USER root
ENV UV_OFFLINE=1 GOPROXY=off GOSUMDB=off NPM_CONFIG_OFFLINE=true
