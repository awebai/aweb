# Appended to candidate-gate/Dockerfile by docker.py for one image build.
# Dependencies are fetched during preparation, before any test runs.
RUN useradd --uid 1000 --create-home test-runner
# Root preparation and the UID1000 runner resolve uv's default through the same
# HOME. Keep it persistent and owned by the runner; /tmp can be purged by hosts.
ENV HOME=/home/test-runner
WORKDIR /src
COPY . .
RUN git init && git fetch source.bundle HEAD && git reset FETCH_HEAD && rm source.bundle
RUN uv sync --frozen --project server && uv sync --frozen --project awid \
    && make production-awid-sync \
    && cd cli/go && go mod download
# The isolated runner's Postgres is 17, and pg_dump refuses a newer server, so
# the tests get the client of the same major version from PGDG.
RUN bash /src/scripts/test-egress/install-pgdg-key.sh \
       /src/scripts/test-egress/keys/ACCC4CF8.asc /etc/apt/keyrings/pgdg.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-17 \
    && rm -rf /var/lib/apt/lists/* \
    && pg_dump --version | grep -q ' 17\.' \
    && python3 scripts/test-egress/test_pgdg_key.py -v
# Fetch the historical CLI while preparation has registry access. The unit suite
# verifies and runs these bytes on its isolated network.
RUN python3 scripts/fetch_released_aw.py --version 1.36.58 /opt/aw-1.36.58 \
    && cd /opt/aw-1.36.58 && sha256sum aw > aw.sha256 && chmod 0555 aw && rm ./*.tgz
RUN make naapp-sync
# Headless Chromium for naapp-lib's browser tests, installed by the Playwright
# version naapp-lib locks, with its system libraries. The tests run headless,
# so only the headless shell is installed. Tests never download a browser.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN uv run --frozen --no-sync --project naapp-lib \
        playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX /opt/ms-playwright
RUN uv build --project server --out-dir /tmp/server-test-build && rm -rf /tmp/server-test-build
RUN cd channel-core && npm ci --no-audit --no-fund \
    && cd ../channel && npm ci --no-audit --no-fund \
    && cd ../pi-extension && npm ci --no-audit --no-fund
RUN chown -R 1000:1000 /src /home/test-runner
ENV UV_OFFLINE=1 GOPROXY=off GOSUMDB=off NPM_CONFIG_OFFLINE=true
