# Appended to candidate-gate/Dockerfile by docker.py for one image build.
# Dependencies are fetched during preparation, before any test runs.
RUN useradd --uid 1000 --create-home test-runner
ENV UV_CACHE_DIR=/tmp/uv-cache HOME=/home/test-runner
WORKDIR /src
COPY . .
RUN git init && git fetch source.bundle HEAD && git reset FETCH_HEAD && rm source.bundle
RUN uv sync --frozen --project server && uv sync --frozen --project awid \
    && cd cli/go && go mod download
# The isolated runner's Postgres is 17, and pg_dump refuses a newer server, so
# the tests get the client of the same major version from PGDG.
RUN curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
       | gpg --dearmor -o /etc/apt/keyrings/pgdg.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-17 redis-server \
    && rm -rf /var/lib/apt/lists/* \
    && pg_dump --version | grep -q ' 17\.'
RUN make naapp-sync
# Headless Chromium for naapp-lib's browser tests, installed by the Playwright
# version naapp-lib locks, with its system libraries. The tests run headless,
# so only the headless shell is installed. Tests never download a browser.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN UV_CACHE_DIR=/tmp/uv-cache uv run --frozen --no-sync --project naapp-lib \
        playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX /opt/ms-playwright
RUN uv build --project server --out-dir /tmp/server-test-build && rm -rf /tmp/server-test-build
RUN cd channel-core && npm ci --no-audit --no-fund \
    && cd ../channel && npm ci --no-audit --no-fund \
    && cd ../pi-extension && npm ci --no-audit --no-fund
RUN chown -R 1000:1000 /src /home/test-runner /tmp/uv-cache
ENV UV_OFFLINE=1 GOPROXY=off GOSUMDB=off NPM_CONFIG_OFFLINE=true
