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
RUN bash /src/scripts/test-egress/install-postgres-client.sh \
    && rm -rf /var/lib/apt/lists/* \
    && pg_dump --version | grep -q ' 17\.' \
    && python3 scripts/test-egress/test_pgdg_key.py -v
RUN uv sync --frozen --project naapp-contracts
RUN uv build --project server --out-dir /tmp/server-test-build && rm -rf /tmp/server-test-build
RUN cd channel-core && npm ci --no-audit --no-fund \
    && cd ../channel && npm ci --no-audit --no-fund \
    && cd ../pi-extension && npm ci --no-audit --no-fund
RUN chown -R 1000:1000 /src /home/test-runner
ENV UV_OFFLINE=1 GOPROXY=off GOSUMDB=off NPM_CONFIG_OFFLINE=true
