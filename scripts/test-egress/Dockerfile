# Dependencies are fetched during image preparation, before any test runs.
ARG TOOLS_IMAGE=aweb-test-tools
FROM ${TOOLS_IMAGE}
RUN useradd --uid 1000 --create-home test-runner
ENV UV_CACHE_DIR=/tmp/uv-cache HOME=/home/test-runner
WORKDIR /src
COPY . .
RUN git init && git fetch source.bundle HEAD && git reset FETCH_HEAD && rm source.bundle
RUN uv sync --frozen --project server && uv sync --frozen --project awid \
    && cd cli/go && go mod download
RUN uv build --project server --out-dir /tmp/server-test-build && rm -rf /tmp/server-test-build
RUN cd channel-core && npm ci --no-audit --no-fund \
    && cd ../channel && npm ci --no-audit --no-fund \
    && cd ../pi-extension && npm ci --no-audit --no-fund
RUN chown -R 1000:1000 /src /home/test-runner /tmp/uv-cache
ENV UV_OFFLINE=1 GOPROXY=off GOSUMDB=off NPM_CONFIG_OFFLINE=true
