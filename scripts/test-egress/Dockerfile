# Dependencies are fetched during image preparation, before any test runs.
ARG TOOLS_IMAGE=aweb-test-tools
FROM ${TOOLS_IMAGE}
ENV UV_CACHE_DIR=/tmp/uv-cache
WORKDIR /src
COPY . .
RUN git init && git fetch source.bundle HEAD && git reset FETCH_HEAD && rm source.bundle
RUN uv sync --frozen --project server && uv sync --frozen --project awid \
    && cd cli/go && go mod download
RUN cd channel-core && npm ci --no-audit --no-fund \
    && cd ../channel && npm ci --no-audit --no-fund \
    && cd ../pi-extension && npm ci --no-audit --no-fund
ENV UV_OFFLINE=1 GOPROXY=off GOSUMDB=off NPM_CONFIG_OFFLINE=true
