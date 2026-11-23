# Tool image for the complete local candidate suite.
FROM python:3.12-bookworm

ARG GO_VERSION=1.26.11
ARG DOCKER_COMPOSE_VERSION=5.7.1-1~debian.12~bookworm
COPY candidate-gate/check-compose-version.sh /opt/candidate/check-compose-version.sh

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash build-essential ca-certificates curl git gnupg jq make \
       postgresql-client redis-tools socat tmux unzip xz-utils zip \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
       | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
       > /etc/apt/sources.list.d/nodesource.list \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
       | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs docker-ce-cli docker-buildx-plugin "docker-compose-plugin=${DOCKER_COMPOSE_VERSION}" \
    && bash /opt/candidate/check-compose-version.sh "$DOCKER_COMPOSE_VERSION" \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture | sed 's/amd64/amd64/;s/arm64/arm64/').tar.gz" \
      | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/opt/uv:${PATH}"
ENV GOTOOLCHAIN=local

COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /uvx /opt/uv/

RUN python3 --version \
    && node --version | grep '^v22\.' \
    && test "$(go env GOVERSION)" = "go1.26.11" \
    && docker --version \
    && uv --version \
    && tmux -V

# Integration runs in this image too, with a different HOME and host UID.
# Install the Chromium shell for the locked Python and renderer Playwright
# versions in a shared path independent of the runner's home directory.
WORKDIR /opt/candidate-browser
COPY awid awid
COPY naapp-lib naapp-lib
COPY server server
RUN uv sync --frozen --project naapp-lib
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN uv run --frozen --no-sync --project naapp-lib \
        playwright install --with-deps --only-shell chromium \
    && npm ci --ignore-scripts --no-audit --no-fund --prefix naapp-lib/renderer \
    && naapp-lib/renderer/node_modules/.bin/playwright install --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX /opt/ms-playwright

# Prepare the standing user-path runtime here. The test stage itself performs
# no image builds, dependency installs or registry pulls.
RUN uv sync --frozen --no-dev --project server
COPY cli/go /opt/user-paths/go
# Standalone tool-image callers retain development builds; the candidate driver
# supplies exact identity, which the released-kernel probe checks before use.
ARG USER_PATHS_SOURCE_SHA=dev
ARG USER_PATHS_CLI_VERSION=dev
RUN test -n "$USER_PATHS_SOURCE_SHA" && test -n "$USER_PATHS_CLI_VERSION" \
    && cd /opt/user-paths/go && CGO_ENABLED=0 go build -trimpath \
       -ldflags "-X main.version=${USER_PATHS_CLI_VERSION} -X main.commit=${USER_PATHS_SOURCE_SHA} -X main.commitRepo=github.com/awebai/aweb" \
       -o /opt/user-paths/aw ./cmd/aw
COPY channel-core/package.json channel-core/package-lock.json /journey/channel-core/
WORKDIR /journey/channel-core
RUN npm ci
COPY channel-core/tsconfig.json ./
COPY channel-core/src ./src
RUN npm run build
# Released kernel/provider inputs are installed only while preparing this image.
COPY candidate-gate/released-oats /opt/user-paths/released-oats/
RUN npm ci --ignore-scripts --no-audit --no-fund --prefix /opt/user-paths/released-oats \
    && test "$(node -p 'require("/opt/user-paths/released-oats/node_modules/@awebai/oats/package.json").version')" = "0.69.19" \
    && OATS_PROBE_PROVIDER_COMMIT="$(node -p 'require("/opt/user-paths/released-oats/provider.json").commit')" \
    && OATS_PROBE_PROVIDER_REPO="$(node -p 'require("/opt/user-paths/released-oats/provider.json").repository')" \
    && git init --bare /opt/user-paths/provider.git \
    && git --git-dir=/opt/user-paths/provider.git fetch --depth=1 "$OATS_PROBE_PROVIDER_REPO" "$OATS_PROBE_PROVIDER_COMMIT" \
    && test "$(git --git-dir=/opt/user-paths/provider.git rev-parse FETCH_HEAD)" = "$OATS_PROBE_PROVIDER_COMMIT" \
    && mkdir /opt/user-paths/oats-aweb \
    && git --git-dir=/opt/user-paths/provider.git archive FETCH_HEAD oats-package | tar -x -C /opt/user-paths/oats-aweb
COPY --from=coredns/coredns:1.11.3 /coredns /opt/user-paths/coredns
# Public runtime code is consumed by the host UID, not the image builder UID.
RUN chmod -R a+rX /opt/candidate-browser /opt/user-paths /journey/channel-core
ARG USER_PATHS_SOURCE_TREE
LABEL aweb.user-paths-ready="1" aweb.user-paths-source-tree="${USER_PATHS_SOURCE_TREE}" aweb.user-paths-source-sha="${USER_PATHS_SOURCE_SHA}"
WORKDIR /
