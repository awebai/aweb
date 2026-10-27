# Tool image for the complete local candidate suite.
FROM python:3.12-bookworm

ARG GO_VERSION=1.26.10

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
    && apt-get install -y --no-install-recommends nodejs docker-ce-cli docker-buildx-plugin docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture | sed 's/amd64/amd64/;s/arm64/arm64/').tar.gz" \
      | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/opt/uv:${PATH}"
ENV GOTOOLCHAIN=local

COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /uvx /opt/uv/

RUN python3 --version \
    && node --version | grep '^v22\.' \
    && test "$(go env GOVERSION)" = "go1.26.10" \
    && docker --version \
    && uv --version \
    && tmux -V

# Integration runs in this image too, with a different HOME and host UID.
# Install the browser at build time through the same locked Playwright as the
# naapp tests, in a shared path independent of the runner's home directory.
WORKDIR /opt/candidate-browser
COPY awid awid
COPY naapp-lib naapp-lib
COPY server server
RUN uv sync --frozen --project naapp-lib
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN uv run --frozen --no-sync --project naapp-lib \
        playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX /opt/ms-playwright
WORKDIR /
