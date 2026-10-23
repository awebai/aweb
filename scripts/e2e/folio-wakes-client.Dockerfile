# The real wakes client runs beside the services, including inside candidate-gate.
FROM golang:1.24.13-bookworm AS cli
ENV GOMAXPROCS=2 CGO_ENABLED=0
WORKDIR /src
COPY cli/go/go.mod cli/go/go.sum ./
RUN go mod download
COPY cli/go/ ./
RUN go build -p=2 -o /out/aw ./cmd/aw

FROM node:22-bookworm-slim AS channel
WORKDIR /src
COPY channel-core/package.json channel-core/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY channel-core/ ./
RUN npm run build && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM docker:28-cli AS docker-cli

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=cli /out/aw /usr/local/bin/aw
COPY --from=channel /usr/local/bin/node /usr/local/bin/node
COPY --from=channel /src/dist /workspace/channel-core/dist
COPY --from=channel /src/package.json /workspace/channel-core/package.json
COPY --from=channel /src/node_modules /workspace/channel-core/node_modules
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY scripts/e2e/ /workspace/scripts/e2e/
RUN AW_NO_UPDATE_CHECK=1 aw version && node --version && docker compose version && python3 --version
ENV PYTHONUNBUFFERED=1
WORKDIR /workspace
CMD ["python3", "/workspace/scripts/e2e/folio_wakes.py"]
