# syntax=docker/dockerfile:1

ARG GO_IMAGE=golang:1.26.10-alpine
ARG RUNTIME_IMAGE=alpine:3.22

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY cli/go/go.mod cli/go/go.sum ./
RUN go mod download
COPY cli/go/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/aw ./cmd/aw
COPY scripts/cross-registry-id-verifier.go /tmp/cross-registry-id-verifier.go
RUN CGO_ENABLED=0 go build -trimpath -o /out/id-tree-verifier /tmp/cross-registry-id-verifier.go

FROM node:22-alpine AS channel-build
WORKDIR /journey/channel-core
COPY channel-core/package.json channel-core/package-lock.json ./
RUN npm ci
COPY channel-core/tsconfig.json ./
COPY channel-core/src ./src
RUN npm run build

FROM ${RUNTIME_IMAGE}
RUN apk add --no-cache ca-certificates dbus gnome-keyring py3-pexpect py3-yaml nodejs
COPY --from=build /out/aw /usr/local/bin/aw
COPY --from=build /out/id-tree-verifier /usr/local/bin/id-tree-verifier
COPY scripts/cross-registry-human-journey.py /usr/local/bin/cross-registry-human-journey.py
COPY --from=channel-build /journey/channel-core/dist /journey/channel-core/dist
COPY --from=channel-build /journey/channel-core/node_modules /journey/channel-core/node_modules
COPY channel-core/package.json /journey/channel-core/package.json
COPY scripts/cross-registry-inbound-verifier.mjs /journey/scripts/cross-registry-inbound-verifier.mjs
ENTRYPOINT ["/usr/local/bin/aw"]
