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

FROM ${RUNTIME_IMAGE}
RUN apk add --no-cache ca-certificates dbus gnome-keyring py3-pexpect py3-yaml
COPY --from=build /out/aw /usr/local/bin/aw
COPY --from=build /out/id-tree-verifier /usr/local/bin/id-tree-verifier
COPY scripts/cross-registry-human-journey.py /usr/local/bin/cross-registry-human-journey.py
ENTRYPOINT ["/usr/local/bin/aw"]
