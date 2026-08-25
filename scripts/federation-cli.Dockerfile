# syntax=docker/dockerfile:1

ARG GO_IMAGE=golang:1.24.13-alpine
ARG RUNTIME_IMAGE=alpine:3.22

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY cli/go/go.mod cli/go/go.sum ./
RUN go mod download
COPY cli/go/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/aw ./cmd/aw

FROM ${RUNTIME_IMAGE}
RUN apk add --no-cache ca-certificates
COPY --from=build /out/aw /usr/local/bin/aw
ENTRYPOINT ["/usr/local/bin/aw"]
