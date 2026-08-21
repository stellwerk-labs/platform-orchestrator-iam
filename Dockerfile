FROM golang:1.26.2-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

# https://stackoverflow.com/questions/36279253/go-compiled-binary-wont-run-in-an-alpine-docker-container-on-ubuntu-host
ENV CGO_ENABLED=0 GOOS=linux GOWORK=off

COPY . .

RUN --mount=target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /opt/server/server ./cmd/server && \
    go build -ldflags="-s -w" -o /opt/server/authorization-migrate ./cmd/authorization-migrate

FROM gcr.io/distroless/static:nonroot AS final

LABEL org.opencontainers.image.source="https://github.com/stellwerk-labs/platform-orchestrator-iam"

WORKDIR /opt/server

COPY --chown=nonroot:nonroot --from=builder /opt/server .

ENTRYPOINT ["/opt/server/server"]
