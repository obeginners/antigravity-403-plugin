FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/plugin ./cmd/plugin

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 appuser
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

WORKDIR /app
COPY --from=builder /out/plugin /app/plugin
COPY config.example.yaml /app/config.example.yaml

LABEL org.opencontainers.image.title="antigravity-403-plugin" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$COMMIT \
      org.opencontainers.image.created=$BUILD_DATE

USER appuser
EXPOSE 9813

# Optional runtime settings can be provided through env vars:
# PLUGIN_CONFIG=/app/config.yaml
# PLUGIN_AUTH_DIR=/app/auths
ENTRYPOINT ["/app/plugin"]
