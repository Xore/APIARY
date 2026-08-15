# galah-llm-broker -- #1420: the sole bridge between the attacker-facing
# galah sensor and the shared Ollama instance on the honeypot-llm network.
# See main.go's own doc comment for what it does and doesn't allow.
# Written from scratch (not vendored): this is this stack's own boundary
# enforcement, not third-party sensor logic.
FROM golang:1.23@sha256:60deed95d3888cc5e4d9ff8a10c54e5edc008c6ae3fba6187be6fb592e19e8c0 AS build
WORKDIR /build
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /galah-llm-broker .

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache busybox-extras
COPY --from=build /galah-llm-broker /usr/local/bin/galah-llm-broker

EXPOSE 11434

USER 65534

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
  CMD nc -z 127.0.0.1 11434 || exit 1

ENTRYPOINT ["/usr/local/bin/galah-llm-broker"]
