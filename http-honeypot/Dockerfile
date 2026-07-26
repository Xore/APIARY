# Static Go binary in a scratch image (~8 MB, no shell/libc).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /honeypot .

FROM scratch
COPY --from=build /honeypot /honeypot

ENV LISTEN_ADDR=:8080
EXPOSE 8080

# Non-root (nobody). The log dir is a volume chowned in compose.
USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/honeypot", "-healthcheck"]

ENTRYPOINT ["/honeypot"]
