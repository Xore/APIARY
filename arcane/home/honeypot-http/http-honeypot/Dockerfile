# Static Go binary in a scratch image (~8 MB, no shell/libc).
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
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
