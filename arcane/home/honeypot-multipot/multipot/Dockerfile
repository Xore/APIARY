# Static Go binary in a scratch image (~8 MB, no shell/libc).
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod .
COPY *.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /multipot .

FROM scratch
COPY --from=build /multipot /multipot

EXPOSE 21 25 1433 3306 5432 5900 6379 9200 27017 2375

# Non-root (nobody). All emulated ports are unprivileged inside the container.
USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/multipot", "-healthcheck"]

ENTRYPOINT ["/multipot"]
