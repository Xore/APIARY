# Static Go binary in a scratch image (~8 MB, no shell/libc).
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
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
