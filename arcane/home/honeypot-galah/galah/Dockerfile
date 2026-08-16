# github.com/0x4d31/galah -- #1420: LLM-powered HTTP honeypot, vendored
# rather than reimplemented (the prompt construction, response caching,
# and multi-provider LLM plumbing is real logic not worth rebuilding for
# one sensor). Apache-2.0 -- no copyleft concern, confirmed against the
# vendored LICENSE file.
#
# Pinned the same way beelzebub/Dockerfile and hellpot/Dockerfile pin their
# own upstream ref: building an unpinned master would change behavior
# whenever this image happens to rebuild. GALAH_REF is the commit tagged
# v1.1.1 (latest at integration time, confirmed via `git ls-remote --tags`).
#
# No source patch needed here (unlike hellpot/router_patch.py): galah's
# commonFields() (internal/logger/logger.go) resolves srcIP/srcPort purely
# from r.RemoteAddr via net.SplitHostPort -- confirmed directly against the
# vendored source, no X-Forwarded-For/X-Real-IP trust anywhere in the
# request path. Raw-port/portbridge-only (docker-compose.galah.yml),
# resolved via ip-enrichment-worker's via_port join, same as beelzebub/
# hellpot.
#
# LLM_PROVIDER/LLM_MODEL/LLM_SERVER_URL are set via environment (they carry
# `env:` tags in internal/app/args.go); everything else needs an explicit
# CLI flag below since ConfigFile/EventLogFile/CacheDBFile/RulesConfigFile
# have no env-var binding in that struct.
#
# CGO_ENABLED=1, glibc final stage, not this repo's usual static+alpine
# pattern: galah's response-cache DB (internal/cache/cache.go) opens
# "sqlite3" via mattn/go-sqlite3, a cgo binding with no pure-Go fallback,
# and galah.New() calls cache.InitializeCache() unconditionally at startup
# -- even with cache duration 0 the sqlite3 driver still has to load, so
# there's no config path around this. Confirmed live: a CGO_ENABLED=0
# build of the real pinned commit starts and fails immediately with
# "Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to
# work. This is a stub" -- not assumed from reading go.mod alone. Rather
# than gamble on alpine's gcompat shim actually satisfying a real
# dynamically-linked glibc cgo binary, the final stage reuses
# cowrie/Dockerfile's own pinned debian:bookworm-slim (same libc family as
# the golang:1.23 build stage, zero compatibility risk) plus
# netcat-openbsd for the same `nc -z` HEALTHCHECK convention alpine gives
# every other sensor here via busybox-extras.
FROM golang:1.23@sha256:60deed95d3888cc5e4d9ff8a10c54e5edc008c6ae3fba6187be6fb592e19e8c0 AS build
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
ARG GALAH_REF=8f77b85e892731cf1402963d8121c79fef0e59c7
WORKDIR /build
RUN git clone https://github.com/0x4d31/galah /build \
 && git checkout "$GALAH_REF"
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=$GALAH_REF" \
    -o /galah ./cmd/galah

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
RUN apt-get update && apt-get install -y --no-install-recommends netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /galah /usr/local/bin/galah
COPY config.yaml /config.yaml

EXPOSE 8888

USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 8888 || exit 1

ENTRYPOINT ["/usr/local/bin/galah", \
  "-c", "/config.yaml", \
  "-o", "/var/log/honeypot/event_log.json", \
  "-f", "/var/log/honeypot/cache.db"]
