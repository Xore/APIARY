# nsmfoo/dicompot — DICOM (medical imaging) honeypot. Vendored rather than
# ported (#238, #413): the actual DICOM PDU/DIMSE state machine (association
# negotiation, C-FIND/C-STORE/C-GET), imported unmodified from
# github.com/nsmfoo/dicompot below, is built on GRAIL's go-dicom and isn't
# worth reimplementing from scratch for one honeypot.
#
# main.go in this directory replaces upstream's own server/dicompot.go
# entrypoint -- see its own doc comment for why: upstream's rotatefilehook
# file logging never actually writes (confirmed directly, not assumed --
# hook.Fire() discards lumberjack's Write() error silently), and
# ConnectionState carries no attacker address at all, so neither the
# protocol logic nor anything else in the vendored package needed to
# change, only the wiring around it.
#
# Pinned the same way tanner/tanner/Dockerfile pins TANNER_REF: building an
# unpinned master would change behavior whenever this image happens to
# rebuild. Fetched via `go get`, not `git clone` -- main.go is a normal
# dependent of the github.com/nsmfoo/dicompot module, not that module's own
# main package, so there is no local source tree to clone at all here. The
# pin itself lives in go.mod/go.sum (committed, like every other Go
# sensor's), not as a rebuild-time ARG -- that's what lets CI's `go test`
# and `go build` run against the exact same resolved deps this image builds.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go proxyproto.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /dicompot .

FROM alpine:3.20
RUN apk add --no-cache busybox-extras
COPY --from=build /dicompot /usr/local/bin/dicompot

# No sample DICOM files bundled: an attacker's C-FIND/C-GET/C-STORE attempts
# get logged regardless of whether any (fake) image data exists behind
# them -- that's the honeypot signal, not realistic image content, and it
# avoids bundling any medical-imaging-shaped sample data at all. /var/log/
# honeypot is deliberately not created here -- like every other sensor's
# image, it's a bind-mount point (docker-compose.dicompot.yml), so its
# permissions come from the host directory, not this image.
RUN mkdir -p /dicom-store

EXPOSE 11112

USER 65534

ENV LOG_FILE=/var/log/honeypot/dicompot.json

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD nc -z 127.0.0.1 11112 || exit 1

ENTRYPOINT ["/usr/local/bin/dicompot"]
