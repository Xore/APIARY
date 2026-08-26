# github.com/SentryPeer/SentryPeer (#1424) -- SIP honeypot/decoy, vendored
# rather than reimplemented (RFC3261 SIP parsing + peer-to-peer bad-actor
# list distribution is real logic not worth rebuilding for one sensor).
# Dual GPL-2.0-only/GPL-3.0-only (COPYING) -- same posture already taken for
# Dionaea's GPL-2.0-or-later: internal/private use only, never redistributed,
# so copyleft has no practical effect here. Confirmed directly against the
# vendored COPYING file, not assumed.
#
# Pinned the same way beelzebub/Dockerfile pins BEELZEBUB_REF: building an
# unpinned master would change behavior whenever this image happens to
# rebuild. SENTRYPEER_REF is the commit checked out during #1424 integration
# (no tagged release newer than this exists at the time of writing).
#
# Adapted from upstream's own Dockerfile (SentryPeer/SentryPeer:Dockerfile),
# not written from scratch -- same build recipe, pinned instead of `git
# clone` off master, plus this stack's own runtime conventions (healthcheck,
# resource limits, JSON logging turned on via env instead of left off).
# Peer-to-peer bad-actor-list sharing (opendht) and the HTTP webhook/API are
# both left compiled-in (upstream builds them unconditionally) but never
# enabled at runtime here -- this repo's own #1415 epic and
# docs/community-threat-intel-sharing.md already declined third-party
# threat-intel sharing for the same reason T-Pot's own ewsposter/hpfeeds
# were declined; SENTRYPEER_PEER_TO_PEER/SENTRYPEER_API/SENTRYPEER_WEBHOOK
# are simply never set.
FROM alpine:edge@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000 AS builder
RUN apk add --no-cache autoconf automake autoconf-archive \
	git sqlite-dev cmocka-dev util-linux-dev curl-dev \
	pcre2-dev jansson-dev libmicrohttpd-dev build-base \
	libtool rust rust-bindgen clang22-libclang cargo cmake python3
RUN apk add --no-cache -X https://dl-cdn.alpinelinux.org/alpine/edge/testing \
    libosip2-dev
RUN apk add --no-cache -X https://dl-cdn.alpinelinux.org/alpine/edge/testing \
    opendht-dev
ARG SENTRYPEER_REF=008be5ebb451467ca9c76763717bc75916e3fcac
RUN git clone https://github.com/SentryPeer/SentryPeer.git /SentryPeer \
 && cd /SentryPeer && git checkout "$SENTRYPEER_REF"
WORKDIR /SentryPeer
# #1424: crash-on-embedded-NUL-byte fix, see nul_byte_crash_patch.py for why
COPY nul_byte_crash_patch.py .
RUN python3 nul_byte_crash_patch.py && rm nul_byte_crash_patch.py
RUN sed -i '/AM_LDFLAGS=/d' Makefile.am
RUN ./bootstrap.sh
RUN ./configure
RUN make
RUN make check
RUN make install

FROM alpine:edge@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000
RUN apk -U add --no-cache \
    libcurl \
    jansson \
    libmicrohttpd \
    libuuid \
    pcre2 \
    sqlite-libs \
    busybox-extras && \
    apk -U add --no-cache -X https://dl-cdn.alpinelinux.org/alpine/edge/testing \
    libosip2 && \
    apk -U add --no-cache -X https://dl-cdn.alpinelinux.org/alpine/edge/testing \
    opendht-libs && \
    mkdir -p /var/lib/sentrypeer /var/log/sentrypeer && \
    addgroup -g 2000 sentrypeer && \
    adduser -S -s /bin/ash -u 2000 -D -g 2000 sentrypeer && \
    chown -R sentrypeer:sentrypeer /var/lib/sentrypeer /var/log/sentrypeer && \
    rm -rf /root/* /var/cache/apk/*

# Installed outside /opt/sentrypeer deliberately: docker-compose.sentrypeer.yml
# mounts a tmpfs at exactly that path (for the cert/key writability below),
# which shadows/empties whatever the image had there at container start --
# confirmed live, the binary silently disappeared and the container failed
# to start ("stat ./sentrypeer: no such file or directory") the first time
# this was actually deployed through the real compose file rather than a
# standalone `docker run`.
COPY --from=builder /SentryPeer/sentrypeer /usr/local/bin/sentrypeer

# /var/log/sentrypeer is a bind-mount point (docker-compose.sentrypeer.yml),
# same convention as every other sensor's image.

# We never expose 5061/TLS (only plain SIP on 5060), but the vendored
# sentrypeer_rust/src/config.rs::generate_self_signed_cert() always runs on
# startup if no cert is found, and hardcodes the relative path "cert.pem"
# regardless of SENTRYPEER_CERT/SENTRYPEER_KEY -- confirmed directly in
# source, not assumed (those env vars are only read on the *load an
# existing cert* path). Confirmed live: the unmodified image crashes with
# "Failed to create TLS cert and key" then panics, because WORKDIR is
# root-owned and the non-root sentrypeer user can't write there. Making
# WORKDIR itself writable is simpler than patching upstream for a feature
# this sensor doesn't use.
RUN mkdir -p /opt/sentrypeer && chown sentrypeer:sentrypeer /opt/sentrypeer

USER sentrypeer:sentrypeer
WORKDIR /opt/sentrypeer/

ENV SENTRYPEER_JSON_LOG=1
ENV SENTRYPEER_JSON_LOG_FILE=/var/log/sentrypeer/sentrypeer.json
ENV SENTRYPEER_SIP_RESPONSIVE=1
# sentrypeer_rust/src/config.rs also writes its own config dir via the
# `directories` crate's XDG_CONFIG_HOME convention (confirmed live: without
# this, it tries $HOME/.config/sentrypeer, which read_only: true makes
# unwritable and isn't covered by docker-compose.sentrypeer.yml's own
# /opt/sentrypeer tmpfs -- a second real crash found deploying this for the
# first time, on top of the binary-location one above). Point it at the
# same already-writable tmpfs instead of adding a second mount.
ENV XDG_CONFIG_HOME=/opt/sentrypeer

EXPOSE 5060/udp 5060/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z -u 127.0.0.1 5060 || exit 1

# No -a (RESTful API, port 8082): nothing in this stack consumes it, the
# JSON log file is read directly, and it's an unused extra surface. No -p
# (Peer to Peer): declined third-party data sharing, same call already made
# in docs/community-threat-intel-sharing.md.
CMD ["/usr/local/bin/sentrypeer", "-v", "-f", "/var/lib/sentrypeer/sentrypeer.db"]
