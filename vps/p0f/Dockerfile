# Vendored from telekom-security/tpotce (docker/p0f, LGPL-2.1, see
# docs/COPYING) rather than built from vanilla p0f: there is no canonical
# actively-maintained p0f upstream (lcamtuf/p0f 404s), so T-Pot's copy is the
# most practical known-good source tree. Everything under this directory
# except this Dockerfile is that vendored source, unmodified.
#
# Runs in API mode (-s), not T-Pot's own -j/-o JSON-log mode: portbridge
# (vps/portbridge/p0f.go) queries p0f's query socket directly per connection
# and folds the OS guess into the one JSON line it already writes, rather
# than shipping and correlating a second independently-rotated log by IP
# after the fact (#241). jansson/jansson-dev stay in the package list purely
# because build.sh links -ljansson unconditionally (Makefile), even though
# -j is never passed at runtime here.
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

COPY . /opt/p0f

RUN apk --no-cache -U upgrade && \
    apk --no-cache -U add \
        bash \
        build-base \
        jansson \
        jansson-dev \
        libcap \
        libpcap \
        libpcap-dev && \
    addgroup -g 2000 p0f && \
    adduser -S -s /bin/bash -u 2000 -D -g 2000 p0f && \
    cd /opt/p0f && \
    ./build.sh && \
    mkdir -p /run/p0f && \
    apk del --purge build-base \
                    jansson-dev \
                    libpcap-dev && \
    rm -rf /root/* /var/cache/apk/*

WORKDIR /opt/p0f

# No USER directive here, unlike T-Pot's own image: this VPS's Docker daemon
# runs with a fleet-wide no-new-privileges default (/etc/docker/daemon.json),
# which blocks file-capability-based privilege gain at exec entirely --
# confirmed live (setcap cap_net_raw+ep on this binary + running as the p0f
# user still failed with pcap_open_live: Operation not permitted). p0f
# already has its own working mechanism for exactly this: -u below opens the
# raw socket and the API listener while still root (prepare_pcap() and
# open_api() both run before drop_privs() in p0f.c's main()), then calls
# setuid/setgid/chroot itself. That happens via plain syscalls on
# capabilities the container already has in its bounding set from start --
# no exec-time privilege gain involved, so no-new-privileges doesn't affect
# it. vps/docker-compose.yml's cap_add is scoped to exactly what this needs:
# NET_RAW (the raw socket), SETUID/SETGID/SYS_CHROOT (drop_privs' own
# setuid()/setgid()/chroot() calls).
#
# -i resolves the host's default-route interface at container start rather
# than hardcoding one, matching how the sibling suricata service picks
# SURICATA_IFACE -- but p0f runs with network_mode: host directly (see
# vps/docker-compose.yml), so unlike suricata this has no compose-level
# override; it always follows whatever interface the VPS actually routes
# through.
# > /dev/null matches T-Pot's own invocation: p0f still prints its startup
# banner and per-fingerprint summary to stdout by default, which is pure
# noise for a query-mode daemon. stderr is left alone so `docker logs` still
# shows real startup failures.
CMD ["/bin/bash", "-c", "exec /opt/p0f/p0f -u p0f -s /run/p0f/p0f.sock -i $(ip route | grep '^default' | awk '{ print $5 }') > /dev/null"]
