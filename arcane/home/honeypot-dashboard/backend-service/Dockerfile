# apiary-backend — the Rust service tier (#1608). Multi-stage: cargo
# release build, then a slim runtime with just the binary. rustls-only
# (no OpenSSL); ca-certificates + curl for TLS trust and the container
# healthcheck.
FROM rust:1-slim-bookworm@sha256:94e9efa4033213dbb70d4f665527e7ece3944ddb7ba1dd2e43f6fd6e2490af58 AS build
# #3315: which revision of the repository this binary is built from. Declared
# in the build stage as well as the runtime one because build.rs reads it from
# the environment to compile it in (/healthz's `revision` field) and the
# runtime stage's LABEL cannot reach back into the compiler. Unset is normal,
# not an error: a developer building this by hand gets "unknown" rather than a
# broken build, and the whole point is that the answer is honest when it is
# missing. Arcane passes it from the synced checkout via the stack's own
# `build.args`; CI passes ${{ github.sha }}.
ARG GIT_SHA
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
# build.rs stamps the binary with its compile time (see the file). It has to
# be copied explicitly: cargo only runs a build script that is actually in
# the crate root, and without it env!("APIARY_BUILD_EPOCH") is a compile
# error rather than a missing value. build.rs also carries GIT_SHA through as
# APIARY_GIT_SHA since #3315.
COPY build.rs ./
COPY src ./src
# report_pdf.rs's two include_bytes!("../assets_pdf/...") calls need this
# present at compile time, not just runtime -- omitting it here isn't a
# missing-at-runtime issue, it's a build failure (only caught now that
# #1628's prep work added this image to containers.yml's build matrix
# for the first time).
COPY assets_pdf ./assets_pdf
RUN cargo build --release

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
# Redeclared per stage: Docker scopes an ARG to the stage that declares it, so
# the value the build stage compiled in is not in scope here on its own.
ARG GIT_SHA
# Static, so it is written here rather than taken from a build arg: the
# repository URL is the same for every build of this image and there is no
# reason to let a caller point the label somewhere else.
ARG GIT_SOURCE=https://github.com/Xore/APIARY
# Build time is the one label a build cannot honestly invent -- unlike the
# revision, there is no earlier source of truth to copy it from. So it stays
# "unknown" unless the builder supplies it, and CI does (containers.yml passes
# metadata-action's labels, which carry a real created/source pair and take
# precedence over these). An "unknown" here reads as "nobody told us", which is
# true; a plausible-looking wrong timestamp would not be.
ARG BUILD_DATE
# #3315: `docker images` shows no revision at all without these. `Labels: null`
# on a stale image is the exact state that let every merge since a redeploy go
# undeployed without anything saying so (see the issue's homeserver example).
# Read with: docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}'
LABEL org.opencontainers.image.revision="${GIT_SHA:-unknown}" \
      org.opencontainers.image.source="${GIT_SOURCE}" \
      org.opencontainers.image.created="${BUILD_DATE:-unknown}" \
      org.opencontainers.image.title="apiary-backend" \
      org.opencontainers.image.description="APIARY dashboard backend service (Rust, axum)"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/apiary-backend /usr/local/bin/apiary-backend
ENV LISTEN_ADDR=0.0.0.0:8081
EXPOSE 8081
# Port derived from $LISTEN_ADDR at check time, not hardcoded to the 8081
# default: every non-default LISTEN_ADDR consumer of this image (backend-
# worker at 127.0.0.1:8099, backend-worker-importer at 127.0.0.1:8098,
# backend-service-mounted at 0.0.0.0:8082 -- see honeypot-dashboard/
# compose.yml) curled the wrong port forever otherwise, reporting
# permanently unhealthy in `docker ps`/`docker inspect` despite actually
# serving correctly (caught live during #1628's first real preflight run,
# not by any test -- CI never runs the image under a non-default
# LISTEN_ADDR).
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=20s \
    CMD curl -sf "http://127.0.0.1:${LISTEN_ADDR##*:}/healthz" || exit 1
USER nobody
CMD ["apiary-backend"]
