# apiary-backend — the Rust service tier (#1608). Multi-stage: cargo
# release build, then a slim runtime with just the binary. rustls-only
# (no OpenSSL); ca-certificates + curl for TLS trust and the container
# healthcheck.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
# report_pdf.rs's two include_bytes!("../assets_pdf/...") calls need this
# present at compile time, not just runtime -- omitting it here isn't a
# missing-at-runtime issue, it's a build failure (only caught now that
# #1628's prep work added this image to containers.yml's build matrix
# for the first time).
COPY assets_pdf ./assets_pdf
RUN cargo build --release

FROM debian:bookworm-slim
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
