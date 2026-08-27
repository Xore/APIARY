# Build the sidecar, then ship only the binary and the signature database.
#
# Two stages because huginn-net pulls in a full Rust toolchain and ~200 crates
# to build, none of which belong on a VPS that also fronts every honeypot.
FROM rust:1-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS build

# libpcap headers: huginn-net captures through libpcap, and the slim base has
# the runtime library but not the headers.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# libpcap0.8 for capture; ca-certificates is not needed -- this talks to
# nothing, it only reads packets and writes stdout.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home --shell /usr/sbin/nologin huginn

COPY --from=build /src/target/release/huginn-sidecar /usr/local/bin/huginn-sidecar

# Runs as root only because packet capture needs NET_RAW/NET_ADMIN, which the
# compose service grants explicitly while dropping every other capability.
ENTRYPOINT ["/usr/local/bin/huginn-sidecar"]
