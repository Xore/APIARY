# statictools — ssdeep/tlsh fuzzy hashing, lief structural parsing, and capa
# capability tagging, as an isolated sidecar rather than a host pip install.
# See server.py's module docstring for why: worker/ghidra-worker.py is
# deliberately stdlib-only on the host, and these are exactly the compiled/
# C-extension dependencies that rule exists to keep off it.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libfuzzy-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ssdeep's own packaging (last touched years ago) needs all four of these
# pinned/present before it will build at all, verified against a clean
# python:3.12-slim image (2026-08-01):
#   - setuptools<81: its setup.py does `import pkg_resources` at build time,
#     which setuptools removed in 81 (deprecated since 2025-11-30). Newer
#     setuptools installed and still failing is this, not a stale cache.
#   - --no-build-isolation: pip's isolated build env ignores the pin above
#     and fetches current setuptools regardless unless the build shares the
#     outer environment.
#   - six, cffi: imported directly by ssdeep/binding.py at build time; not
#     declared as build requirements, so pip's dependency resolution never
#     installs them on its own.
RUN pip install --no-cache-dir -U pip 'setuptools<81' wheel six cffi \
    && pip install --no-cache-dir --no-build-isolation ssdeep \
    && pip install --no-cache-dir py-tlsh lief flare-capa==9.4.0

# capa-rules must match capa's own version exactly (Mandiant's own
# requirement -- rule schema drifts between releases). Pinned by tag and
# verified by digest, same convention as GhidrAssist's release zip in
# ghidrassist/README.md: a third-party artifact pulled at build time gets a
# checksum, not just a URL.
ARG CAPA_RULES_VERSION=v9.4.0
ARG CAPA_RULES_SHA256=273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669
RUN curl -fsSL -o /tmp/capa-rules.tar.gz \
      "https://github.com/mandiant/capa-rules/archive/refs/tags/${CAPA_RULES_VERSION}.tar.gz" \
    && echo "${CAPA_RULES_SHA256}  /tmp/capa-rules.tar.gz" | sha256sum -c - \
    && mkdir -p /app/capa-rules \
    && tar -xzf /tmp/capa-rules.tar.gz -C /app/capa-rules --strip-components=1 \
    && rm /tmp/capa-rules.tar.gz

COPY server.py /app/server.py

# Non-root. capa needs the sample on disk (it has no stdin mode), so this
# service writes one file per request under $TMPDIR -- /tmp is world-writable
# by default, so 65534 can do that without owning anything else. It reads
# capa-rules and its own code, and reads sample bytes into memory otherwise;
# it has no reason to write anywhere outside of that.
RUN chown -R 65534:65534 /app/capa-rules
USER 65534:65534
EXPOSE 9091

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9091/v1/health', timeout=3).status==200 else 1)"

ENTRYPOINT ["python3", "/app/server.py"]
