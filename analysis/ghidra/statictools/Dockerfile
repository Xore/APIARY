# statictools — ssdeep/tlsh fuzzy hashing and lief structural parsing, as an
# isolated sidecar rather than a host pip install. See server.py's module
# docstring for why: worker/ghidra-worker.py is deliberately stdlib-only on
# the host, and these are exactly the compiled/C-extension dependencies that
# rule exists to keep off it.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libfuzzy-dev \
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
    && pip install --no-cache-dir py-tlsh lief

COPY server.py /app/server.py

# Non-root. This service only ever reads sample bytes into memory and parses
# them; it has no reason to write anywhere.
USER 65534:65534
EXPOSE 9091

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9091/v1/health', timeout=3).status==200 else 1)"

ENTRYPOINT ["python3", "/app/server.py"]
