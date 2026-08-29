FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

LABEL maintainer="honeypot-stack"
LABEL description="Ships Ghidra/sandbox/GitHub-analysis/workbench-run results into Elasticsearch (#378)"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY importer.py .

# No USER here -- runs as the uid the compose service sets (root, via
# cap_add: DAC_READ_SEARCH, same as the dashboard and yara-scanner services:
# the Ghidra/GitHub-analysis result directories are root-owned host bind
# mounts this container otherwise can't read).
VOLUME ["/state-importer"]

CMD ["python", "-u", "importer.py"]
