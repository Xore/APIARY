FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

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
