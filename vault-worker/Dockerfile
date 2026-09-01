FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

LABEL maintainer="honeypot-stack"
LABEL description="Knowledge-store vault-ingest worker (#1634 stage 2)"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10002 --no-create-home --shell /usr/sbin/nologin vaultworker \
    && mkdir -p /vault && chown vaultworker:vaultworker /vault

COPY sanitize.py worker.py ./

USER 10002:10002

CMD ["python", "-u", "worker.py"]
