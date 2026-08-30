# github.com/awhitehatter/mailoney -- #1422: SMTP honeypot. Retires
# multipot's own self-written SMTP handler (see docker-compose.multipot.yml's
# MULTIPOT_DISABLE) in favor of a real vendored tool, matching this epic's
# "vendor, don't reimplement" convention -- multipot's handler only ever did
# EHLO/AUTH/envelope capture, Mailoney adds real DATA/message-body capture on
# top of the same posture. MIT licensed, confirmed directly against the
# vendored LICENSE file.
#
# python:3.11-slim, matching upstream's own Dockerfile choice and this
# repo's existing snare/Dockerfile precedent -- psycopg2-binary/SQLAlchemy
# wheel availability lags on brand-new Python releases; no reason to be the
# first to find that out the hard way on a 3.14 base when upstream already
# validated 3.11.
#
# json_log_patch.py adds a second, additive JSON-line log sink: Mailoney
# persists each session to a SQLAlchemy DB only (SQLite by default) with no
# file-based event log of its own -- confirmed by reading mailoney/core.py
# directly. Every other sensor here writes one JSON line per event to a
# bind-mounted file for ip-enrichment-worker/Filebeat; this patch adds that
# without touching the existing DB write. See that file's own doc comment.
FROM python:3.11-slim@sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6 AS build
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
ARG MAILONEY_REF=0987c40b45c2f0491cff3c2cbec4fc8d08a2a54d
WORKDIR /build
RUN git clone https://github.com/awhitehatter/mailoney /build \
 && git checkout "$MAILONEY_REF"
COPY json_log_patch.py /tmp/json_log_patch.py
RUN python3 /tmp/json_log_patch.py

FROM python:3.11-slim@sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6
RUN apt-get update && apt-get install -y --no-install-recommends netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /build /app
RUN pip install --no-cache-dir -r requirements.txt

ENV MAILONEY_DB_URL=sqlite:////data/mailoney.db \
    MAILONEY_JSON_LOG=/var/log/honeypot/mailoney.json \
    MAILONEY_BIND_PORT=25 \
    MAILONEY_SERVER_NAME=mail01.nexusai.local

EXPOSE 25

# 65534 (nobody), not a named user: matches every other non-root sensor
# here (beelzebub, hellpot) and honeypot-init's compose.yml log-dir chown
# convention exactly -- that job chowns /logs/mailoney to literal
# 65534:65534 on the host, which only lines up if the container actually
# runs as that UID. No in-image chown needed: /var/log/honeypot is a
# bind mount (ownership comes from the host side, not the image) and
# /data is tmpfs (Docker's own default tmpfs mode is 1777, world-
# writable, no extra config required).
USER 65534

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 25 || exit 1

ENTRYPOINT ["python", "main.py"]
