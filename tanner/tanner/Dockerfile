# mushorg/tanner — built from source (no published Docker Hub image)
# Supports three run-modes: tanner | tannerapi | tannerweb
# Set `command:` in docker-compose.yml to the desired mode.
#
# IMPORTANT: python:3.10-slim is required.
# pylibinjection ships a pre-generated Cython .c file compiled against
# Python <= 3.10's PyCode_New API (14-arg form). Python 3.11 changed
# PyCode_New to 16 args (added co_qualname + co_exceptiontable), so
# gcc rejects the old generated C code at build time.
FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc

LABEL maintainer="honeypot-stack"

RUN apt-get update && apt-get install -y --no-install-recommends \
      git \
      build-essential \
      libffi-dev \
      libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Pin the audited source revision. Building an unpinned master made dependency
# and emulator behaviour change whenever Dockge happened to rebuild the image.
ARG TANNER_REF=3bc9ae2831db2d7e9c3aa3fb98b3b3a6fc73b18c
RUN git clone https://github.com/mushorg/tanner /opt/tanner \
 && git -C /opt/tanner checkout "$TANNER_REF" \
 && rm -rf /opt/tanner/.git

WORKDIR /opt/tanner

RUN python -m venv /opt/tanner/tanner-env \
 && /opt/tanner/tanner-env/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/tanner/tanner-env/bin/pip install --no-cache-dir -r requirements.txt \
 && /opt/tanner/tanner-env/bin/pip install --no-cache-dir \
      'aioredis==2.0.1'

COPY compatibility_patch.py /tmp/compatibility_patch.py
RUN /opt/tanner/tanner-env/bin/python /tmp/compatibility_patch.py \
 && /opt/tanner/tanner-env/bin/pip install --no-cache-dir . \
 && rm /tmp/compatibility_patch.py

ENV PATH="/opt/tanner/tanner-env/bin:$PATH"

# Runtime dirs — owned by nobody so the process can write to them.
# Log files go to /tmp/tanner (writable tmpfs) not /opt/tanner (read-only layer).
RUN mkdir -p /tmp/tanner /opt/tanner/files \
 && chown -R nobody:nogroup /tmp/tanner /opt/tanner /opt/tanner/files

USER nobody

CMD ["tanner"]
