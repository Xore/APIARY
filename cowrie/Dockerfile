# Cowrie SSH/Telnet honeypot -- GPU server persona (Dell PowerEdge R7525 / dual EPYC 7742 / 2x A100)
# Preserves the two-stage build, uid 2000, sync-fs.py, and the dropin cache
# pre-build from the original honeypot-stack Dockerfile.
#
# Dynamic txtcmds (free / df / dd / ss / proc/*) are generated at runtime by
# bin/gen-dynamic-txtcmds.py via the entrypoint wrapper so values differ
# between sessions and don't look static/canned.
#
# Scripts are placed in /cowrie/cowrie-git/bin/ -- a directory that already
# exists from the upstream git clone -- to avoid the custom /cowrie/bin/
# directory that caused 'exec: no such file or directory' on multi-stage builds.

FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 python3-venv python3-pip \
      libssl-dev libffi-dev build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 2000 cowrie && useradd -u 2000 -g cowrie -d /cowrie -s /sbin/nologin cowrie

RUN git clone --depth 1 https://github.com/cowrie/cowrie /cowrie/cowrie-git

WORKDIR /cowrie/cowrie-git

RUN python3 -m venv /cowrie/cowrie-env \
 && /cowrie/cowrie-env/bin/pip install --no-cache-dir --upgrade pip setuptools wheel \
 && /cowrie/cowrie-env/bin/pip install --no-cache-dir -r requirements.txt \
 && if [ -f requirements-output.txt ]; then \
        /cowrie/cowrie-env/bin/pip install --no-cache-dir -r requirements-output.txt; \
    fi \
 && /cowrie/cowrie-env/bin/pip install --no-cache-dir .

RUN /cowrie/cowrie-env/bin/python3 -c \
    "import cowrie.shell.fs as f; import pickle, pathlib; \
     p = pathlib.Path('share/cowrie/fs.pickle'); \
     p.parent.mkdir(parents=True, exist_ok=True); \
     pickle.dump(f.CowrieFilesystem('/').fs, open(str(p), 'wb'))" \
  || true

# Static honeyfs and txtcmds
COPY honeyfs/   /cowrie/cowrie-git/honeyfs/
COPY txtcmds/   /cowrie/cowrie-git/txtcmds/

COPY bin/sync-fs.py /tmp/sync-fs.py
RUN /cowrie/cowrie-env/bin/python3 /tmp/sync-fs.py \
      /cowrie/cowrie-git/share/cowrie/fs.pickle \
      /cowrie/cowrie-git/honeyfs \
 && rm -f /tmp/sync-fs.py

ENV PYTHONPATH="/cowrie/cowrie-git/src"
RUN /cowrie/cowrie-env/bin/python3 /cowrie/cowrie-git/bin/regen-dropin.cache

# Place both runtime scripts inside the existing cowrie-git/bin/ directory
# so the --from=builder copy lands them in a path that is guaranteed to exist.
COPY bin/gen-dynamic-txtcmds.py /cowrie/cowrie-git/bin/gen-dynamic-txtcmds.py
COPY bin/entrypoint.sh           /cowrie/cowrie-git/bin/entrypoint.sh
RUN chmod +x \
      /cowrie/cowrie-git/bin/entrypoint.sh \
      /cowrie/cowrie-git/bin/gen-dynamic-txtcmds.py

RUN chown -R cowrie:cowrie /cowrie

# ---- Stage 2: lean runtime ----
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 libssl3 ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 2000 cowrie && useradd -u 2000 -g cowrie -d /cowrie -s /sbin/nologin cowrie

COPY --from=builder --chown=cowrie:cowrie /cowrie /cowrie

COPY cowrie.cfg  /cowrie/cowrie-git/etc/cowrie.cfg
COPY userdb.txt  /cowrie/cowrie-git/etc/userdb.txt

ENV PATH="/cowrie/cowrie-env/bin:$PATH"
ENV PYTHONPATH="/cowrie/cowrie-git/src"
ENV PYTHONUNBUFFERED=1

WORKDIR /cowrie/cowrie-git
USER cowrie

EXPOSE 2222 2223
ENTRYPOINT ["/cowrie/cowrie-git/bin/entrypoint.sh"]
