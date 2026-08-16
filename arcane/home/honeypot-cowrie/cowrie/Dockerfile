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

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 python3-venv python3-pip \
      libssl-dev libffi-dev build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 2000 cowrie && useradd -u 2000 -g cowrie -d /cowrie -s /sbin/nologin cowrie

# #1488: pinned to v3.0.12 (ced855a) -- was an unpinned `--depth 1` HEAD
# clone, which is exactly how the honeyfs.py rewrite below silently landed
# and broke the entire honeyfs mechanism. Shallow-fetch of the exact commit,
# not a full clone, so this stays fast.
RUN git init -q /cowrie/cowrie-git \
 && cd /cowrie/cowrie-git \
 && git remote add origin https://github.com/cowrie/cowrie \
 && git fetch -q --depth 1 origin ced855a5cda953eb4ad439d8ee8060afe4234fe4 \
 && git checkout -q FETCH_HEAD

WORKDIR /cowrie/cowrie-git

RUN python3 -m venv /cowrie/cowrie-env \
 && /cowrie/cowrie-env/bin/pip install --no-cache-dir --upgrade pip setuptools wheel \
 && /cowrie/cowrie-env/bin/pip install --no-cache-dir -r requirements.txt \
 && if [ -f requirements-output.txt ]; then \
        /cowrie/cowrie-env/bin/pip install --no-cache-dir -r requirements-output.txt; \
    fi \
 && /cowrie/cowrie-env/bin/pip install --no-cache-dir .

# #1488: the old `cowrie.shell.fs.CowrieFilesystem('/').fs` snippet this
# replaced no longer exists in current Cowrie (renamed to HoneyPotFilesystem
# as part of the honeyfs.py rewrite) and was failing silently behind
# `|| true`. `createfs` (a real installed console script, walking this
# builder stage's own root filesystem as the template) is upstream's own
# documented replacement -- same node format bin/sync-fs.py already merges
# onto, no `|| true`: a real failure here should fail the build.
#
# #1487: this baseline pickle is built to fs.pickle.dist, not the live
# share/cowrie/fs.pickle path -- see the honeyfs.dist comment below for why.
RUN mkdir -p share/cowrie \
 && /cowrie/cowrie-env/bin/createfs -l / -d 100 -o fs.pickle.dist

# Static honeyfs and txtcmds.
#
# #1487: honeyfs lands at honeyfs.dist, not the live honeyfs/ path.
# compose.yml now bind-mounts honeyfs/ and share/cowrie/ from the host (same
# reasoning as cowrie.cfg/userdb.txt's existing bind mounts) so the
# honeyfs-implant service (arcane/home/honeypot-cowrie/honeyfs-implant/) can
# write a new artifact into a persona's fake filesystem live, without a
# rebuild -- planting a file into a running container is not enough on its
# own, since fs.pickle (not the directory listing) is what Cowrie's `ls`
# actually consults (see bin/sync-fs.py's own docstring). A bind mount would
# shadow this image's own baked content with an empty host directory on
# first run, so the real content stays here, outside the mount points, as a
# seed source entrypoint.sh copies from on first boot.
COPY honeyfs/   /cowrie/cowrie-git/honeyfs.dist/
COPY txtcmds/   /cowrie/cowrie-git/txtcmds/

# sync-fs.py now also runs at every container startup (entrypoint.sh) to
# merge whatever's live in the bind-mounted honeyfs/ into fs.pickle -- kept
# here as a permanent runtime script, not a /tmp scratch file.
COPY bin/sync-fs.py /cowrie/cowrie-git/bin/sync-fs.py
RUN /cowrie/cowrie-env/bin/python3 /cowrie/cowrie-git/bin/sync-fs.py \
      /cowrie/cowrie-git/fs.pickle.dist \
      /cowrie/cowrie-git/honeyfs.dist

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
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

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
