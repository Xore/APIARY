#!/bin/sh
set -e

# Generate dynamic txtcmds (free / df / dd / ss / proc/*) with
# randomised-but-plausible values before Cowrie starts.
# Each container boot produces fresh numbers so repeated sessions
# never see identical output.
/cowrie/cowrie-env/bin/python3 \
    /cowrie/cowrie-git/bin/gen-dynamic-txtcmds.py \
    /cowrie/cowrie-git/txtcmds

# #1487: honeyfs/ and share/cowrie/ are now bind-mounted from the host (see
# compose.yml and the Dockerfile's honeyfs.dist/fs.pickle.dist comments) so
# the honeyfs-implant service can plant a live artifact into this persona's
# fake filesystem without a rebuild. A fresh bind mount shadows the image's
# own baked content, so seed both from the .dist copies on first boot only
# -- never overwrite anything already live there (a second boot might carry
# an implanted file the .dist seed doesn't know about).
HONEYFS_DIR=/cowrie/cowrie-git/honeyfs
HONEYFS_DIST=/cowrie/cowrie-git/honeyfs.dist
FS_PICKLE=/cowrie/cowrie-git/share/cowrie/fs.pickle
FS_PICKLE_DIST=/cowrie/cowrie-git/fs.pickle.dist

# cp -r, not -a: -a's attribute preservation tries to set the target
# directory's own mtime after populating it, which needs ownership of that
# directory (not just write access) and fails under EPERM when the host
# bind-mount isn't owned by uid 2000 -- confirmed live. Harmless to skip:
# sync-fs.py's own fixed CTIME constant is what an attacker's `ls -la`
# actually sees, never the real copied files' mtimes, so there is nothing
# real to preserve here.
if [ -z "$(ls -A "$HONEYFS_DIR" 2>/dev/null)" ]; then
    echo "entrypoint: seeding empty honeyfs bind mount from $HONEYFS_DIST"
    cp -r "$HONEYFS_DIST"/. "$HONEYFS_DIR"/
fi
if [ ! -f "$FS_PICKLE" ]; then
    echo "entrypoint: seeding empty fs.pickle bind mount from $FS_PICKLE_DIST"
    cp "$FS_PICKLE_DIST" "$FS_PICKLE"
fi

# Always re-merge honeyfs into fs.pickle, seeded or not -- picks up
# anything the honeyfs-implant service wrote since this container's last
# boot. Cheap and idempotent (bin/sync-fs.py is pure stdlib, no cowrie
# dependencies, and only touches nodes that actually changed).
/cowrie/cowrie-env/bin/python3 /cowrie/cowrie-git/bin/sync-fs.py "$FS_PICKLE" "$HONEYFS_DIR"

# Clear the implant-pending marker (if honeyfs-implant set one to force
# this restart via autoheal) now that the fresh content is indexed --
# var/lib/cowrie is already bind-mounted for host key/uuid persistence, so
# this needs no new mount. See compose.yml's HEALTHCHECK for the other half.
rm -f /cowrie/cowrie-git/var/lib/cowrie/.implant-pending

exec /cowrie/cowrie-env/bin/python3 \
     /cowrie/cowrie-env/bin/twistd \
     -n --umask=0022 --pidfile= \
     --logger cowrie.python.logfile.stdoutLogger \
     cowrie
