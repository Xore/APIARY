#!/bin/sh
set -e

# #2926: seed the txtcmds tmpfs from the image's .dist copy first.
# compose.yml mounts a tmpfs over /cowrie/cowrie-git/txtcmds (the generator
# rewrites it every boot, so it is deliberately ephemeral) -- which also
# masked everything the Dockerfile baked there, so every committed overlay
# entry the generator does not itself write (netstat, ps, id, lspci, who,
# klist, nmap, nvcc, nvidia-smi, wbinfo, smbstatus, dmesg, mount) was
# absent at runtime. Unconditional, unlike the honeyfs seed below: a tmpfs
# starts empty on every boot, so there is never live content to preserve.
TXTCMDS_DIR=/cowrie/cowrie-git/txtcmds
TXTCMDS_DIST=/cowrie/cowrie-git/txtcmds.dist
mkdir -p "$TXTCMDS_DIR"
# cp -r, not -a -- same EPERM-on-directory-mtime reasoning as the honeyfs
# copy below.
cp -r "$TXTCMDS_DIST"/. "$TXTCMDS_DIR"/

# Generate dynamic txtcmds (free / df / ss / top / proc/* ...) with
# randomised-but-plausible values before Cowrie starts, over the seed.
# Each container boot produces fresh numbers so repeated sessions
# never see identical output.
/cowrie/cowrie-env/bin/python3 \
    /cowrie/cowrie-git/bin/gen-dynamic-txtcmds.py \
    "$TXTCMDS_DIR"

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
# #2913: seeding only when the mount is empty meant a honeyfs change merged to
# the repo never reached a running honeypot -- the mount is non-empty from the
# first boot onward, so every later image rebuild shipped content the container
# then ignored forever. A merged honeyfs fix was not a deployed honeyfs fix.
#
# A blind re-copy on every boot is not the answer either: honeyfs-implant
# plants live artifacts into this same tree, and clobbering those on each
# restart is exactly what the original "first boot only" guard was protecting
# against.
#
# So refresh when, and only when, the IMAGE's content actually changed.
# The .dist fingerprint is recorded under var/lib/cowrie (already bind-mounted
# for host-key/uuid persistence, so it survives restarts). On a boot where the
# fingerprint differs -- i.e. a genuinely new image -- .dist is copied over the
# mount again. `cp -r "$HONEYFS_DIST"/. ` only writes paths that exist in
# .dist, so implanted files the image knows nothing about are left in place.
# An implant that overwrote a path .dist also ships does get reverted, but only
# on an image change, which is precisely when the repo's version should win.
HONEYFS_STAMP=/cowrie/cowrie-git/var/lib/cowrie/.honeyfs-dist-id
dist_id="$(find "$HONEYFS_DIST" -type f -exec sha256sum {} + 2>/dev/null \
    | sort | sha256sum | cut -d' ' -f1)"
prev_id=""
[ -f "$HONEYFS_STAMP" ] && prev_id="$(cat "$HONEYFS_STAMP" 2>/dev/null || true)"

if [ -z "$(ls -A "$HONEYFS_DIR" 2>/dev/null)" ]; then
    echo "entrypoint: seeding empty honeyfs bind mount from $HONEYFS_DIST"
    cp -r "$HONEYFS_DIST"/. "$HONEYFS_DIR"/
elif [ "$dist_id" != "$prev_id" ]; then
    echo "entrypoint: honeyfs.dist changed (image rebuilt) -- refreshing image-owned files, implants preserved"
    cp -r "$HONEYFS_DIST"/. "$HONEYFS_DIR"/
fi
mkdir -p "$(dirname "$HONEYFS_STAMP")" 2>/dev/null || true
printf '%s\n' "$dist_id" > "$HONEYFS_STAMP" 2>/dev/null || true
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
