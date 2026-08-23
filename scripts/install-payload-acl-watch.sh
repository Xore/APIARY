#!/usr/bin/env bash
set -euo pipefail

# Keep captured payloads readable by the payload-inventory worker.
#
# #1789: the worker runs as `nobody` and the payload files are owned 1000:1000,
# so what grants it access is a per-file ACL entry, not the mode. The binaries
# directory carries the right default ACL --
#
#     default:user:nobody:r-x
#
# -- but a default ACL is applied when a file is *created* in the directory.
# dionaea stages its downloads elsewhere and rename(2)s them in, and rename
# preserves the source file's mode and ACLs, so the entry is never applied.
# Measured live: every file written after 2026-08-22 22:14 arrived as 0600 with
# no ACL, the worker could not read a byte of it, and 61 payloads were stored
# with an empty Kind and MIME application/octet-stream. Capture never stopped;
# only identification did, which is the kind of failure that looks like quiet
# success.
#
# The real fix belongs in the producer -- dionaea should create the file in its
# download directory, or set the ACL itself. This exists because until that
# lands the store degrades silently with every new capture, and a payload we
# cannot classify is a payload we cannot triage.
#
# Deliberately a path unit rather than a timer: the window between a file
# landing and the worker's next scan is what decides whether it gets classified
# on the first pass, and a timer wide enough to be cheap is wide enough to lose
# that race.

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root: sudo ./install-payload-acl-watch.sh" >&2
    exit 1
fi

BIN_DIR=${PAYLOAD_BINARIES_DIR:-/var/lib/docker/volumes/dionaea-lib/_data/binaries}
WORKER_USER=${PAYLOAD_WORKER_USER:-nobody}

[[ -d ${BIN_DIR} ]] || { echo "payload directory not found: ${BIN_DIR}" >&2; exit 1; }
command -v setfacl >/dev/null || { echo "setfacl not installed (acl package)" >&2; exit 1; }

install -m 0755 /dev/stdin /usr/local/sbin/apiary-payload-acl <<EOF
#!/usr/bin/env bash
# Re-apply the read entry the directory's default ACL was meant to confer.
# Grants nothing new: it is the same entry every pre-2026-08-22 file carries.
set -euo pipefail
setfacl -m u:${WORKER_USER}:r-- "${BIN_DIR}"/* 2>/dev/null || true
EOF

cat >/etc/systemd/system/apiary-payload-acl.service <<EOF
[Unit]
Description=Restore payload-store ACLs so the inventory worker can read captures
Documentation=https://github.com/Xore/APIARY/issues/1789

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/apiary-payload-acl
EOF

cat >/etc/systemd/system/apiary-payload-acl.path <<EOF
[Unit]
Description=Watch the payload store for newly captured files
Documentation=https://github.com/Xore/APIARY/issues/1789

[Path]
PathModified=${BIN_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now apiary-payload-acl.path
# Once now, so anything already on disk is covered rather than waiting for the
# next capture to trigger the watch.
systemctl start apiary-payload-acl.service

echo "watching ${BIN_DIR} for ${WORKER_USER}"
systemctl --no-pager --lines=0 status apiary-payload-acl.path | head -4
