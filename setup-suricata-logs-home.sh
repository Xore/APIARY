#!/usr/bin/env bash
set -euo pipefail

# Install boot ordering and retry support for the read-only VPS log mounts.
# The two sshfs entries themselves must already exist in /etc/fstab.

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root: sudo ./setup-suricata-logs-home.sh" >&2
  exit 1
fi

wireguard_unit=${WIREGUARD_UNIT:-wg-quick@wg0.service}
mount_paths=(
  /opt/stacks/honeypot-stack/logs/suricata
  /opt/stacks/honeypot-stack/logs/portbridge
)
mount_units=()

for mount_path in "${mount_paths[@]}"; do
  if ! findmnt --fstab --mountpoint "$mount_path" >/dev/null; then
    echo "Missing /etc/fstab entry for $mount_path" >&2
    exit 1
  fi

  # Dockge commonly exposes /opt/stacks as a symlink into /var/dockge/stacks.
  # fstab-generator names the unit from the canonical destination.
  canonical_path=$(readlink -f "$mount_path")
  mount_unit=$(systemd-escape --path --suffix=mount "$canonical_path")
  mount_units+=("$mount_unit")
  install -d -m 0755 "/etc/systemd/system/${mount_unit}.d"
  cat >"/etc/systemd/system/${mount_unit}.d/10-wireguard.conf" <<EOF
[Unit]
Requires=${wireguard_unit}
After=${wireguard_unit}

[Mount]
TimeoutSec=30s
EOF
done

cat >/usr/local/sbin/honeypot-log-mounts <<EOF
#!/usr/bin/env bash
set -euo pipefail

units=(
  '${mount_units[0]}'
  '${mount_units[1]}'
)
paths=(
  ${mount_paths[0]}
  ${mount_paths[1]}
)

systemctl reset-failed "\${units[@]}" || true
systemctl start "\${units[@]}"

for path in "\${paths[@]}"; do
  mountpoint --quiet "\$path" || {
    echo "Expected mount is unavailable: \$path" >&2
    exit 1
  }
done
EOF
chmod 0755 /usr/local/sbin/honeypot-log-mounts

cat >/etc/systemd/system/honeypot-log-mounts.service <<EOF
[Unit]
Description=Recover honeypot VPS log mounts
Requires=${wireguard_unit}
After=${wireguard_unit} docker.service
Wants=docker.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeypot-log-mounts
ExecStartPost=/bin/sh -c 'for container in hp-evebox hp-filebeat; do docker inspect "\$container" >/dev/null 2>&1 && docker restart "\$container" >/dev/null || true; done'
RemainAfterExit=yes
Restart=on-failure
RestartSec=15s
TimeoutStartSec=2min

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable honeypot-log-mounts.service
systemctl restart honeypot-log-mounts.service

echo
systemctl --no-pager --full status honeypot-log-mounts.service
for mount_path in "${mount_paths[@]}"; do
  findmnt --target "$mount_path"
done
