#!/bin/sh
set -eu

# This is a dedicated nested daemon. It never mounts /var/run/docker.sock from
# the homeserver. Nested containers have no NAT/forwarding, so emulated command
# execution cannot be used to attack other systems.
dockerd-entrypoint.sh \
  --host=unix:///var/run/docker.sock \
  --host=tcp://0.0.0.0:2375 \
  --iptables=false \
  --ip-forward=false &
daemon_pid=$!

until docker info >/dev/null 2>&1; do
  kill -0 "$daemon_pid" 2>/dev/null || exit 1
  sleep 1
done

if ! docker image inspect tanner-sandbox:latest >/dev/null 2>&1; then
  tar -C /seed/command-rootfs -cf - . | docker import - tanner-sandbox:latest >/dev/null
fi
if ! docker image inspect template_injection:latest >/dev/null 2>&1; then
  tar -C /seed/template-rootfs -cf - . | docker import - template_injection:latest >/dev/null
fi

touch /run/tanner-sandbox-ready
wait "$daemon_pid"
