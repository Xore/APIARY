#!/usr/bin/env bash
set -euo pipefail

action=${1:-}
bridge=virbr-hpsbx
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

case "$action" in
  start)
    ip link show "$bridge" >/dev/null
    ip link set "$bridge" up
    ip address replace 198.18.0.1/24 dev "$bridge"
    nft delete table inet honeypot_sandbox_egress 2>/dev/null || true
    nft -f "$script_dir/forensic-egress-network.nft"
    ;;
  stop)
    nft delete table inet honeypot_sandbox_egress 2>/dev/null || true
    ip address del 198.18.0.1/24 dev "$bridge" 2>/dev/null || true
    ;;
  *)
    echo "usage: $0 start|stop" >&2
    exit 2
    ;;
esac
