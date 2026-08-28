#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo bash $0" >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
virsh net-info honeypot-sandbox >/dev/null

if systemctl is-active --quiet squid.service; then
  echo "The host already uses the default squid.service; refusing to replace it." >&2
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq-base squid nftables logrotate
systemctl disable --now squid.service 2>/dev/null || true

target=/usr/local/libexec/honeypot-sandbox
install -d -m 0755 -o root -g root "$target"
install -m 0755 -o root -g root "$script_dir/forensic-egress-network.sh" "$target/"
install -m 0644 -o root -g root "$script_dir/forensic-egress-network.nft" "$target/"
install -d -m 0750 -o root -g root /etc/honeypot-sandbox
install -m 0644 -o root -g root "$script_dir/forensic-egress-dnsmasq.conf" /etc/honeypot-sandbox/dnsmasq.conf
install -m 0644 -o root -g root "$script_dir/forensic-egress-squid.conf" /etc/honeypot-sandbox/squid.conf
install -m 0644 -o root -g root "$script_dir/forensic-egress-allowed-domains.txt" /etc/honeypot-sandbox/allowed-domains.txt

install -d -m 0750 -o nobody -g nogroup /var/log/honeypot-sandbox/dns
install -d -m 0750 -o proxy -g adm /var/log/honeypot-sandbox/proxy

# dnsmasq (log-queries=extra) and squid (stdio access.log + cache.log) both
# log unbounded to the trees above; Debian's own /etc/logrotate.d/squid only
# covers /var/log/squid/*, so this custom pair needs its own drop-in or the
# host fills its disk. postrotate signals each daemon to reopen its log
# in place rather than restarting it -- SIGUSR2 (not SIGUSR1, which only
# dumps cache stats) is what makes dnsmasq close/reopen a log-facility file.
install -m 0644 -o root -g root "$script_dir/forensic-egress-logrotate.conf" /etc/logrotate.d/honeypot-sandbox-egress

/usr/sbin/dnsmasq --test --conf-file=/etc/honeypot-sandbox/dnsmasq.conf
/usr/sbin/squid -k parse -f /etc/honeypot-sandbox/squid.conf
/usr/sbin/logrotate -d /etc/logrotate.d/honeypot-sandbox-egress >/dev/null
for unit in honeypot-sandbox-egress-network.service honeypot-sandbox-egress-dns.service honeypot-sandbox-egress-proxy.service; do
  install -m 0644 -o root -g root "$script_dir/$unit" "/etc/systemd/system/$unit"
done

defaults=/etc/default/honeypot-sandbox
touch "$defaults"
if grep -q '^SANDBOX_NETWORK_MODE=' "$defaults"; then
  sed -i 's/^SANDBOX_NETWORK_MODE=.*/SANDBOX_NETWORK_MODE=controlled/' "$defaults"
else
  printf '\nSANDBOX_NETWORK_MODE=controlled\n' >>"$defaults"
fi
if grep -q '^SANDBOX_WINDOWS_MODE=' "$defaults"; then
  sed -i 's/^SANDBOX_WINDOWS_MODE=.*/SANDBOX_WINDOWS_MODE=wine/' "$defaults"
else
  printf 'SANDBOX_WINDOWS_MODE=wine\n' >>"$defaults"
fi

systemctl daemon-reload
systemctl enable --now honeypot-sandbox-egress-network.service \
  honeypot-sandbox-egress-dns.service honeypot-sandbox-egress-proxy.service

nft list table inet honeypot_sandbox_egress >/dev/null
ss -H -lntup | grep -E '198\.18\.0\.1:(53|3128)\b'
echo "Controlled forensic egress enabled."
echo "Real DNS queries and replies are logged; direct guest forwarding remains blocked."
