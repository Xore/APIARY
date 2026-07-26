#!/usr/bin/env bash
set -uo pipefail

result=/var/lib/honeypot-result
sample=/opt/honeypot/input/sample
pcap_pid=
stop_instrumentation() {
  if [[ -n ${pcap_pid:-} ]]; then
    kill -INT "$pcap_pid" >/dev/null 2>&1 || true
    wait "$pcap_pid" 2>/dev/null || true
  fi
}
trap stop_instrumentation EXIT
mkdir -p "$result"
chmod 0700 "$result"
install -d -m 0700 -o 0 -g 0 "$result/trace"
exec >"$result/runner.log" 2>&1

date -u +%FT%TZ >"$result/started-at.txt"
iface=$(ip -o link show | awk -F': ' '$2 != "lo" {sub(/@.*/, "", $2); print $2; exit}')
if [[ -n $iface ]]; then
  ip link set "$iface" up
  ip address flush dev "$iface"
  ip address add 198.18.0.2/24 dev "$iface"
fi
rm -f /etc/resolv.conf
printf 'nameserver 198.18.0.1\noptions attempts:1 timeout:2\n' >/etc/resolv.conf
tcpdump -i any -U -n -s 0 -w "$result/guest-network.pcap" \
  >"$result/guest-tcpdump.log" 2>&1 &
pcap_pid=$!
sleep 1
sha256sum "$sample" >"$result/sample.sha256"
file -b "$sample" >"$result/file-type.txt"
md5sum "$sample" >"$result/sample.md5"
sha1sum "$sample" >"$result/sample.sha1"
uname -a >"$result/kernel.txt"
find /etc /home /opt /tmp /var/tmp -xdev -printf '%p\t%s\t%T@\n' 2>/dev/null | sort >"$result/files-before.tsv"
ps auxww >"$result/processes-before.txt"
ss -H -t -u -n -a -p >"$result/sockets-before.txt" 2>&1 || true

chown 1500:1500 "$sample"
file_type=$(cat "$result/file-type.txt")
python3 /usr/local/sbin/honeypot-payload-classifier "$sample" >"$result/classification.json" \
  2>"$result/classification-error.txt" || true
kind=$(jq -r '.code // "binary"' "$result/classification.json" 2>/dev/null || printf binary)
platform=$(jq -r '.platform // "Unknown"' "$result/classification.json" 2>/dev/null || printf Unknown)
analysis_path=$(jq -r '.analysis_path // "Static metadata"' "$result/classification.json" 2>/dev/null || printf 'Static metadata')
printf '%s\n' "$platform" >"$result/platform.txt"
printf '%s\n' "$analysis_path" >"$result/analysis-path.txt"

# Baseline static collection applies to every type, not only PE files.
chmod 0400 "$sample"
timeout 30s strings -a -n 5 "$sample" 2>/dev/null | head -n 4000 >"$result/strings-ascii.txt" || true
timeout 30s strings -a -e l -n 5 "$sample" 2>/dev/null | head -n 4000 >"$result/strings-utf16le.txt" || true
timeout 30s exiftool "$sample" >"$result/exiftool.txt" 2>&1 || true

windows_mode=$(cat /etc/honeypot-sandbox-windows-mode 2>/dev/null || printf static)
network_mode=$(cat /etc/honeypot-sandbox-network-mode 2>/dev/null || printf isolated)
[[ $windows_mode == static || $windows_mode == wine ]] || windows_mode=static
[[ $network_mode == isolated || $network_mode == controlled ]] || network_mode=isolated
proxy_env=()
if [[ $network_mode == controlled ]]; then
  proxy_env=(
    HTTP_PROXY=http://198.18.0.1:3128 HTTPS_PROXY=http://198.18.0.1:3128
    http_proxy=http://198.18.0.1:3128 https_proxy=http://198.18.0.1:3128
    NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
  )
fi

configure_wine_proxy() {
  [[ $network_mode == controlled ]] || return 0
  setpriv --reuid=1500 --regid=1500 --init-groups --no-new-privs \
    env HOME=/home/sandbox WINEPREFIX=/home/sandbox/.wine WINEDEBUG=-all \
    wine reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' \
    /v ProxyEnable /t REG_DWORD /d 1 /f >/dev/null 2>&1 || true
  setpriv --reuid=1500 --regid=1500 --init-groups --no-new-privs \
    env HOME=/home/sandbox WINEPREFIX=/home/sandbox/.wine WINEDEBUG=-all \
    wine reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' \
    /v ProxyServer /t REG_SZ /d 198.18.0.1:3128 /f >/dev/null 2>&1 || true
}

if [[ $kind == pe-exe || $kind == pe-dll ]]; then
  timeout 30s python3 /usr/local/sbin/honeypot-pe-forensics "$sample" \
    >"$result/pe-forensics.json" 2>"$result/pe-forensics-error.txt" || true
  timeout 30s objdump -x "$sample" 2>&1 | head -c 262144 >"$result/pe-objdump.txt" || true
  timeout 30s osslsigncode verify -in "$sample" >"$result/authenticode.txt" 2>&1 || true
fi

runner=()
wine_route=false
wine_sample='Z:\opt\honeypot\input\sample'
case "$kind" in
  pe-exe)
    if [[ $windows_mode == wine ]]; then
      runner=(wine "$sample")
      wine_route=true
      printf 'wine-pe\n' >"$result/execution-mode.txt"
    else
      printf 'static-policy\n' >"$result/execution-mode.txt"
    fi
    ;;
  pe-dll)
    printf 'static-dll\n' >"$result/execution-mode.txt"
    ;;
  vbscript)
    if [[ $windows_mode == wine ]]; then
      runner=(wine cscript.exe //B //NoLogo "$wine_sample")
      wine_route=true
      printf 'wine-vbscript\n' >"$result/execution-mode.txt"
    else
      printf 'static-policy\n' >"$result/execution-mode.txt"
    fi
    ;;
  jscript)
    if [[ $windows_mode == wine ]]; then
      runner=(wine cscript.exe //B //NoLogo //E:JScript "$wine_sample")
      wine_route=true
      printf 'wine-jscript\n' >"$result/execution-mode.txt"
    else
      printf 'static-policy\n' >"$result/execution-mode.txt"
    fi
    ;;
  batch)
    if [[ $windows_mode == wine ]]; then
      runner=(wine cmd.exe /d /c "$wine_sample")
      wine_route=true
      printf 'wine-batch\n' >"$result/execution-mode.txt"
    else
      printf 'static-policy\n' >"$result/execution-mode.txt"
    fi
    ;;
  powershell)
    if [[ $windows_mode == wine ]]; then
      runner=(wine powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$wine_sample")
      wine_route=true
      printf 'wine-powershell\n' >"$result/execution-mode.txt"
    else
      printf 'static-policy\n' >"$result/execution-mode.txt"
    fi
    ;;
  shell) runner=(/bin/bash "$sample"); printf 'bash\n' >"$result/execution-mode.txt" ;;
  python) runner=(/usr/bin/python3 "$sample"); printf 'python3\n' >"$result/execution-mode.txt" ;;
  javascript) runner=(/usr/bin/node "$sample"); printf 'nodejs\n' >"$result/execution-mode.txt" ;;
  php) runner=(/usr/bin/php "$sample"); printf 'php-cli\n' >"$result/execution-mode.txt" ;;
  elf-exe) chmod 0500 "$sample"; runner=("$sample"); printf 'linux-native\n' >"$result/execution-mode.txt" ;;
  *) printf 'static-unsupported-type\n' >"$result/execution-mode.txt" ;;
esac

if ((${#runner[@]})); then
  if $wine_route; then
    configure_wine_proxy
    runner=(xvfb-run -a -s '-screen 0 1024x768x24' "${runner[@]}")
  fi
  set +e
  timeout --signal=TERM --kill-after=10s 120s \
    strace -ff -tt -yy -s 512 -o "$result/trace/strace" -- \
    setpriv --reuid=1500 --regid=1500 --init-groups --no-new-privs \
    env HOME=/home/sandbox USER=sandbox LOGNAME=sandbox \
    "${proxy_env[@]}" WINEPREFIX=/home/sandbox/.wine WINEDEBUG=-all \
    WINEDLLOVERRIDES=winemenubuilder.exe=d "${runner[@]}" \
    >"$result/stdout.txt" 2>"$result/stderr.txt"
  status=$?
  set -e
  if $wine_route; then
    setpriv --reuid=1500 --regid=1500 --init-groups --no-new-privs \
      env HOME=/home/sandbox WINEPREFIX=/home/sandbox/.wine wineserver -k >/dev/null 2>&1 || true
  fi
else
  : >"$result/stdout.txt"
  printf 'Dynamic execution was not selected for payload type %s (%s). Static collection completed.\n' \
    "$kind" "$analysis_path" >"$result/stderr.txt"
  status=not-executed
fi
printf '%s\n' "$status" >"$result/exit-status.txt"

ps auxww >"$result/processes-after.txt"
ss -H -t -u -n -a -p >"$result/sockets-after.txt" 2>&1 || true
find /etc /home /opt /tmp /var/tmp -xdev -printf '%p\t%s\t%T@\n' 2>/dev/null | sort >"$result/files-after.tsv"
comm -13 "$result/files-before.tsv" "$result/files-after.tsv" >"$result/files-created-or-changed.tsv" || true
stop_instrumentation
pcap_pid=
date -u +%FT%TZ >"$result/finished-at.txt"
sync
systemctl poweroff --no-wall --force
