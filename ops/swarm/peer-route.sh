#!/bin/sh
# Keep the two managers' hub addresses on the direct encrypted path.
set -eu

[ "$#" -eq 4 ] || { echo 'usage: peer-route.sh PEER_HUB LOCAL_HUB FIBRE_PEER LAN_PEER' >&2; exit 2; }
peer=$1 local=$2 fibre=$3 lan=$4

if ping -n -q -I wg-fibre -c 1 -W 1 "$fibre" >/dev/null 2>&1; then
    dev=wg-fibre
elif ping -n -q -I wg-lan -c 1 -W 1 "$lan" >/dev/null 2>&1; then
    dev=wg-lan
else
    echo 'neither direct WireGuard path is healthy; retaining the last route' >&2
    exit 1
fi

case "$(ip -o route show exact "$peer/32")" in
    *" dev $dev "*" src $local"*) exit 0 ;;
esac
ip route replace "$peer/32" dev "$dev" src "$local"
