#!/bin/sh
set -eu
echo "honeypot sandbox smoke test"
id
ip -brief address
ip route
printf 'sandbox lifecycle verified\n' >/tmp/honeypot-smoke-created.txt
exit 0
