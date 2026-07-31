#!/usr/bin/env bash
# install-github-publisher.sh — set up the host-side GitHub-analysis
# publisher. Modelled on sandbox/install-worker.sh.
#
# This installs the spool, the systemd units, and (if absent) a fresh clone
# of GITHUB_REPO -- but leaves GITHUB_PUBLISH_ENABLED at 0 in the installed
# env file regardless of what this checkout's example says, and never writes
# a GH_PAT. Arming real publication is a separate, explicit step an operator
# takes by hand editing /etc/honeypot-github.env -- see that file's own
# header, and WORK-LEDGER.md rule 7.
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
for cmd in git jq zip file; do
  command -v "$cmd" >/dev/null || { echo "$cmd is required" >&2; exit 1; }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target=/usr/local/libexec/honeypot-github
install -d -m 0755 -o root -g root "$target"
for file in process-github-requests.sh publish-sample.sh resolve-sample.sh check-denylist.sh collect-results.py; do
  install -m 0755 -o root -g root "$script_dir/$file" "$target/$file"
done

if [[ ! -e /etc/honeypot-github.env ]]; then
  install -m 0600 -o root -g root "$script_dir/github.env.example" /etc/honeypot-github.env
  echo "Wrote /etc/honeypot-github.env from the example. GITHUB_PUBLISH_ENABLED=0" \
       "and GH_PAT is empty -- both need an operator's hand before real publication works."
else
  echo "/etc/honeypot-github.env already exists, leaving it alone."
fi

for unit in honeypot-github-publish.service honeypot-github-publish.path \
            honeypot-github-collect.service honeypot-github-collect.timer; do
  install -m 0644 -o root -g root "$script_dir/$unit" "/etc/systemd/system/$unit"
done

install -d -m 0700 -o root -g root \
  /var/lib/honeypot-github/requests/pending \
  /var/lib/honeypot-github/requests/rejected \
  /var/lib/honeypot-github/pending \
  /var/lib/honeypot-github/results

# shellcheck disable=SC1091
source /etc/honeypot-github.env
clone_dir=${GITHUB_CLONE:-/var/lib/honeypot-github/repo}
repo=${GITHUB_REPO:-Xore/honeypot}
if [[ ! -d $clone_dir/.git ]]; then
  install -d -m 0700 -o root -g root "$(dirname "$clone_dir")"
  git clone --quiet "https://github.com/$repo.git" "$clone_dir"
  echo "Cloned $repo to $clone_dir. Wire GH_PAT into its push credentials" \
       "(a credential helper or an https remote carrying the token) before" \
       "setting GITHUB_PUBLISH_ENABLED=1 -- an anonymous clone can fetch but not push."
fi

systemctl daemon-reload
systemctl reset-failed honeypot-github-publish.service honeypot-github-collect.service 2>/dev/null || true
systemctl enable --now honeypot-github-publish.path honeypot-github-collect.timer

echo "GitHub-analysis publisher installed, dry-run only until /etc/honeypot-github.env is armed by hand."
systemctl --no-pager --plain is-active honeypot-github-publish.path honeypot-github-collect.timer
