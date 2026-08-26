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
# #2083: each of these is load-bearing downstream -- setfacl is what
# re-grants uid 65534 write access to the spool on every drain run
# (process-github-requests.sh; without the 'acl' package that grant
# silently no-ops and dashboard submissions never land), and
# honeypot-github-collect.service hardcodes /usr/bin/python3 as its
# interpreter. Fail here, with names, rather than at runtime far away.
for cmd in git jq zip file setfacl; do
  if ! command -v "$cmd" >/dev/null; then
    echo "$cmd is required" >&2
    [[ $cmd == setfacl ]] && echo "  (install the 'acl' package)" >&2
    exit 1
  fi
done
[[ -x /usr/bin/python3 ]] || { echo "/usr/bin/python3 is required" \
  "(honeypot-github-collect.service hardcodes that path)" >&2; exit 1; }

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
  # #2083: use the GH_PAT this script just sourced, if it is already armed
  # -- an anonymous clone fails outright on a private results repo, which
  # is what this pipeline feeds. Auth goes through a one-shot GIT_ASKPASS
  # helper, deliberately NOT a user:pass@ remote: a credential-in-URL is
  # exactly the shape scripts/check-public-leaks.py's :51 pattern exists to
  # catch, env-var placeholder or not. A `git clone -c credential.helper`
  # was also rejected because clone PERSISTS -c key=value into the new
  # repository's config (--config). The helper lives only for this one
  # clone (root-owned 0700 temp file) and reads the PAT from its inherited
  # environment, so the token never appears in any URL, any persisted
  # config, or any process argv.
  if [[ -n ${GH_PAT:-} ]]; then
    export GH_PAT
    askpass=$(mktemp /tmp/honeypot-clone-askpass.XXXXXX)
    trap 'rm -f "$askpass"' EXIT
    printf '#!/bin/sh\ncase $1 in *Username*) echo x-access-token ;; *) printf "%%s\\n" "$GH_PAT" ;; esac\n' >"$askpass"
    chmod 0700 "$askpass"
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$askpass" \
      git clone --quiet "https://github.com/$repo.git" "$clone_dir"
    rm -f "$askpass"
    trap - EXIT
    echo "Cloned $repo to $clone_dir using the GH_PAT from /etc/honeypot-github.env" \
         "(via a one-shot askpass helper; nothing credential-bearing persists)."
  else
    git clone --quiet "https://github.com/$repo.git" "$clone_dir"
    echo "Cloned $repo to $clone_dir anonymously -- works only for a public repo." \
         "If GITHUB_REPO is private, arm GH_PAT in /etc/honeypot-github.env and re-run" \
         "this script; either way wire push credentials (a credential helper or an" \
         "https remote carrying the token) before setting GITHUB_PUBLISH_ENABLED=1."
  fi
fi

systemctl daemon-reload
systemctl reset-failed honeypot-github-publish.service honeypot-github-collect.service 2>/dev/null || true
systemctl enable --now honeypot-github-publish.path honeypot-github-collect.timer

echo "GitHub-analysis publisher installed, dry-run only until /etc/honeypot-github.env is armed by hand."
systemctl --no-pager --plain is-active honeypot-github-publish.path honeypot-github-collect.timer
