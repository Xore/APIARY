#!/usr/bin/env bash
# install-backup-essentials.sh — enable the daily essentials backup on the
# workstation that acts as the backup host.
#
# Modelled on sandbox/install-worker.sh and
# analysis/github/install-github-publisher.sh's unit-install shape: the script
# is copied out to /usr/local/libexec rather than run in place.
#
# analysis/install-backup-timer.sh deliberately does the opposite, because
# backup-honeypot.sh tars up the very checkout it lives in and a copied-out
# version would silently drift from what it backs up. backup-essentials.sh has
# no such coupling -- it only talks to remote hosts over SSH -- so copying it
# out costs nothing.
#
# It is also required here, not a preference. The backup host runs Rocky with
# SELinux enforcing, where a systemd unit cannot exec a file labelled
# user_home_t:
#
#   avc: denied { execute } ... scontext=system_u:system_r:init_t:s0
#                                tcontext=unconfined_u:object_r:user_home_t:s0
#
# Running in place from ~/Github/APIARY fails with 203/EXEC. Anything under
# /usr/local/libexec gets bin_t and just works.
#
# Re-run this script after a `git pull` to pick up a new version.
#
# Run once, as root, on the backup host:
#   sudo scripts/install-backup-essentials.sh
#
# Env:
#   RUN_AS      user the timer runs as       (default: the invoking sudo user)
#   REPO_DIR    checkout to run from         (default: this script's repo)

set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=${REPO_DIR:-$(cd -- "$script_dir/.." && pwd)}
run_as=${RUN_AS:-${SUDO_USER:-xore}}

id "$run_as" >/dev/null 2>&1 || { echo "user '$run_as' does not exist" >&2; exit 1; }
run_group=$(id -gn "$run_as")
passphrase_file=/etc/apiary-backup.pass
libexec=/usr/local/libexec/apiary-backup-essentials.sh

command -v gpg >/dev/null || { echo "gpg is required but not installed" >&2; exit 1; }

# --- passphrase -------------------------------------------------------------
#
# Symmetric AES256 with a passphrase, not a keypair: recovery then depends on
# one string a human can keep in a password manager, with no key file that
# itself needs backing up. The whole point is that a copy of the archive plus
# the passphrase is sufficient -- no access to this machine, this repo, or any
# keyring.

created_passphrase=0
if [[ -s $passphrase_file ]]; then
  echo "keeping existing passphrase at $passphrase_file"
else
  umask 077
  # 32 bytes of base64 from the kernel CSPRNG.
  openssl rand -base64 32 > "$passphrase_file"
  created_passphrase=1
fi
chown "$run_as:$run_group" "$passphrase_file"
chmod 600 "$passphrase_file"

# --- destinations -----------------------------------------------------------

install -d -m 700 -o "$run_as" -g "$run_group" "/home/$run_as/apiary-backups"

# --- units ------------------------------------------------------------------

tmp_unit=$(mktemp)
trap 'rm -f "$tmp_unit"' EXIT

install -d -m 0755 -o root -g root /usr/local/libexec
install -m 0755 -o root -g root "$script_dir/backup-essentials.sh" "$libexec"
# Belt and braces: install(1) already gives it bin_t under /usr/local/libexec,
# but a restorecon makes that explicit and repairs the label if the file was
# copied in some other way first.
command -v restorecon >/dev/null && restorecon "$libexec" 2>/dev/null || true

sed -e "s|^User=.*|User=$run_as|" \
    -e "s|^Group=.*|Group=$run_group|" \
    -e "s|^ExecStart=.*|ExecStart=$libexec|" \
    "$script_dir/apiary-backup-essentials.service" > "$tmp_unit"
install -m 0644 -o root -g root "$tmp_unit" /etc/systemd/system/apiary-backup-essentials.service
install -m 0644 -o root -g root "$script_dir/apiary-backup-essentials.timer" \
  /etc/systemd/system/apiary-backup-essentials.timer

# Pin the checkout the runbooks are collected from, so the unit does not have
# to guess it from $HOME.
if [[ ! -f /etc/default/apiary-backup-essentials ]]; then
  printf 'REPO_DIR=%s\n' "$repo_dir" > /etc/default/apiary-backup-essentials
  chmod 0644 /etc/default/apiary-backup-essentials
else
  echo "keeping existing /etc/default/apiary-backup-essentials"
fi

systemctl daemon-reload
systemctl reset-failed apiary-backup-essentials.service 2>/dev/null || true
systemctl enable --now apiary-backup-essentials.timer

echo
echo "apiary-backup-essentials.timer installed and enabled — daily, +/-30m random delay."
echo "  runs as:  $run_as"
echo "  from:     $libexec (copied from $repo_dir; re-run this installer after a git pull)"
echo "  run now:  systemctl start apiary-backup-essentials.service"
echo "  logs:     journalctl -u apiary-backup-essentials.service"

if [[ $created_passphrase -eq 1 ]]; then
  cat <<EOF

  ############################################################
  #  BACKUP PASSPHRASE — SAVE THIS IN YOUR PASSWORD MANAGER  #
  ############################################################

$(cat "$passphrase_file")

  Every archive is encrypted with it. It is stored on this machine at
  $passphrase_file, which is no help at all if this machine is the thing
  that died — that is the case the backups exist for. Put it somewhere
  else, now.

  Recover with:  gpg -d archive.tar.gz.gpg | tar xz
EOF
fi
