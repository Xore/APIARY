# VPS admin SSH access — key inventory

There is no installer or provisioning script that manages
`/root/.ssh/authorized_keys` on the VPS. It is edited by hand, which is how it
drifted (#2860): the workstation's admin key was rotated on 2026-08-31 (new
key, comment `apiary-hermes-control`, replacing the retired
`kimi-cli-honeypot-admin` key) and the new public half was added to the
homeserver's `authorized_keys` but never to the VPS's. The direct `ssh vps`
alias then failed `Permission denied (publickey)` for six days while the
homeserver-hop route (which uses the separate `strato_vps` key installed by
`scripts/install-homeserver.sh`) kept working and masked the drift.

## Two independent keys reach the VPS as root

| key | private key location | purpose |
|---|---|---|
| workstation admin key | `~/.ssh/id_ed25519_apiary` (comment `apiary-hermes-control`) | direct `ssh vps` alias from the workstation |
| `strato_vps` | `/root/.ssh/strato_vps` on the homeserver, installed by `install-homeserver.sh:step_provision_secrets` (`install -m 600 "$VPS_SSH_KEY" /root/.ssh/strato_vps`) | the homeserver-hop route: `ssh homeserver` → `sudo ssh -p 2222 -i /root/.ssh/strato_vps root@<wireguard-addr>` |

Both must independently be present in the VPS's `/root/.ssh/authorized_keys`.
Rotating one does not rotate the other, and neither installer asserts the
workstation admin key — that entry is manual and must be re-added by hand
after any workstation key rotation:

```
ssh homeserver "sudo ssh -p 2222 -i /root/.ssh/strato_vps root@<wireguard-addr> \
  'echo \"<new pubkey line>\" >> /root/.ssh/authorized_keys'"
```

## Verifying both paths still work

```
ssh vps hostname                                                    # direct
ssh homeserver "sudo ssh -p 2222 -i /root/.ssh/strato_vps root@<wireguard-addr> hostname"  # hop
```

Both must return the VPS's own hostname, with no passphrase prompt and no
agent. Do not assert a specific expected string here: the VPS was reinstalled
on 2026-09-03 (Ubuntu -> Rocky Linux 9) and now answers `localhost` until its
hostname is set, so a hardcoded expectation would fail on a correct host.

If the direct path fails but the hop still works, check in order: whether the
workstation's current public key is in the VPS's `authorized_keys`
(`ssh -vvv vps hostname 2>&1 | grep -i offering` shows which private key the
alias is offering; compare its fingerprint against
`authorized_keys` with `ssh-keygen -lf`), whether `~/.ssh/config`'s `vps` stanza
still points `IdentityFile` at the current key, and whether `sshd_config` on
the VPS changed (`prohibit-password` root login and the default
`AuthorizedKeysFile .ssh/authorized_keys` are the expected values as of
2026-09-03).

## The admin SSH port is part of this inventory too

Admin SSH is supposed to listen on **2222**, not 22, so that port 22 belongs to the
honeypot (`docs/CGNAT-DEPLOYMENT.md` step 1 -- and that step has no script; it is
done by hand). Both commands above therefore assume a port, and the assumption has
already been wrong once: after the 2026-09-03 reinstall sshd came back on 22, which
made `portbridge` fail to bind the cowrie SSH rule (#2923) and would break the hop
command below, which hardcodes `-p 2222`.

Check it rather than assume it, on the host:

```
sshd -T | grep '^port'
ss -ltnp | grep ':22 '        # should be portbridge, not sshd
```

and match the alias in `~/.ssh/config` to whatever it really is.

## The third direction: homeserver -> workstation

Two of the three key paths that matter are above. The third is
**homeserver -> workstation**, which `install-homeserver.sh:step_restore_env_files`
depends on: it `scp`s each stack's `.env` **from** the backup host
(`scp -i "$BACKUP_HOST_KEY" -P 22 ... "${BACKUP_HOST_USER}@${BACKUP_HOST}:..."`),
falling back to `.env.example` only when no backup exists. A reinstall run
against a stale `BACKUP_HOST` therefore does not fail loudly -- it silently
restores placeholder `.env` files for every stack.

`BACKUP_HOST` lives in the private `install-homeserver.conf`, not in this
repo, and the workstation's LAN address has changed more than once. Before
any reinstall, verify the configured value actually resolves to the current
workstation rather than assuming it:

```
ssh homeserver "ssh -o BatchMode=yes -o ConnectTimeout=5 <backup-user>@<backup-host> hostname"
```

If that does not return the workstation's hostname, fix `BACKUP_HOST` in
`install-homeserver.conf` before running the installer.

## Reinstall note (#1609)

A bare-OS reinstall of the VPS replaces `/root/.ssh/authorized_keys`
entirely, and **both** entries above are manual on the VPS side.
`install-homeserver.sh:step_provision_secrets` re-provisions only the
*private* half of `strato_vps`, onto the homeserver; nothing in either
installer writes any public key into the VPS's `authorized_keys`
(`git grep authorized_keys scripts/` finds no such step). So after a VPS
reinstall, the workstation admin key **and** the hop key's public half both
have to be re-added by hand from this doc, or the alias fails again with no
record of why.

This is not hypothetical: the VPS was reinstalled on 2026-09-03 and its
`authorized_keys` was replaced. The workstation admin key was re-added by
hand and the direct alias works; at the time of writing the homeserver had
also just been reinstalled and did not yet hold `/root/.ssh/strato_vps`, so
the hop route was unavailable and the direct alias was the only working path
to the VPS. Restore order matters: if the direct alias is not established
first, a reinstall of both hosts leaves no remote path in at all.
