# Research: full-installation smoke test (#518)

Live-system findings from the actual homeserver (`supermicro`) and VPS
(`87.106.162.235`), gathered 2026-08-04 to inform the smoke-test plan and
the eventual single install script. This is a snapshot, not a design —
treat it as ground truth to reconcile the design docs against, not as
something to keep updating by hand.

## 1. What's already running (home)

All 12 home Dockge stacks plus the sandbox/ghidra/pihole/dockge
infrastructure are up and healthy right now — this is a far more complete
baseline than `docs/ROADMAP.md` (last audited 2026-07-31) describes. The
roadmap says `ml-worker` is "a scaffold, not a Compose service" and that
`llm-worker`/`reporter` "do not exist" — both are stale:

- `hp-ml-worker` is running (`ml-worker-ml-worker` image), GPU-attached.
- `hp-reporter` is running (`honeypot-utilities-reporter` image).
- `llm-worker/` exists and is intentionally **not** a persistent stack —
  its README documents it as a safety-gated one-shot process (synthetic
  contract checks by default; a captured-data / production-session canary
  requires explicit compose overlay files and `LLM_ENABLED`/
  `LLM_ALLOW_CAPTURED_DATA` flags). This is correct behavior per #66/#83,
  not a gap — the smoke test should exercise the *documented* invocations
  (`--selftest`, synthetic canary, production-session canary), not expect
  a always-on `hp-llm-worker` container.

**Action:** update `docs/ROADMAP.md`'s "Current baseline" section — it's
actively misleading about what exists.

Running container inventory (46 containers) spans: all honeypot sensors
(cowrie, dionaea+tftp-relay, conpot x5 personas + guardian, dnp3, http+api,
multipot, cisco-asa, citrix, rdp, dicompot, dns), SNARE+TANNER (6
containers), ELK (elasticsearch, kibana, filebeat, evebox, arkime capture +
viewer), dashboard + es-results-importer + services-adapter,
payload-dedupe + yara-scanner, ip-enrichment-worker, autoheal,
log-maintenance, ghosts (NPC sandbox, API + postgres), and a separate
Ghidra static-analysis stack (`ghidra-ghidra-1`, `ghidra-statictools-1`,
`ghidra-revdeck-1`, `ghidra-ollama-1`).

## 2. GPU / Ollama / ML — matches the design docs, don't rebuild it

- Driver: NVIDIA 580.173.02, CUDA 13.0, `nvidia-smi` and
  `nvidia-container-toolkit` (1.19.1) both present and working.
  `nvidia-container-runtime` is wired into `/etc/docker/daemon.json` as the
  `nvidia` runtime.
- No host-level `nvcc` or `ollama` binary — **this is correct by design**,
  not missing. `docs/gpu-llm-analysis-worker.md` and
  `docs/gpu-ml-worker-acceleration.md` both specify Ollama runs as the
  shared containerized service in the Ghidra stack (`ghidra-ollama-1`,
  image `ollama/ollama:0.32.0`) and CUDA PyTorch wheels are self-contained
  in `ml-worker`'s image — no CUDA toolkit needed on the host beyond the
  driver.
- One RTX 4000 Ada (20 GB card, docs say 8192 MiB — **verify this**:
  `nvidia-smi` on this box reports 20475 MiB total, which doesn't match
  the "8192 MiB" figure quoted throughout `gpu-llm-analysis-worker.md` and
  `gpu-ml-worker-acceleration.md`. Either the card was upgraded since
  those docs were written or the docs describe a different unit — reconcile
  before scripting VRAM budgets.)
- GPU is idle (2 MiB used, no processes) at time of writing — confirms
  Ollama's `OLLAMA_KEEP_ALIVE` unload behavior is working as documented.

**Smoke test for this area should**: verify driver/toolkit versions,
`docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi -L`,
`ollama list` inside `ghidra-ollama-1` for the pinned model
(`qwen3.5:9b@...` per `analysis/ghidra/models/approved-models.json`), and
the T1–T4 checks already written out in `docs/gpu-ml-worker-acceleration.md`
§8 and `docs/gpu-llm-analysis-worker.md` §"Verification" — those exist,
they just haven't been wired into an automated script.

## 3. Disk layout (home) — see `docs/HOMESERVER-DISK-LAYOUT.md`

The homeserver was installed via Ubuntu's `subiquity`/`curtin` autoinstaller
(confirmed from `/etc/fstab` comments and `/etc/netplan/00-installer-config.yaml`
header). Four physical disks, each with one job. Full breakdown and an
autoinstall template to reproduce it are in the new
[`docs/HOMESERVER-DISK-LAYOUT.md`](../HOMESERVER-DISK-LAYOUT.md).

## 4. VPS — reachable, Traefik/portbridge/Suricata healthy, no Wireshark yet

VPS admin access is `ssh -p 2222 root@87.106.162.235` (key-based). The
**port 22 host-key mismatch is expected, not an incident**: port 22 on the
VPS public IP is bound by `portbridge` (`ss -tlnp` shows
`*:22 users:(("portbridge",...))`), which tunnels it to the home Cowrie SSH
honeypot — Cowrie legitimately presents a different/rotating host key.
Real admin SSH is the OpenSSH daemon on 2222 (socket-activated,
`0.0.0.0:2222` and `[::]:2222`), which was not affected.

Running on the VPS: `traefik` (v3.7.8, healthy), `hp-portbridge`, `hp-p0f`,
`hp-suricata` + rules-refresh + log-maintenance + log-rotate,
`auth-portal`/`auth-redis` (SSO), and one `socat` sidecar per proxied
service (23 of them) bridging the VPS-side port to the WireGuard tunnel.

**Findings to act on:**
- **No `wireshark`/`tshark`/`dumpcap` installed** — only `tcpdump`. The
  Wireshark setup in #518 needs to be designed from scratch: headless
  capture (`tshark`/`dumpcap`) on the VPS's public interface, rotated pcap
  files, and either (a) a read-only export path back to home the same way
  Suricata/portbridge logs already do it (see below), or (b) a
  `dumpcap`-writes / `wireshark`-reads split where the GUI only ever runs
  on the home side against synced pcaps. Recommend (a)+(b) combined,
  matching the existing pattern — don't open a new inbound path to the VPS
  for this.
- **Two orphaned `p0f` containers** (`elegant_jackson`, `determined_gagarin`,
  auto-generated Docker names, not part of `vps/docker-compose.yml`'s
  `hp-p0f`) have been running for 2 days alongside the properly-managed
  `hp-p0f`. These look like stray manual `docker run` invocations that
  were never cleaned up — worth a quick decision (stop them / find out who
  started them) before folding VPS state into a scripted install, so the
  script doesn't have to special-case them.
- VPS disk: single 120G virtio disk (`vda`), 15G used — no RAID, no extra
  mounts. Much simpler than home; an autoinstall template isn't as useful
  here since VPS provisioning is provider-image-driven, not PXE/ISO
  autoinstall. Worth documenting the provider image + cloud-init used, if
  known, as a separate short section rather than forcing it into the same
  autoinstall template as the homeserver.
- `.env` files present: `/root/vps/.env` (37 lines), `/root/auth-backend/.env`
  (43 lines) — both root-only permissions (0600), already correctly
  restricted. These belong in the backup-blocker inventory (§5).
- Suricata log path confirmed: VPS writes to a named volume mounted at
  `/etc/suricata` + `/var/lib/suricata` inside `hp-suricata`, and the
  container's actual EVE/log output is bind-mounted from
  `/opt/stacks/honeypot-stack/logs/suricata` on the VPS, which the
  homeserver pulls **read-only** via `sshfs` (see `/etc/fstab` on home —
  `IdentityFile=/root/.ssh/strato_vps`, `port=2222`,
  `PasswordAuthentication=no`). Portbridge logs use the identical pattern.
  **The Wireshark pcap path should reuse this exact mechanism** — write on
  VPS, pull read-only over the existing sshfs mount (or a new one scoped
  to a pcap directory) rather than pushing from VPS to home.

### Session note: VPS SSH access

This research session did not have outbound SSH credentials for the VPS
under the `xore` user (only `root`'s `/root/.ssh/strato_vps` key existed,
readable via this box's passwordless-sudo group membership). Per explicit
user instruction, that key was copied to `~/.ssh/vps_strato_key` under
`xore` and an `ssh vps` config alias was added
(`HostName 87.106.162.235`, `Port 2222`, `User root`), with the known-host
fingerprint carried over from `root`'s already-trusted `[10.8.0.1]:2222`
entry (not blindly accepted). **This duplicates a production-root key into
a second location** — worth a deliberate decision during the smoke-test
work about whether that's the long-term access model (e.g., a
scoped/non-root key for automation instead) rather than leaving two copies
of the same root key lying around.

## 5. Backup-blocker inventory (issue's explicit hard blocker)

Everything below must be backed up off-host before smoke testing starts,
per the issue. No database backup needed (explicitly out of scope).

**Home (`supermicro`):**
- `.env` files — 23 found under `/var/dockge/stacks/*/.env`, plus
  `honeypot-init.env` and the top-level `.env` in the `honeypot-stack`
  Dockge checkout. (List is in the research; don't paste contents into any
  doc/issue — treat the list itself as sensitive.)
- Windows sandbox state: nothing under `sandbox/` in the repo checkout is
  a built image — VM disks/ISOs live outside the repo (need to confirm
  exact host paths from whoever built the current sandbox golden image;
  not found under an obvious path in this pass — **follow-up needed**,
  see open questions).
- `/opt/honeypot-ghidra/backups/` already exists (has at least
  `issue-144/`) — existing backup mechanism to fold into the same
  off-host backup pass rather than reinvent.
- No separate "Windows ISO" directory was found under common locations in
  this pass (`sudo find` for `*.iso`/`*.qcow2` only turned up an unrelated
  `ipxe.iso`) — **this needs a direct answer from whoever manages
  `sandbox/windows`**, not a guess.

**VPS:**
- `/root/vps/.env`, `/root/auth-backend/.env` (both 0600, root-owned).
- Traefik/Suricata/portbridge config under `/root/vps/` (small, 644K
  total) — cheap to back up wholesale.

## 6. Docs-vs-reality gaps found this pass

- `docs/ROADMAP.md` "Current baseline" is stale on `ml-worker`/
  `llm-worker`/`reporter` status (§1 above).
- GPU VRAM figure mismatch between docs (8192 MiB) and live hardware
  (20475 MiB) (§2 above) — needs reconciling before the GPU smoke test
  encodes a wrong budget.
- No doc currently describes VPS packet capture at all — this is new
  ground, not a reconciliation.
- No doc currently describes the homeserver's physical disk layout — new
  `docs/HOMESERVER-DISK-LAYOUT.md` fills that gap.

## 7. Open questions for the issue owner

1. Where do the Windows sandbox VM disks and installer ISOs actually live
   on disk right now? Not found in this pass; needed before the backup
   blocker can be marked done.
2. Are `elegant_jackson`/`determined_gagarin` (orphaned VPS `p0f`
   containers) safe to stop, or are they intentional and just need proper
   compose ownership?
3. Long-term VPS access model: keep reusing the root `strato_vps` key
   (now duplicated to `xore`'s home directory on the homeserver), or cut a
   scoped automation key?
4. Confirm the actual GPU card/VRAM (20 GB seen live vs. 8 GB in docs) so
   `docs/gpu-*-worker*.md` can be corrected in the same pass.
