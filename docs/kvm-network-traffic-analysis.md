# Network Traffic Analysis in the KVM Environment

> **Status (2026-07-31):** rewritten. This was a 1000-line greenfield build
> guide for a capture pipeline that was never built as described — different
> bridge names, different addresses, different paths, and a sample-execution
> script that contradicted the isolation model the sandboxes were actually
> given. Nearly everything it proposed to build now exists, built differently
> and better. What follows is where each piece lives and why it is shaped the
> way it is. Remaining gaps are
> [#87](https://github.com/Xore/honeypot-stack/issues/87).
>
> The superseded version is in git history if the original reasoning is ever
> wanted; do not restore it.

---

## The short version

Traffic is captured on the host side of an isolated libvirt bridge, never
inside the guest and never by an agent the guest could interfere with. There
are **two** such bridges, because there are two sandboxes:

| | Windows detonation guest | Linux / Wine runner |
|---|---|---|
| Bridge | `virbr-sandbox` | `virbr-hpsbx` |
| Subnet | `10.10.10.0/24` | isolated, no DHCP |
| Network XML | `sandbox/windows/setup/sandbox-network.xml` | `sandbox/network.xml` |
| Fake internet | INetSim at `10.10.10.1` | none by default; optional logged DNS + Squid allowlist (`controlled` mode) |
| Capture | `docker-compose.sandbox.yml` (tcpdump, Zeek, Suricata) | root-owned `tcpdump` per job, host and guest side |
| Results | `sandbox/results/<run>/` | `/var/lib/honeypot-sandbox/results/` (root-only), sanitized export copied out |
| Orchestrator | `sandbox/windows/orchestrate/run_sample.py` | `sandbox/run-linux-sample.sh` |

Neither bridge has a `<forward>` element, so neither can route anywhere. That
is the first barrier, not the only one.

---

## 1. Where capture actually happens

### 1.1 Windows guest — a per-detonation gateway stack

`docker-compose.sandbox.yml` is brought up around a single detonation and
stopped after it. `run_sample.py` drives both ends. It is deliberately **not**
part of `docker-compose.yml` and must never be merged into it.

- **INetSim** (`10.10.10.1`) resolves every name to itself and answers on every
  port. This is not decoration: a sample that gets connection-refused stops
  early and tells you nothing, so answering everything is what puts the whole
  C2 conversation into the logs. Anything the sample downloads lands in
  `fakenet_logs/`.
- **Zeek** and **Suricata** sniff the bridge from the *host* side with
  `network_mode: host` and `NET_ADMIN`/`NET_RAW`. That vantage point is the
  only one that sees traffic addressed to something nothing answers on. It is
  also a genuine privilege grant, which is why only these two sniffers have it
  — INetSim and mitmproxy run with all capabilities dropped.
- **tcpdump** writes `network.pcap`. Zeek's logs are derived evidence; the pcap
  is the primary record and the one thing you cannot reconstruct if a parser
  turns out to have been wrong about a protocol.
- **mitmproxy** is opt-in (`--profile mitm`) and off by default. Enabling it
  means pointing `dns_default_ip` at `10.10.10.3`, which also aims SMTP, FTP and
  IRC at a proxy that does not speak them. Worth it for decrypted bodies from
  one specific sample; a net loss as a standing default. The guest must trust
  its CA before `GOLDEN_READY` is taken — a certificate error is itself an
  evasion trigger for some families.

### 1.2 Linux / Wine runner

`sandbox/run-linux-sample.sh` and the queue worker capture two pcaps per job: a
root-owned `network.pcap` on the bridge, filtered to that job's fixed MAC, and a
guest-side `guest-network.pcap` that includes loopback and resolver traffic. The
unprivileged sample cannot stop either.

Every transient VM gets the host-enforced `honeypot-sandbox-strict` libvirt
filter, which permits ordinary IPv4/IPv6/ARP while preventing source-MAC
spoofing and dropping other layer-2 protocols — so the per-MAC capture filter
cannot be evaded from inside.

---

## 2. Isolation: three barriers, not one

For the Windows bridge:

1. The libvirt network has no `<forward>`.
2. The gateway containers sit on a macvlan marked `internal: true`, which
   removes the default route Docker would otherwise install.
3. Phase 0 adds an iptables DROP pair across `virbr-sandbox`.

Removing any one of them because "the container needs to pull something" puts
live malware on the internet. Build images ahead of time instead.

A side effect of macvlan, and it is the expected one: **the host cannot talk to
those containers.** Collect their output from the bind-mounted results
directory, not over the network.

The Linux side reaches the same place differently — an early nftables chain
rejects every other host or forwarded packet, and IP forwarding and libvirt NAT
are never enabled. Optional `controlled` mode adds exactly two things: a logged
DNS endpoint and an allowlisted HTTP/HTTPS proxy at `198.18.0.1`. Direct guest
connections, private destinations, arbitrary domains and non-HTTP protocols stay
blocked.

---

## 3. Two rejected designs, and why

These are recorded because both look reasonable and both were in the superseded
guide as finished, copy-pasteable code.

### 3.1 No guest agent, no live sample injection

The old §9.1 opened a file handle in a **running** guest over the QEMU guest
agent, streamed the sample in base64, and called `guest-exec` to run it.

The **Linux runner** refuses this outright. Samples are injected with
`virt-copy-in` / libguestfs **while the VM is powered off**, results are
extracted with `virt-copy-out` after forced shutdown, and the overlay is then
destroyed. There is no host-to-guest management service at all, so a
compromised guest has no channel to push data back through.

The **Windows orchestrator does not have this property**, and an earlier
revision of this section wrongly claimed it did. `run_sample.py` waits for
WinRM on the booted guest and drives the whole run through it — sample copy
over SMB, then ProcMon, FakeNet, Regshot and execution as PowerShell
invocations. The reason is real: the telemetry tools have to be started before
the sample and stopped after it, from outside its control, which offline
injection alone cannot do. The cost is equally real: a credentialed service
listening inside a guest that is deliberately running malware.

That is [#94](https://github.com/Xore/honeypot-stack/issues/94) — a decision to
make before the golden image is built, since the credentials and the share are
baked into it. Until it is made, treat the Windows sandbox's isolation as
resting on the *network* barriers in §2 alone, not on the absence of a
management channel.

The QEMU guest agent is also installed in the golden image for host-side file
copy. It is a narrower grant than `guest-exec` on a live infected VM, and it is
not how a sample gets in.

### 3.2 No libvirt lifecycle hooks

The old guide started tcpdump from `/etc/libvirt/hooks/qemu.d/capture-start`
on any domain named `analysis-*`.

Capture lifecycle is owned by the orchestrator instead — `run_sample.py` for
Windows, the worker for Linux. That matters for a specific reason:
`run_pending.sh` holds a non-blocking `flock` so that overlapping spool triggers
collapse into one drain, because two concurrent detonations would revert the
snapshot out from under each other. A libvirt hook fires outside that lock, on
domain state alone, and would happily start a second capture into a second file
for a run the worker does not know about.

---

## 4. What downstream consumes it

- **Arkime** is deployed and indexes the **VPS** sensor's pcap ring from
  `logs/suricata/pcap/`, mounted over WireGuard. It does *not* currently index
  sandbox captures — [#87](https://github.com/Xore/honeypot-stack/issues/87).
- **EveBox** and **Kibana** read the VPS `eve.json`. See
  [`../vps/suricata/README.md`](../vps/suricata/README.md), including the
  `HOME_NET` trap and the fact that `eve.json` is unrotated
  ([#79](https://github.com/Xore/honeypot-stack/issues/79)).
- **The dashboard** reads the sanitized export directory read-only and shows
  worker state, dynamic risk, static YARA versus observed behaviour, ATT&CK
  mappings, syscalls, file changes, DNS names and bounded packet summaries.
  Authenticated administrators can download the pcaps. Oversize pcaps and the
  raw result directories stay root-only.
- **`generate_report.py`** folds `zeek_logs/http.log` into the Windows report.
  The Linux sandbox has no Zeek equivalent — also
  [#87](https://github.com/Xore/honeypot-stack/issues/87).

## 5. Retention

Already automated. `/etc/default/honeypot-sandbox` sets raw-result retention to
30 days and sanitized export retention to 180;
`honeypot-sandbox-cleanup.timer` applies it daily. Failed requests stay
root-only for 30 days and orphaned staged samples expire after seven.

The VPS side is not equivalent: `pcap-log` is a bounded ~50 GB ring, but
`eve.json` has no rotation at all (#79).

---

## 6. Pitfalls that are still true

| Symptom | Cause |
|---|---|
| Sniffer container starts but logs nothing | It is on the macvlan instead of `network_mode: host` — a container interface does not see the bridge |
| Host cannot curl the gateway containers | Expected. macvlan; read the bind-mounted results directory instead |
| Detonation depends on a network fetch and hangs | The gateway stack has no route to the internet by design. Refresh Suricata rules on the host, ahead of time |
| Two captures for one sample | Something started a detonation outside `run_pending.sh`'s lock |
| Guest reaches nothing and the sample exits in seconds | Working as intended on the Linux side without `controlled` mode; on the Windows side it means INetSim did not come up |

---

## References

- [libvirt Hooks](https://libvirt.org/hooks.html) — for context on §3.2, not because they are used
- [Suricata configuration](https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html)
- [Zeek documentation](https://docs.zeek.org/en/master/)
- [Arkime documentation](https://arkime.com/documentation)
- [INetSim manual](https://www.inetsim.org/documentation.html)
- [`docs/kvm-snapshot-vs-golden-image.md`](kvm-snapshot-vs-golden-image.md)
- [`sandbox/README.md`](../sandbox/README.md) — the Linux runner, in detail
- [`sandbox/windows/IMPLEMENTATION_PLAN.md`](../sandbox/windows/IMPLEMENTATION_PLAN.md) — the Windows phases
