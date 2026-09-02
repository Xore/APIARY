# Research: CVE-2026-41567 — Moby archive-API container-binary execution — sensor host exposure (#2824)

Verifies the CVE's mechanics against the vendor advisory (not the secondary
aggregators the issue itself already flagged as having inflated the CVSS
once), measures both hosts' actual Docker/Moby version against the affected
range, and enumerates real Docker-socket reachability from compose files and
live `docker inspect` output rather than from memory. Gathered 2026-09-02.

**Scope, per the issue:** analysis only. No upgrade was performed, no
detection was built, and no socket-proxy config was touched.

## 1. The CVE, re-verified against the primary advisory

- **Primary sources:** the [GitHub Security Advisory](https://github.com/advisories/GHSA-x86f-5xw2-fm2r) (mirrored at [moby/moby's own advisory](https://github.com/moby/moby/security/advisories/GHSA-x86f-5xw2-fm2r)), cross-checked against distro trackers ([Alpine](https://security.alpinelinux.org/vuln/CVE-2026-41567), [SUSE](https://www.suse.com/security/cve/CVE-2026-41567.html)).
- **Mechanism, more precise than the issue's summary:** when a **compressed**
  archive (`xz` or `gzip`) is uploaded via `PUT /containers/{id}/archive` or
  piped through `docker cp -`, the daemon resolves the decompression binary
  (`xz`, `unpigz`, etc.) **from the target container's own filesystem
  rather than the host's**, due to incorrect operation ordering. A
  container built from a malicious image can ship a trojanized
  `xz`/`unpigz` binary at the path the daemon looks up, which then executes
  with full daemon privileges — host root UID, unrestricted capabilities —
  the moment *any* compressed archive is written into that container via
  the archive API. The issue's summary ("piping an archive into a container
  created from an untrusted image lets the image execute code") is directionally
  correct but omits the compression-format precondition, which matters for
  §5's coverage question below: an **uncompressed tar** through the same
  endpoint does not hit this bug at all, because no decompression binary is
  ever resolved or invoked.
- **CVSS confirmed at 7.2** (`AV:L/AC:H/PR:L/UI:R/S:C`) directly from the
  advisory — the issue's own correction of the secondary aggregator's 9.6 is
  right, and I found no source disputing 7.2.
- **Affected: Moby < 29.5.1, moby/moby v2 < v2.0.0-beta.14. Fixed in Docker
  Engine 29.5.1 and moby/moby v2.0.0-beta.14** — confirmed against the
  advisory, matching the issue's own stated range exactly.

## 2. What Docker/Moby version do the homeserver and the VPS actually run — measured, not assumed

```
$ ssh homeserver "docker version --format '{{json .}}'"
Server.Version: 29.7.2
Server.Components[0] (Engine): Module github.com/moby/moby/v2, ModuleVersion v2.0.0+unknown
```

```
$ ssh homeserver "sudo ssh -p 2222 -i /root/.ssh/strato_vps root@10.8.0.1 \
    docker version --format '{{json .}}'"
Server.Version: 29.7.2  (identical build — same Engine version string, same components)
```

(Direct `ssh vps` from this workstation returned `Permission denied
(publickey)` at the time of this check — the VPS's own SSH key for this
workstation may have rotated or the workstation's forwarding changed since
the last verified session; fell back to the documented `homeserver`→VPS hop
route, which worked and returned an identical result.)

**Both hosts run Engine 29.7.2 — above the 29.5.1 fixed threshold.
Neither host is in the CVE's affected range.** The `Module`/`ModuleVersion`
field (`github.com/moby/moby/v2`, `v2.0.0+unknown`) is the newer
`moby/moby` v2 module-versioning line the advisory also names, but the
governing number for the fix is the Engine release (29.7.2), which the
advisory states directly supersedes 29.5.1. Both hosts patched **before**
this assessment even started — this is not a finding requiring a
maintenance window.

## 3. Socket reachability — enumerated from compose files and live state, not memory

Grepped every compose file under `arcane/home/` and `vps/` for
`docker.sock` and `privileged: true` rather than relying on the issue's own
example list:

| Container | Socket access | Real exposure |
|---|---|---|
| `hp-tanner-docker` (`honeypot-tanner/compose.yml`) | **No** raw socket bind at all. Runs its own disposable **nested** Docker daemon (`privileged: true`, `DOCKER_TLS_CERTDIR=`) — the compose file's own comment states this explicitly and warns future editors never to replace it with a bind mount of the homeserver's socket | The privileged flag here grants control of the *nested* daemon inside its own container, not the homeserver's real one. CVE-2026-41567 could still fire **inside that nested daemon** if it also runs an unpatched Moby and untrusted decoy images pipe compressed archives into it — version of the nested daemon not checked (see §6) |
| `hp-services-adapter` (`honeypot-dashboard/compose.yml:826`) | **Yes** — raw `/var/run/docker.sock:/var/run/docker.sock` bind, the one genuine direct-socket mount found outside the proxy pair | Hardened: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`. These don't block the archive-API vector specifically (a Docker API call over the socket doesn't need any of the dropped Linux capabilities *inside this container* — the danger is entirely on the daemon side), but they do mean a compromise of this adapter itself is already the "attacker has full daemon access" scenario regardless of this CVE |
| `hp-autoheal` (`honeypot-utilities/compose.yml:203-224`) | **No** direct bind — talks to `docker-socket-proxy:2375` over its own private network (`DOCKER_SOCK=tcp://docker-socket-proxy:2375`) | Gated by the proxy (below) |
| `hp-docker-socket-proxy` (`honeypot-utilities/compose.yml:124-146`) | **Yes**, `ro` bind of the real socket, `tecnativa/docker-socket-proxy:v0.5.0` | The only container standing directly between the real socket and every other consumer in this stack |
| Every other compose file's `docker.sock` mention (`conpot`, `cowrie`, `dnp3`, `elk`, `endlessh`) | **No socket access in that file at all** — every one of these is a comment explaining that the *separate* `hp-autoheal` container (not the service defined in that file) watches it daemon-wide by label. Read each file directly rather than trusting the grep hit as a positive | None — false positives from the initial grep, resolved by reading context |
| CI runners (`github-ci-runner`, `github-deploy-runner`) | Both in the `docker` group per #2780 (this batch's other decision row) — group membership is host-root-equivalent, confirmed there independently | Same daemon, same archive-API surface, if either runner's job pulls/runs an untrusted image and pipes a compressed archive into it. Directly adjacent to #2780's open decision, not something this issue should pre-empt |

**The proxy's actual ACL matters and I could not fully resolve it.**
`docker-socket-proxy`'s environment sets `CONTAINERS=1`, `IMAGES=1`,
`POST=1` (`honeypot-utilities/compose.yml:130-132`). `tecnativa/docker-socket-proxy`'s
`POST` flag is documented upstream as a blanket toggle for mutating
requests across whichever resource categories are enabled — whether that
specifically includes `PUT /containers/{id}/archive` (a `PUT`, not a
`POST`, despite the flag's name) is a detail of the proxy's own request-method
matching that I did not verify by reading `tecnativa/docker-socket-proxy`'s
source. Flagged as unverified in §6 rather than asserted either way — this
is the one live question that would actually change the exposure answer,
since `hp-autoheal` is the one container that talks to the daemon *only*
through this gate.

## 4. RedTail/#2721 adjacency, checked rather than assumed

The issue draws an analogy to #2721's RedTail Docker-API worm campaign,
which the plan notes probed exposed sockets directly. That worm's
precondition (an internet-reachable, unauthenticated Docker API, the
classic `tcp:2375` exposure) is a **materially different** exposure shape
from this CVE's precondition (`AV:L` — local access to *an already-running*
Docker API endpoint, `UI:R` — a user or automated process has to actually
push a compressed archive into a container built from the malicious
image). Nothing in this fleet exposes the raw Docker API on a routable
port the way the RedTail campaign's targets did — every consumer here
either reaches the socket through a Unix-domain bind inside the same host
(`hp-services-adapter`, the CI runners) or through the socket-proxy's
gated TCP listener on a private Docker network
(`docker-socket-proxy_net`, explicitly commented as reachable by nothing
else in the stack). The adjacency the issue draws is real in spirit
(both are Docker-API-surface risks) but the specific worm behavior #2721
describes does not have a matching entry point here today.

## 5. Detection: is Docker API request activity logged anywhere in this fleet?

**No.** Grepped for any Docker API audit/access logging config
(`dockerd` audit flags, an API-request-logging sidecar, `auditd`) across
every compose file and found none. `docker-socket-proxy` itself can emit
access logs (`LOG_LEVEL` env var, not currently set in this stack's
config), but nothing currently ships or ingests them into Elasticsearch —
there is no `docker-socket-proxy` entry in `arcane/home/honeypot-elk/analysis/filebeat.yml`'s
log-source list. **The issue's proposed detection signature (archive PUT →
`exec_create` correlation within 5s, or an archive request from outside the
management network) has nothing to run against today.** This matches the
issue's own instruction to say so plainly rather than sketch a signature
over a stream that isn't collected — building that collection is
out-of-scope new work, not a config toggle.

## 6. What I could not verify

- Whether `tecnativa/docker-socket-proxy`'s `POST=1` flag actually gates
  `PUT` requests to the archive endpoint, or only literal HTTP `POST`
  verbs — I did not read the proxy's own ACL-matching source. This is the
  one open question that bears directly on `hp-autoheal`'s real exposure,
  flagged rather than guessed at.
- The Moby/Docker version running inside `hp-tanner-docker`'s **nested**
  daemon — a separate, disposable Docker-in-Docker instance the compose
  file explicitly isolates from the host socket. If that nested daemon is
  older than 29.5.1 and tanner's emulated services pull attacker-influenced
  images that pipe compressed archives through it, the CVE could apply
  *inside that sandbox* independent of the host's patched version. Did not
  check the pinned base image tag for that service in this pass.
- Direct `ssh vps` from this workstation failed with `Permission denied
  (publickey)` at the time of this check (worked via the documented
  homeserver-hop fallback instead) — noting this as a possible drift in the
  workstation's direct VPS key/session that's worth a quick separate check,
  not something this issue's scope covers fixing.

## 7. Bottom line

Both hosts are patched (Engine 29.7.2 ≥ 29.5.1) — **this is not an active
exposure requiring a maintenance window**, contrary to what "we run Docker,
therefore we might be exposed" would suggest before measuring. The more
durable finding is structural: Docker API access is not logged anywhere in
this fleet today, so *if* a future regression reintroduced an old Engine
version, or if the nested `tanner_docker` daemon (unchecked, §6) turns out
to be behind, there would be no signal of exploitation either way. That
gap is general to Docker-API-surface risk, not specific to this one CVE,
and building the logging is real follow-on scope (#2366/#2780/#2825's
territory per the issue's own cross-reference), not something to bolt onto
this research row.
