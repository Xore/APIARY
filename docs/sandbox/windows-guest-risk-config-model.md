# Windows detonation guests — per-VM risk/realism configuration model

> **Status**: Model documented against the three real guest profiles that
> exist today. Not a code refactor — each profile's actual configuration
> stays exactly as built; this records the axes, the one hard rule, and
> where each profile currently sits, so a fourth profile (or a change to
> an existing one) has a real model to check itself against instead of
> re-deriving the reasoning from scratch. See "Follow-up work" for what
> this surfaced but didn't build.
> **Last updated**: 2026-08-08
> **Tracking**: [#467](https://github.com/Xore/APIARY/issues/467)

---

## Why this exists

[#467](https://github.com/Xore/APIARY/issues/467) came up while adding
BYOVD driver bait (LOLDrivers) to `win11-analysis.qcow2` and asking
whether `win11-ghosts.qcow2` should get the same treatment. The honest
answer required stepping back from "yes/no on this one feature" to "what
*is* a guest's risk/realism configuration, actually" — each detonation
host today is a fixed, hand-built bundle of properties, not a point in a
documented space of independently toggleable knobs. This is that space,
recorded once so future decisions (a fourth profile, a change to an
existing one) can be checked against it instead of re-litigated.

Three real Windows guest profiles exist as of this writing:
`win11-sandbox` (`sandbox/windows`), `win11-ghosts` (`sandbox/ghosts`),
and `win11-cape` (`sandbox/cape`). A fourth, `sandbox/windows_kimi`, is
an early prototype checked into the repo (the living-persona daemon's own
header credits it as the origin of that feature) but is not a deployed,
tracked profile with its own `IMPLEMENTATION_PLAN.md` — it is not
included in the matrix below, but its `provision/60-living-persona.ps1`
is the real ancestor of `sandbox/windows/packer/scripts/07-living-persona.ps1`.

## The axes

Seven axes, taken directly from #467's own list:

1. **Network exposure** — real WAN / FakeNet-served / fully isolated
2. **Persona / NPC activity** — GHOSTS NPC / legacy persona daemon (#290) / none
3. **Simulated input** — fake mouse/keyboard movement on or off
4. **Simulated background traffic** — fake network noise on or off
5. **Filesystem bait** — fake mounted shares/decoy files on or off
6. **Kernel-level attack surface** — vulnerable/attackable signed drivers (LOLDrivers-class) present or not
7. **Userspace attack surface** — vulnerable/unpatched software (local-privesc-only, no kernel component) present or not

## The one hard rule

From #467's own recorded decision, reasoned through and not since
revisited: **kernel-level attack surface (axis 6) is gated strictly to
network exposure = isolated. No exception path, regardless of any other
axis's value.**

A BYOVD driver exploit that reaches kernel is not scoped to the guest
OS — kernel code execution can reach host-visible resources (device
passthrough surfaces, any host-side channel the VM touches, and in the
worst case a hypervisor escape chain layered on top). A fully isolated
guest makes a successful kernel exploit a contained, fully observed
technique. A guest with real WAN egress turns the exact same exploit into
a genuine route to actual outbound C2 or lateral movement. No amount of
per-VM knob granularity on the *other* axes changes that asymmetry — it
is inherent to what "real WAN" means once kernel code execution is on
the table.

Axes 2–5 and 7 (persona, simulated input, traffic noise, filesystem
bait, userspace-only attack surface) do **not** carry this restriction —
their blast radius stays inside the guest's own user-mode boundary,
the same boundary a WAN-connected guest's own real activity already
operates inside. They are safe to mix freely regardless of network
exposure. Axis 6 is the one axis that is a hard either/or, not a peer
knob.

If axis 6 = present (i.e. axis 1 must = isolated), the guest may still
carry admin-gated LOLDrivers **only** behind an explicit, individually-
authorized opt-in each time it's used — see `win11-ghosts`'s own row
below for what that looks like in practice, and why it exists even
though axis 1 for that profile is *not* isolated (the gate exists
precisely because #467's decision-in-practice ended up "yes, but only
behind a loud, explicit, non-default gate" rather than a plain
axis-1-based block — the code enforces the *authorization* requirement,
not a hard technical impossibility, because policy alone was judged
insufficient without the loud warning).

## Current state, per profile

| Axis | `win11-sandbox` | `win11-ghosts` | `win11-cape` |
|---|---|---|---|
| 1. Network exposure | Isolated (no `<forward>`; FakeNet-served for intercepted outbound) | **Real WAN** (`<forward>` present, deliberate — #325/#331) | Isolated (no `<forward>`, same posture as the Linux runner) |
| 2. Persona / NPC | Legacy persona daemon (`07-living-persona.ps1`, #290) | GHOSTS NPC (real `Ghosts.Api` client, `sandbox/ghosts/Dockerfile.client-win`) | **None** — documented known gap (`autounattend.xml`'s own header: "the decoy persona ... KNOWN GAP, not fixed here") |
| 3. Simulated input | Yes — cubic-Bezier mouse movement, Gaussian jitter, periodic typing (`07-living-persona.ps1`) | N/A — GHOSTS' own real activity substitutes | No |
| 4. Simulated background traffic | Yes (`08-traffic-noise.ps1`) | N/A — real traffic from real browsing | No |
| 5. Filesystem bait | Yes (`05-decoy-content.ps1`) | No | No |
| 6. Kernel-level attack surface | Yes, unconditional (`10-loldrivers.ps1`, always provisioned) | Available, **admin-gated opt-in** (`provision-loldrivers.sh`, `--i-accept-the-real-wan-risk`, PR #873) — never yet run against a live `win11-ghosts.qcow2` | No — not yet decided either way |
| 7. Userspace attack surface | **Not implemented** | **Not implemented** | **Not implemented** |

Two things stand out from the matrix itself, not from any single
profile's own docs:

- **Axis 7 (userspace-only vulnerable software) is a real gap across
  every profile**, not just an oversight on one. #467's own text
  specifically asked whether this axis could be offered safely on a
  WAN-connected guest as a middle ground short of kernel-level bait —
  per the hard rule above, yes, it can (no kernel component means no
  hypervisor-escape-adjacent blast radius) — but nothing anywhere in
  this repo implements it yet.
- **`win11-cape` predates this model** (built after #467 was filed) and
  has never had an explicit attack-surface decision made for it at all —
  axes 6 and 7 are both simply absent, not deliberately excluded the way
  `win11-ghosts`'s axes 3–5 are (N/A because GHOSTS' own real activity
  already provides equivalent realism, a documented reason) or the way
  `win11-cape`'s own axes 2–4 are (explicitly excluded per
  `win11-cape.pkr.hcl`'s own header, since CAPE's debugger-class-evasion
  focus doesn't need full persona realism the same way AV/behavioral
  evasion checks do).

## Follow-up work

This document is the model; it does not itself change any golden
image. Four concrete, scoped follow-ups came out of writing it, each
filed as its own issue rather than bundled here (every one of them
needs an actual golden-image rebuild to verify, the same rebuild-gated
posture #368/#787's own comments already hold every other
guest-behavior change to — not something to casually re-trigger inside
a documentation change):

- [#901](https://github.com/Xore/APIARY/issues/901) — Validate the
  admin-gated LOLDrivers toggle end-to-end against a real
  `win11-ghosts.qcow2` cycle (with-set vs. without, gate-on vs.
  gate-off) — the code (#873) already exists and is untested against a
  real image; this is verification work, not new engineering.
- [#902](https://github.com/Xore/APIARY/issues/902) — Design and add a
  userspace-only vulnerable-software attack-surface option (axis 7) —
  genuinely new engineering: which software, which CVEs, how it's
  provisioned, and confirming it stays local-privesc-only with no
  kernel or remote-listener component before it ships anywhere.
- [#903](https://github.com/Xore/APIARY/issues/903) — Decide,
  explicitly, whether `win11-cape` should carry any attack surface
  (axis 6 and/or 7) at all, given its debugger-class-evasion focus
  differs from `win11-analysis`'s AV/behavioral-evasion one — and
  implement whichever way that decision goes.
- [#904](https://github.com/Xore/APIARY/issues/904) — Give
  `win11-cape` its own persona identity distinct from
  `win11-analysis`'s (not full persona/input/traffic-noise parity,
  which stays deliberately excluded — just fixing the fingerprint-reuse
  gap `autounattend.xml`'s own header already flags, promoted here to a
  tracked issue instead of a comment-only note).
