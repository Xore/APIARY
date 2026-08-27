# DECEPTION EXTENSIONS

This document tracks deception and honeypot projects evaluated for
integration into the APIARY stack — both candidates still under
consideration and the outcome of every decision already made. It was
created before most of the sensors below were deployed, and sat unused in
template form while that deployment happened; the status pass below (per
#2358) backfills the record so the file reflects reality instead of a
perpetual "everything is unevaluated" state. It is also the intake list for
the [deception-sensors epic (#1415)](https://github.com/Xore/APIARY/issues/1415),
which turned much of this file into the #1418–#1424 integration series.

## Tracking format

For each candidate project:

- **Name**: Project name
- **Category**: SSH / Web / ICS / Cloud/API / Multi-protocol / other service-specific decoys
- **Repository**: GitHub URL
- **Rationale**: Why it is interesting for APIARY
- **Integration idea**: How to wire it into Arcane / portbridge / dashboard
- **Status**: Planned / Experimenting / Integrated / Dropped

New entries can be added as bullet records following that shape; shipped
integrations each carry their live `arcane/home/<stack>` location so an
auditor can jump from decision to running code without archaeology.

**Pre-tracker integrations.** Cowrie, Conpot, Dionaea, SNARE/TANNER,
endlessh, multipot, the http/api pair, and the DNP3 sensor all predate this
file's tracking — they are marked integrated with whichever issue records
their (usually later) split or evaluation work rather than a nonexistent
original adoption ticket.

---

## SSH deception and honeypots

| Project | Status | Live location | Decision record |
|---|---|---|---|
| Cowrie | Integrated | `arcane/home/honeypot-cowrie/` | pre-tracker baseline; split out by #258 |
| Endlessh | Integrated | `arcane/home/honeypot-endlessh/` | evaluated with #246 |

Still under consideration:

- Sshesame
- Fakessh (fffaraz/fakessh)
- Honeyshell
- SierraSoftworks/honeypot
- SSHoneyNet
- mn2rb/SSH-Honeypot
- marceloalmeida/ssh-honeypot
- njkleiner/ssh-honeypot
- Phantom-Grid
- ShardLure

## Web / HTTP deception

| Project | Status | Live location | Decision record |
|---|---|---|---|
| Galah | Integrated | `arcane/home/honeypot-galah/` | #1420; routed-path decision in #1511 |
| HellPot | Integrated | `arcane/home/honeypot-hellpot/` | #1419 |
| WordPot | Integrated | `arcane/home/honeypot-wordpot/` | #1421; routed-path decision in #1512 |
| Canarytokens | Integrated | `arcane/home/honeypot-canarytokens/` | #1426; the token-creation design record was retired by #2367 and its live contract is `backend-service/src/canarytokens.rs` |

Still under consideration:

- Krawl
- OWASP Python-Honeypot

## ICS / SCADA / fieldbus deception

| Project | Status | Live location | Decision record |
|---|---|---|---|
| Conpot | Integrated | `arcane/home/honeypot-conpot/` | pre-tracker; six personas split out by #258 |
| Dionaea | Integrated | `arcane/home/honeypot-dionaea/` | pre-tracker malware-capture sensor; split by #258 |
| SNARE/TANNER | Integrated | `arcane/home/honeypot-tanner/` | pre-tracker web-app group; split by #258 |
| DNP3 protocol sensor | Integrated | `arcane/home/honeypot-dnp3/` | pre-tracker; split by #258 |
| dicompot (DICOM) | Integrated | `arcane/home/honeypot-dicompot/` | #238 batch, per-decoy plan #413 |

## Cloud, database and API deception

| Project | Status | Live location | Decision record |
|---|---|---|---|
| Beelzebub | Integrated | `arcane/home/honeypot-beelzebub/` | #1418 (multi-protocol by its own description) via epic #1415 |
| Elasticpot | Integrated | `arcane/home/honeypot-elasticpot/` | #1423 |

Still under consideration:

- Acra

## Multi-protocol platforms

| Project | Status | Decision record |
|---|---|---|
| T-Pot | Dropped | surveyed for adoptable pieces in #233; no wholesale platform adoption; adjacent community-intel-sharing pattern declined in #242 |
| Qeeqbox Honeypots | Planned | |
| HFish | Planned | |

## Service-specific decoys (backfilled from the live inventory)

None of these had rows here despite being deployed — the original five
sections didn't have slots for them. Recorded now so every running sensor
traces back to at least one decision.

| Project | Status | Live location | Decision record |
|---|---|---|---|
| Multipot (multi-service single binary) | Integrated | `arcane/home/honeypot-multipot/` | pre-tracker; split by #258 |
| HTTP + API honeypot pair | Integrated | `arcane/home/honeypot-http/` | pre-tracker; split by #258 |
| RDP decoy (rdphoneypot lineage) | Integrated | `arcane/home/honeypot-rdp-honeypot/` | #238 batch, per-decoy plan #412 |
| Cisco ASA VPN gateway decoy | Integrated | `arcane/home/honeypot-cisco-asa-honeypot/` | #238 batch, CVE context #414 |
| Citrix ADC gateway decoy | Integrated | `arcane/home/honeypot-citrix-honeypot/` | #238 batch, CVE context #414 |
| DNS amplification bait | Integrated | `arcane/home/honeypot-dns-honeypot/` | #238 batch, safety-sensitive design #415 |
| Mailoney (SMTP) | Integrated | `arcane/home/honeypot-mailoney/` | #1422 |
| SentryPeer (VoIP/SIP) | Integrated | `arcane/home/honeypot-sentrypeer/` | #1424 |

---

## Open questions / experiments

Use this section for design spikes, PoCs and experiment results, e.g.:

- How to surface per-sensor deception metadata in the dashboard
- How to unify logging/enrichment for third-party sensors
- How to treat LLM-driven decoys (Galah, Beelzebub, Krawl) in analysis and persona design
