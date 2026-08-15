# DECEPTION EXTENSIONS

This document tracks additional deception and honeypot projects evaluated for integration into the APIARY stack.

## Scope

- SSH deception and honeypots
- Web / HTTP application deception
- ICS / SCADA / fieldbus honeypots
- Cloud, database and API deception
- Multi‑protocol / framework‑style platforms

## Tracking format

For each candidate project:

- **Name**: Project name
- **Category**: SSH / Web / ICS / Cloud/API / Multi‑protocol
- **Repository**: GitHub URL
- **Rationale**: Why it is interesting for APIARY
- **Integration idea**: How to wire it into Arcane / portbridge / dashboard
- **Status**: Planned / Experimenting / Integrated / Dropped

You can maintain the list as a markdown table per category or as bullet points.

---

## SSH deception and honeypots

> Add notes and decisions for SSH‑focused projects here.

Examples to evaluate:
- Cowrie (baseline, already integrated)
- Sshesame
- Fakessh (fffaraz, hugefiver)
- Honeyshell
- SierraSoftworks/honeypot
- SSHoneyNet
- mn2rb/SSH-Honeypot
- marceloalmeida/ssh-honeypot
- njkleiner/ssh-honeypot
- Phantom‑Grid
- ShardLure

## Web / HTTP deception

> Add notes and decisions for web / HTTP deception projects here.

Examples to evaluate:
- HellPot
- Galah
- Krawl
- OWASP Python-Honeypot

## ICS / SCADA deception

> Add notes and decisions for ICS / SCADA / DNP3 projects here.

Examples to evaluate:
- Conpot
- Dionaea
- SNARE/TANNER

## Cloud, database and API deception

> Add notes and decisions for cloud / DB / API deception projects here.

Examples to evaluate:
- Acra
- Beelzebub

## Multi‑protocol platforms

> Add notes and decisions for general multi‑protocol platforms here.

Examples to evaluate:
- T‑Pot
- Qeeqbox Honeypots
- HFish

---

## Open questions / experiments

Use this section for design spikes, PoCs and experiment results, e.g.:

- How to surface per‑sensor deception metadata in the dashboard
- How to unify logging/enrichment for third‑party sensors
- How to treat LLM‑driven decoys (Galah, Beelzebub, Krawl) in analysis and persona design
