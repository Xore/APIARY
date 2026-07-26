# Honeypot personas

[`personas.json`](personas.json) is the canonical inventory for the fictional
organizations, sites, and assets exposed by this stack. Each event should carry
`persona_id`, `site_id`, `asset_id`, and `organization`; Filebeat adds those
fields for upstream formats that cannot emit them. The live dashboard exposes
each field as a clickable investigation pivot, and Elasticsearch stores them
under `honeypot.*`.

| Persona | Sensors | Attacker-facing identity |
|---|---|---|
| `nexusai-gpu01` | Cowrie | Ubuntu GPU inference/training node |
| `nexusai-core` | multipot | mail, database, cache, VNC, search and Docker backend estate |
| `nexusai-edge` | HTTP honeypot | public NexusAI documentation/account edge |
| `nexusai-platform` | API honeypot | Kubernetes, registry, metadata and inference gateway |
| `meridian-legacy` | Dionaea | legacy FTP, SMB and SIP integration server |
| `rheinwerk-water-s7-200` | Conpot | water-intake Siemens S7-226 |
| `rheinwerk-water-s7-1200` | Conpot | treatment-hall Siemens S7-1215C |
| `nordchem-s7-1500` | Conpot | chemical-line Siemens S7-1516 |
| `elbegrid-iec104` | Conpot | substation IEC-104 RTU |
| `elbegrid-dnp3` | DNP3 sensor | substation 23 DNP3 outstation/RTU |
| `northfuel-guardian` | Conpot | filling-station tank gauge |
| `stadtwaerme-kamstrup` | Conpot | district-heating MULTICAL meter |
| `meridian-customer-portal` | SNARE/TANNER | fictional customer service portal |

Validate the inventory and Cowrie identity before deployment:

```bash
python3 personas/validate_personas.py
```

Compose runs `persona-apply` before `log-init`, so every normal Dockge/Compose
deployment validates the manifest and event wiring before sensors start. It
also idempotently refreshes Dionaea's mutable FTP, TFTP, UPnP, and printer
persona files in the persistent volume and records the applied manifest hash in
`state/personas/applied.json`. Run it manually with:

```bash
docker compose -f compose.yml run --rm persona-apply
```

Never use a real organization, clone a live website, or seed real credentials
or customer data. Version persona changes here, in the relevant sensor source,
and in the dashboard/Filebeat metadata together.
