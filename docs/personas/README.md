# Honeypot personas

[`personas.json`](../../personas/personas.json) is the canonical inventory for the fictional
organizations, sites, and assets exposed by this stack. Each event should carry
`persona_id`, `site_id`, `asset_id`, and `organization`; Filebeat adds those
fields for upstream formats that cannot emit them. Elasticsearch stores all four
under `honeypot.*`. The live dashboard turns the first three into clickable
investigation pivots in an event's decoy group; `organization` is stored and
exported but is not itself a pivot — the dashboard's `organization` filter is
`source.as.organization_name` (the attacker's network/ASN owner), a different
field entirely.

All 18 entries in `personas.json`:

| Persona | Sensors | Attacker-facing identity |
|---|---|---|
| `nexusai-gpu01` | Cowrie | Ubuntu GPU inference/training node |
| `nexusai-core` | multipot, Mailoney | mail, database, cache, VNC, search and Docker backend estate |
| `nexusai-edge` | HTTP honeypot | public NexusAI documentation/account edge |
| `nexusai-platform` | API honeypot | Kubernetes, registry, metadata and inference gateway |
| `nexusai-directory` | Beelzebub | LDAP, SSH, HTTP and MCP directory/AI-agent estate, plus a secondary admin bastion |
| `nexusai-analytics-legacy` | Elasticpot | standalone legacy analytics Elasticsearch node, deliberately distinct from `nexusai-core`'s own `es-logs-01` |
| `meridian-legacy` | Dionaea | legacy FTP, SMB and SIP integration server |
| `meridian-legacy-web` | Hellpot | decommissioned marketing site that was never formally taken offline |
| `meridian-customer-portal` | SNARE/TANNER | fictional customer service portal |
| `meridian-staff-console` | Galah | internal staff/admin console with request-varying backend tooling |
| `harborline-pbx` | SentryPeer | legacy SIP trunk for an old dispatch-office phone system |
| `rheinwerk-water-s7-200` | Conpot | water-intake Siemens S7-226 |
| `rheinwerk-water-s7-1200` | Conpot | treatment-hall Siemens S7-1215C |
| `nordchem-s7-1500` | Conpot | chemical-line Siemens S7-1516 |
| `elbegrid-iec104` | Conpot | substation IEC-104 RTU |
| `elbegrid-dnp3` | DNP3 sensor | substation 23 DNP3 outstation/RTU |
| `northfuel-guardian` | Conpot | filling-station tank gauge |
| `stadtwaerme-kamstrup` | Conpot | district-heating MULTICAL meter |

Validate the inventory and Cowrie identity before deployment:

```bash
python3 personas/validate_personas.py
```

Compose runs `persona-apply` before `log-init`, so every normal Dockge/Compose
deployment validates the manifest and event wiring before sensors start. It
also idempotently refreshes Dionaea's mutable FTP, TFTP, UPnP, and printer
persona files in the persistent volume and records the applied manifest hash in
`state/personas/applied.json`. `persona-apply` is a service of the
`honeypot-init` stack (`arcane/home/honeypot-init/compose.yml`), not of the
root marker compose file, so run it against that stack's deployed copy:

```bash
cd /var/dockge/stacks/honeypot-init   # or /opt/stacks/honeypot-init
docker compose -f compose.yml run --rm persona-apply
```

Never use a real organization, clone a live website, or seed real credentials
or customer data. Version persona changes here, in the relevant sensor source,
and in the dashboard/Filebeat metadata together.
