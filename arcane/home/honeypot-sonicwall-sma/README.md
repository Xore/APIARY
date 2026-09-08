# honeypot-sonicwall-sma

SonicWall SMA1000 Work Place/AMC decoy, #3033. Targets the
CVE-2026-83548 (Work Place SSRF) / CVE-2026-83549 (AMC OS command
injection) chain.

## What it presents

- `GET /` (and anything else outside `/cgi-bin/`) — a pre-auth Work Place
  login page.
- `GET|POST /cgi-bin/...` — classified as `cve_2026_83548_ssrf_probe`, the
  stage-one SSRF-shaped relay request. The decoy then performs one fixed,
  non-attacker-steerable outbound hop toward `api-honeypot`'s cloud-metadata
  surface (`AMC_RELAY_URL`, logged as `cve_2026_83548_ssrf_relay`) and
  responds with a synthetic internal Appliance Management Console page.
- `POST /cgi-bin/amc/rollbackConfirm.action` — the AMC surface's own action
  route from the previous response. Classified as
  `cve_2026_83549_amc_command_injection_probe`, full request body logged.

No Suricata rule ships with this decoy: neither CVE has a public PoC or
vendor IOC giving a literal request shape to match against. See
`docs/research/3011-sonicwall-cve.md` and issue #3033 for the full
reasoning, and the doc comment at the top of `sonicwall-sma-honeypot/main.go`.

## Config

See `.env.example`. `AMC_RELAY_URL` (compose environment, not `.env`) is the
fixed relay target — never read from the incoming request.

## Ports

- `8443` internal (TLS, PROXY-protocol fronted)
- `${HP_BIND:-10.8.0.2}:8543` external bind, portbridge rule
  `tcp:8543:10.8.0.2:8543:pp`
