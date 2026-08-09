# Dashboard screenshots

Captured live against the production dashboard (real captured attack
telemetry — event counts, alerts, sandbox results — not fixture data), at
three resolutions per [#672](https://github.com/Xore/APIARY/issues/672).
Refreshed after the card-footer/content-width/table-readability layout
fixes ([#790](https://github.com/Xore/APIARY/issues/790),
[#824](https://github.com/Xore/APIARY/pull/824)) landed — this set replaces
the pre-fix screenshots from the original #672 PR.

- **uhq/** — 1920x1080 desktop
- **4k/** — 3840x2160 desktop
- **iphone/** — 393x852 (Playwright's own "iPhone 14 Pro" device preset)

Each folder has the same eight pages: `overview`, `events`, `alerts`, `ips`,
`sandbox`, `ghidra`, `payload-workbench`, `reports`.

Real IPs/hashes/YARA matches visible in these images are attacker-supplied
data captured by the honeypot — the whole point of the tool — not operator
secrets, with one deliberate exception: the `ips` page's top row is redacted
(solid box over the address) in all three resolutions. That row is this
stack's own VPS portbridge address, not an attacker's — the portbridge
relays real internet traffic to the sensors over WireGuard, and something in
that path is attributing relayed traffic to the relay's own address instead
of preserving the original source IP. That's a real data-quality bug (it's
losing genuine attacker attribution for everything routed through the
portbridge), filed separately as
[#827](https://github.com/Xore/APIARY/issues/827) — redacted here because
publishing the stack's own real infrastructure address doesn't belong in a
public screenshot regardless of why it ended up in the table.

## Desktop (UHQ, 1920x1080)

| | |
|---|---|
| ![Overview](uhq/overview.png) Overview | ![Events](uhq/events.png) Events |
| ![Alerts](uhq/alerts.png) Alerts | ![Attack sources](uhq/ips.png) Attack sources |
| ![Sandbox](uhq/sandbox.png) Sandbox | ![Ghidra](uhq/ghidra.png) Ghidra |
| ![Payload workbench](uhq/payload-workbench.png) Payload workbench | ![Reports](uhq/reports.png) Reports |

## Desktop (4K, 3840x2160)

| | |
|---|---|
| ![Overview](4k/overview.png) Overview | ![Events](4k/events.png) Events |
| ![Alerts](4k/alerts.png) Alerts | ![Attack sources](4k/ips.png) Attack sources |
| ![Sandbox](4k/sandbox.png) Sandbox | ![Ghidra](4k/ghidra.png) Ghidra |
| ![Payload workbench](4k/payload-workbench.png) Payload workbench | ![Reports](4k/reports.png) Reports |

## Mobile (iPhone 14 Pro, 393x852)

| | | |
|---|---|---|
| ![Overview](iphone/overview.png) | ![Events](iphone/events.png) | ![Alerts](iphone/alerts.png) |
| Overview | Events | Alerts |
| ![Attack sources](iphone/ips.png) | ![Sandbox](iphone/sandbox.png) | ![Ghidra](iphone/ghidra.png) |
| Attack sources | Sandbox | Ghidra |
| ![Payload workbench](iphone/payload-workbench.png) | ![Reports](iphone/reports.png) | |
| Payload workbench | Reports | |

## Regenerating

Same layout-check viewports the Playwright acceptance matrix uses
(`dashboard/frontend/e2e/dashboard.spec.ts`), captured against a real
authenticated session rather than the isolated/mocked identity the e2e suite
uses. Needs a valid `__Host-apiary_session` cookie (`dashboard/oidc_auth.go`'s
`oidcSessionCookie`) for an account with at least viewer access — the
dashboard's page routes don't themselves require one (the dashboard uses
native OIDC directly, not the Traefik ForwardAuth + oauth2-proxy gateway
every other investigation UI sits behind, #1026; the dashboard's own
listener is WireGuard-only, see #822), but a real session is what makes the
account menu show a logged-in identity instead of the signed-out state.

If capturing right after a dashboard redeploy, wait for real data before
shooting: the container reports `healthy` well before its ES-derived state
(sensor list, event counts) has actually warmed up, so a capture taken
immediately after deploy can show an all-zero, `0001-01-01`-timestamped
dashboard that looks broken but isn't — filed as
[#828](https://github.com/Xore/APIARY/issues/828).
