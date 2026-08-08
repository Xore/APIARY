# Keycloak hard-cutover contract

Status: accepted Phase 0 decision record for #976 and epic #986.

## Fixed architecture

Keycloak and PostgreSQL run in the Dockge-managed `honeypot-keycloak` stack on
the homeserver. Public TLS terminates at VPS Traefik, which reaches Keycloak and
protected applications only over WireGuard bridges. `auth.example.invalid` is the
OIDC issuer. `keycloak-admin.example.invalid` is the administrator console and has
an additional file-backed bcrypt BasicAuth gate at Traefik.

The dashboard is a confidential native OIDC client. Every application without
acceptable native OIDC gets its own isolated `oauth2-proxy` instance and its
own confidential Keycloak client. Proxies do not share client secrets, cookie
secrets, cookies, or upstream networks. A proxy may inject identity headers
only when its upstream has no path reachable from the browser, another stack,
or the honeynet that bypasses that proxy.

Humans are created by administrators only. Every human must configure TOTP.
Automation uses narrowly scoped service accounts and is not treated as a human
MFA exception. Recovery is an administrator-driven credential reset because the
pinned Keycloak runtime does not provide a recovery-code required-action factory.

## Route and consumer matrix

| Route | Consumer | Integration | Keycloak client | Required role | Trust boundary and special traffic |
|---|---|---|---|---|---|
| `dashboard.*`, `honeypot.*` | APIARY dashboard, APIs, SSE, exports, embedded settings | Native authorization-code OIDC with PKCE | `apiary-dashboard` | `user`; mutations require `admin` | Dashboard validates tokens and owns its session. No proxy identity headers. PDF routes use the same dashboard session. |
| `kibana.*` | Kibana | Isolated gateway | `kibana` | `user` | Gateway is the only network peer allowed to reach Kibana; preserve WebSockets and base paths. |
| `evebox.*` | EveBox | Isolated gateway | `evebox` | `user` | Gateway is the only upstream path; preserve API, stream, and download behavior. |
| `arkime.*` | Arkime | Isolated gateway | `arkime` | `user` | Arkime may accept injected identity only on the gateway-only network; remove direct/header-auth access. |
| `tanner.*` | TANNER UI | Isolated gateway | `tanner` | `user` | Gateway-only upstream network; preserve API and static assets. |
| `rev.*` | RevDeck/Ghidra UI | Isolated gateway | `revdeck` | `user` | Gateway-only upstream network; preserve long responses, downloads, and streams. |
| `traefik.*` | Traefik read-only dashboard | Isolated gateway | `traefik-dashboard` | `admin` | Gateway fronts `api@internal`; callback is excluded from recursive auth. |
| `dockge.*` | Dockge administrator UI | Isolated gateway | `dockge` | `admin` | Gateway-only route; WebSockets must pass. Dockge's own authorization remains enabled when supported. |
| `auth.example.invalid` | OIDC login, discovery, JWKS, account console | Direct Keycloak | n/a | public protocol endpoints; authenticated account actions | Rate-limited edge route to the Keycloak WireGuard bridge. |
| `keycloak-admin.example.invalid` | Keycloak administration | Direct Keycloak plus Traefik BasicAuth | n/a | Keycloak administrator + MFA | Entire hostname is protected by the outer BasicAuth middleware before Keycloak. |
| decoy/static/API/status/file/blog hosts currently lacking `forward-auth` | Public honeypot or explicitly application-owned auth | Public / unchanged | none | none | Never attach operator SSO merely because the hostname exists. Public collection must remain independent of IdP availability. |

The deployment validator must fail when a protected router has neither native
OIDC ownership nor its named gateway. A redirect alone is not evidence: each
row must retain an authorized real-page/API check and an unauthorized denial
check before cutover.

## Claims and sessions

- Immutable identity and audit key: Keycloak `sub`.
- Display identity: `preferred_username`, with `name` as optional display text.
- Dashboard roles: client roles in `resource_access.apiary-dashboard.roles`;
  `admin` implies the normal `user` capabilities.
- Gateway roles: the matching client's role claim only. A role for one client
  never authorizes another client.
- Authorization code flow only, exact redirect URIs, S256 PKCE, state, and
  nonce. Implicit and resource-owner-password grants stay disabled.
- Sessions fail closed on invalid signature, issuer, audience/authorized party,
  expiry, not-before, missing subject, missing required role, refresh failure,
  or unavailable required identity state.
- Logout deletes local/gateway state and uses Keycloak RP-initiated logout with
  an allowlisted post-logout redirect.

## Hard-cutover removal list

The production cutover removes all of the following in one reviewed change:

- the `auth-portal` router/service and VPS dependency on the old runtime;
- the `forward-auth` and `strip-auth-identity` middleware chain;
- `/_auth/verify`, `/_auth/introspect`, and the `xore_sso` cookie;
- `AUTH_INTROSPECTION_URL`, `AUTH_INTROSPECTION_TOKEN`, `AUTH_TARGET_HOST`,
  `AUTH_SESSION_COOKIE_NAME`, and trusted `X-Auth-*` behavior;
- Arkime's old generic header-auth path and every direct protected-upstream
  route that bypasses its gateway;
- old account/settings iframe URLs and legacy recovery links.

There is no legacy user import, dual-write, fallback runtime, or rollback to
the old identity system. Recovery restores the validated Keycloak/APIARY
release and its PostgreSQL backup.

## Validation gates

For every protected row, test anonymous, authorized, wrong-role, expired,
revoked/disabled, wrong-issuer, wrong-audience, direct-backend, and forged-header
access. Also exercise its deep links, static assets, API calls, WebSockets/SSE,
downloads, refresh, and logout where applicable. Keycloak, PostgreSQL,
discovery/JWKS, gateway, DNS, TLS, and client-secret failures must deny access
without affecting public honeypot collection.
