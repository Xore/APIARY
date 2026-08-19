# Dashboard modernization-port cutover

Status: first draft runbook for #1628. Unlike
[`KEYCLOAK-CUTOVER.md`](KEYCLOAK-CUTOVER.md), this has not yet been executed
end-to-end — refine it against what actually happens the first time it's
run, the way that doc was.

Tracking issue for everything this cutover depends on:
[#1628](https://github.com/Xore/APIARY/issues/1628). **Do not start the
procedure below until every item in that issue's "Deployment / ops
blockers" section is checked off and the worker-retirement and
feature-parity triage sections have an explicit decision recorded, not
just this doc existing.** A runbook does not substitute for the
prerequisites it assumes.

## Fixed architecture

**Old:** one Go binary (`arcane/home/honeypot-dashboard/dashboard`),
Arcane stack `honeypot-dashboard`, service `dashboard`, published on host
port 19090, fronted by VPS Traefik's `honeypot-dashboard` router
(`vps/traefik/dynamic.yml`). Background loops (`notifyLoop`,
`reportScheduleLoop`) run inside this same binary/service.

**New:** three tiers, all currently gated behind the `next` Compose
profile so nothing binds a host port or receives traffic until cutover:

- `dashboard-next` — TanStack Start frontend/BFF (Arcane stack
  `honeypot-dashboard`, same stack as the old `dashboard` service, for now)
- `backend-service` — Rust request/response tier (split into its own
  Arcane stack `honeypot-dashboard-backend`, #1622)
- `backend-service-mounted`, `backend-worker`, `backend-worker-importer`,
  `backend-worker-enrichment` — Rust workers and the sandbox/Ghidra/
  GitHub-analysis submission tier (Arcane stack `honeypot-dashboard`,
  same as `dashboard-next`)

Cutover is not a config flag. It is: bring the new tiers up standalone,
verify them, repoint Traefik, move the port binding, then retire the old
service and the old standalone worker stacks. There is no beta hostname
today (#1628) — the new stack goes live at the same hostname the old one
serves, which is why the pre-flight verification step below matters more
than it would with a staged rollout.

## Rollback plan

None existed before this doc. The plan: **do not delete the old
`dashboard` service definition or the old standalone worker stacks in the
same change that cuts over.** Comment them out of active duty (stop the
containers, leave the Compose service blocks and their images in place)
for a bake period — one week is a reasonable starting point, adjust based
on what the bake period actually surfaces — before deleting anything.
Instant revert during the bake period is: re-point Traefik's
`honeypot-dashboard` service back to the old `socat-hp-dashboard:8090`
target, `docker compose up -d dashboard` (and the old standalone worker
stacks, if they were stopped), done. No data migration to reverse — both
tiers read the same Elasticsearch indices; the new tiers writing
alongside the old ones during the bake period is the point (see worker
retirement below), not a hazard.

## Cutover procedure

Each step assumes the previous one is verified, not just completed.
Referenced scripts (`docker compose --profile next up -d`,
`deploy-dashboard-rolling.sh`) run from each stack's own directory on the
homeserver, per `docs/CI-CD.md`'s existing deploy conventions.

1. **Confirm #1628's prerequisites are actually met**, not assumed —
   walk its checklist literally, item by item.
2. **Set real values** for every var `.env.example` documents as
   currently defaulting to empty in both `honeypot-dashboard` and
   `honeypot-dashboard-backend` — `DASHBOARD_SERVICE_TOKEN` above all;
   an empty value there means the two tiers trust every request from
   anything else on `honeynet`, not just each other.
3. **Bring the new tiers up without touching Traefik**:
   `docker compose --profile next up -d` in both stacks. All new
   containers start; nothing external routes to them yet — `dashboard`
   is still the only thing Traefik reaches.
4. **Verify from the homeserver directly**, bypassing Traefik entirely
   (`curl` against the container's own port, or a host port temporarily
   published for this check only): `/healthz` returns 200, a handful of
   golden-path pages SSR correctly, `/api/live` streams, login redirects
   to Keycloak and completes. Run `port-tests/{backend-api,frontend-ssr,
   auth-flow}.sh` against this live instance if not already fresh.
5. **Re-point Traefik**: in `vps/traefik/dynamic.yml`, change the
   `honeypot-dashboard` service's `loadBalancer` target from
   `socat-hp-dashboard:8090` to wherever `dashboard-next` is reachable
   from the VPS (a new `socat` forward, same pattern as the existing
   one, or a direct WireGuard-bridge address — decide based on how
   `dashboard-next`'s eventual host placement is resolved; today
   everything is still on one host, so this mirrors the existing
   `socat-hp-dashboard` pattern exactly). Deploy just this change and
   watch Traefik's own health check — it hits `/healthz` on an interval,
   so a bad repoint fails visibly within seconds, not silently.
6. **Move the port binding**: add a `ports:` mapping to `dashboard-next`
   in `compose.yml` (host `19090:8080`, same host port the old service
   held), remove it from `dashboard`, then `docker compose up -d
   dashboard-next` to apply. Leave `dashboard` running underneath (it
   just stops being reachable by port or by Traefik) rather than
   stopping it in this same step — that's the next step, deliberately
   separated so a problem discovered here doesn't also cost the instant
   restart-old-service rollback.
7. **Full live validation**: every golden-path page, every export/
   download path, SSE, settings save, credentials/canarytokens actions,
   report generation, auth (login, TOTP, logout, session expiry),
   mobile nav if #1576's fix has landed by this point. Treat this the
   same way `KEYCLOAK-CUTOVER.md`'s validation gates treat auth — no
   step here is optional because it "probably still works."
8. **Stop, don't yet delete, the old tiers**: `docker compose stop
   dashboard` in `honeypot-dashboard`, plus whichever standalone old
   worker stacks were decided (per #1628) to retire —
   `honeypot-attacker-identity-worker`, `honeypot-agent-intrusion-worker`,
   and the plain `es-results-importer` service inside `honeypot-dashboard`
   itself. This starts the bake period.
9. **After the bake period, with no rollback needed**: delete the
   `dashboard` service block from `compose.yml`, delete the retired
   worker stacks' directories (or their Arcane manifest entries, per
   however that decision was actually recorded), drop every `profiles:
   ["next"]` line from the remaining new-tier services, and remove the
   now-dead `DASHBOARD_SERVE_MODE`/cross-host-split code paths if #1622's
   cross-host split was never actually exercised in production by this
   point — or keep them if it was.

## Hard-cutover removal list (step 9 above, spelled out)

- `dashboard` Compose service and its container, plus `scripts/
  deploy-dashboard-rolling.sh` (superseded — replace with whatever
  redeploy tooling #1628's "no redeploy tooling" item lands)
- `arcane/home/honeypot-attacker-identity-worker/` stack, if its
  Rust replacement in `backend-worker` was confirmed at parity (#1628's
  worker-retirement decision, not automatic)
- `arcane/home/honeypot-agent-intrusion-worker/` stack, same condition
- the plain Python `es-results-importer` Compose service inside
  `honeypot-dashboard/compose.yml` (distinct from its Rust replacement,
  `backend-worker-importer`), same condition
- every `profiles: ["next"]` line across both dashboard stacks
- the old Traefik `socat-hp-dashboard` forward, once nothing references it

**Not removed by this cutover, decided separately:** whether
`DASHBOARD_SERVE_MODE`'s cross-host split (frontend and BFF on different
docker hosts, #1622's stated next step) is ever actually used. This
runbook assumes a single-host cutover throughout; a cross-host cutover
needs its own pass at step 5 in particular.

## What this runbook deliberately does not decide

- Which of the ten feature-parity gaps (#1628) block step 7's validation
  vs. ship as an accepted v1 cut. Decide before step 1, not during step 7.
- Whether `notifyLoop`/`reportScheduleLoop`'s Rust replacements have run
  long enough dual-writing to trust on their own — the old versions
  retire with the rest of `dashboard` in step 8/9, same as everything
  else in that binary. If that's premature for these two specifically,
  split them out before starting the procedure, not after.
