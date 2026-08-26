// The BFF half of #2183's boot gate. An unset/empty SERVICE_TOKEN used to
// silently switch off this tier's inbound x-service-token check
// (proxyToRust) exactly the way it silently switched off backend-service's
// require_service_token — two seams, one missing variable, zero signals.
// This module holds the one decision both halves share: a deployment may
// only run unauthenticated when it says so out loud, via
// APIARY_ALLOW_UNAUTH_DEV=1, and anything else refuses to boot with the
// same [E-SERVICE-TOKEN] marker the Rust side emits (backend-service/src/
// main.rs's resolve_service_token), so a grep of any log finds either
// flavor. Keep that message's wording in sync with the Rust copy — they are
// two renderings of one contract, not two contracts.

/** Unset/empty SERVICE_TOKEN + this set to exactly "1" is the only way an
 * unauthenticated instance may boot (#2183). Exactly "1" on purpose: no
 * truthiness zoo where `=0` or `=false` reads as consent. */
export const DEV_UNAUTH_OVERRIDE_ENV = 'APIARY_ALLOW_UNAUTH_DEV'

/** The refusal code both tiers stamp on their boot-failure lines; cutover
 * prose points operators at this exact string. */
export const SERVICE_TOKEN_GATE_CODE = 'E-SERVICE-TOKEN'

function tokenIsSet(token: string | undefined): boolean {
  return typeof token === 'string' && token.length > 0
}

/** Why the tier may or may not boot, as far as env alone decides:
 * - `{ kind: 'token' }` — a real SERVICE_TOKEN; enforcement stays on.
 * - `{ kind: 'dev-override' }` — no token, APIARY_ALLOW_UNAUTH_DEV=1.
 * - `{ kind: 'refuse', message }` — otherwise, message carries the remedy. */
export function serviceTokenPolicy(env: {
  SERVICE_TOKEN?: string
} & Record<string, string | undefined> = process.env):
  | { kind: 'token' }
  | { kind: 'dev-override' }
  | { kind: 'refuse'; message: string } {
  if (tokenIsSet(env.SERVICE_TOKEN)) return { kind: 'token' }
  if (env[DEV_UNAUTH_OVERRIDE_ENV] === '1') return { kind: 'dev-override' }
  return {
    kind: 'refuse',
    message: `[${SERVICE_TOKEN_GATE_CODE}] refusing to start: SERVICE_TOKEN is unset or empty, which would leave the /bff/* proxy tier (and, unchecked here, every SSR data path) open to unauthenticated requests. Set SERVICE_TOKEN to the shared secret the Rust tier also carries — see docs/DASHBOARD-CUTOVER.md step 2 — or, for local development only, set ${DEV_UNAUTH_OVERRIDE_ENV}=1 explicitly (#2183).`,
  }
}

/** Throws the E-SERVICE-TOKEN refusal text when env does not sanction an
 * unauthenticated boot; silent otherwise. Called once from
 * backend.server.ts's module scope: the route tree statically imports every
 * route module into the server bundle, so first evaluation happens while
 * Nitro boots — the process dies before listening rather than serving one
 * open request and hoping someone reads a warning. */
export function assertServiceTokenPolicy(
  env: Parameters<typeof serviceTokenPolicy>[0] = process.env,
): void {
  const policy = serviceTokenPolicy(env)
  if (policy.kind === 'refuse') throw new Error(policy.message)
}
