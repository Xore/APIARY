// Keycloak OIDC for the BFF (the port's auth owner, per Xore): same
// client id and redirect paths the Go tier registered (/auth/login,
// /auth/callback), so cutover needs no realm changes. PKCE + state in a
// short-lived redis entry; sessions in session.server.ts.
//
// Dev/test: OIDC_DISABLED=1 short-circuits the whole flow with a fixture
// identity, mirroring the Go dev harness' stubbed session store.
import * as oidc from 'openid-client'
import Redis from 'ioredis'
import { randomBytes } from 'node:crypto'

const PENDING_TTL_SECONDS = 600
const PENDING_PREFIX = 'bff:oidc:pending:'

let redisClient: Redis | null = null
function redis(): Redis {
  if (!redisClient) {
    redisClient = new Redis(process.env.OIDC_SESSION_REDIS_URL ?? 'redis://127.0.0.1:6379/0', {
      maxRetriesPerRequest: 2,
      enableOfflineQueue: false,
    })
    redisClient.on('error', () => {})
  }
  return redisClient
}

let configPromise: Promise<oidc.Configuration> | null = null

export function oidcDisabled(): boolean {
  return process.env.OIDC_DISABLED === '1'
}

// Keycloak's account console lives at <issuer>/account/ by convention (the
// issuer is already .../realms/<realm>), so these links need no extra env
// var beyond OIDC_ISSUER_URL. Restores settings_modal.html:58-84's "Account
// & security" card (dashboard/authorization.go's keycloakAccountActions),
// dropped in the frontend-next port -- Keycloak account-console v2's own
// hash routes for the "signing in" (passkeys + 2FA) and device-activity
// panes.
export function accountConsoleActions(): { manageAccount: string; profile: string; security: string; sessions: string } | null {
  if (oidcDisabled()) return null
  const issuer = (process.env.OIDC_ISSUER_URL ?? 'https://auth.example.invalid/realms/apiary').replace(/\/$/, '')
  const base = `${issuer}/account/`
  return {
    manageAccount: base,
    profile: `${base}#/personal-info`,
    security: `${base}#/security/signingin`,
    sessions: `${base}#/security/device-activity`,
  }
}

async function clientSecret(): Promise<string> {
  const file = process.env.OIDC_CLIENT_SECRET_FILE
  if (file) {
    const { readFile } = await import('node:fs/promises')
    return (await readFile(file, 'utf8')).trim()
  }
  return process.env.OIDC_CLIENT_SECRET ?? ''
}

export async function oidcConfig(): Promise<oidc.Configuration> {
  if (!configPromise) {
    // A failed attempt must not stick: `configPromise` held a permanently-
    // rejected promise here before this fix, because `if (!configPromise)`
    // is false for ANY assigned promise, resolved or rejected -- one
    // transient failure (confirmed live: a real EACCES on the OIDC client
    // secret file, since fixed separately, but Keycloak/Redis being
    // briefly unreachable at startup would hit this identically) poisoned
    // every login attempt for the rest of the process's life, since
    // nothing ever reset the cache back to null. Clearing it on rejection
    // lets the next request retry fresh instead of replaying the same
    // cached error forever.
    configPromise = (async () => {
      const issuer = new URL(process.env.OIDC_ISSUER_URL ?? 'https://auth.example.invalid/realms/apiary')
      return oidc.discovery(issuer, process.env.OIDC_CLIENT_ID ?? 'apiary-dashboard', await clientSecret())
    })().catch((err) => {
      configPromise = null
      throw err
    })
  }
  return configPromise
}

export function externalURL(): string {
  return (process.env.OIDC_EXTERNAL_URL ?? 'http://127.0.0.1:4173').replace(/\/$/, '')
}

export async function beginLogin(returnTo: string): Promise<{ redirect: string }> {
  const config = await oidcConfig()
  const verifier = oidc.randomPKCECodeVerifier()
  const challenge = await oidc.calculatePKCECodeChallenge(verifier)
  const state = randomBytes(24).toString('base64url')
  const safeReturn = returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : '/'
  await redis().set(
    PENDING_PREFIX + state,
    JSON.stringify({ verifier, returnTo: safeReturn }),
    'EX',
    PENDING_TTL_SECONDS,
  )
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: `${externalURL()}/auth/callback`,
    scope: 'openid profile email roles',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  })
  return { redirect: url.href }
}

function dashboardClientId(): string {
  return process.env.OIDC_CLIENT_ID ?? 'apiary-dashboard'
}

export async function completeLogin(requestUrl: URL): Promise<{
  sub: string
  username: string
  displayName: string
  role: 'admin' | 'user'
  idToken?: string
  returnTo: string
} | null> {
  const state = requestUrl.searchParams.get('state') ?? ''
  const raw = await redis().getdel(PENDING_PREFIX + state)
  if (!raw) return null
  const pending = JSON.parse(raw) as { verifier: string; returnTo: string }
  const config = await oidcConfig()
  // The BFF may sit behind Traefik: rebuild the callback URL on the
  // registered external origin regardless of what the proxy hop used.
  const callbackUrl = new URL(`${externalURL()}/auth/callback`)
  requestUrl.searchParams.forEach((value, key) => callbackUrl.searchParams.set(key, value))
  const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
    pkceCodeVerifier: pending.verifier,
    expectedState: state,
  })
  const claims = tokens.claims()
  if (!claims?.sub) return null
  const username = String(claims.preferred_username ?? claims.sub)
  // Dashboard roles are the apiary-dashboard client's own roles, not realm
  // roles (docs/KEYCLOAK-CUTOVER.md "Claims and sessions") — they live under
  // resource_access.<client id>.roles, not realm_access.roles.
  const resourceAccess = claims.resource_access as
    | Record<string, { roles?: string[] } | undefined>
    | undefined
  const roles = resourceAccess?.[dashboardClientId()]?.roles ?? []
  return {
    sub: String(claims.sub),
    username,
    displayName: String(claims.name ?? username),
    role: roles.includes('admin') ? 'admin' : 'user',
    idToken: tokens.id_token,
    returnTo: pending.returnTo,
  }
}
