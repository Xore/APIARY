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
    configPromise = (async () => {
      const issuer = new URL(process.env.OIDC_ISSUER_URL ?? 'https://auth.example.invalid/realms/apiary')
      return oidc.discovery(issuer, process.env.OIDC_CLIENT_ID ?? 'apiary-dashboard', await clientSecret())
    })()
  }
  return configPromise
}

function externalURL(): string {
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

export async function completeLogin(requestUrl: URL): Promise<{
  sub: string
  username: string
  displayName: string
  role: string
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
  const roles = (claims.realm_access as { roles?: string[] } | undefined)?.roles ?? []
  return {
    sub: String(claims.sub),
    username,
    displayName: String(claims.name ?? username),
    role: roles.includes('admin') ? 'admin' : 'user',
    idToken: tokens.id_token,
    returnTo: pending.returnTo,
  }
}
