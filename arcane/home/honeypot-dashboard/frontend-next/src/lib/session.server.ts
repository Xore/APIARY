// BFF session store: opaque sid cookie → session document in redis (the
// same oidc-sessions valkey the Go tier uses, different key namespace).
// Redis-backed by design so N BFF instances on any docker host share
// sessions (#1610's horizontal requirement) — no in-process session state.
import Redis from 'ioredis'
import { randomBytes } from 'node:crypto'

export type Session = {
  sub: string
  username: string
  displayName: string
  role: 'admin' | 'user'
  idToken?: string
  createdAt: number
}

const SESSION_TTL_SECONDS = 12 * 60 * 60
const PREFIX = 'bff:session:'
export const SESSION_COOKIE = '__Host-apiary_bff'

let client: Redis | null = null
let lastRedisError = 0

function redis(): Redis {
  if (!client) {
    client = new Redis(process.env.OIDC_SESSION_REDIS_URL ?? 'redis://127.0.0.1:6379/0', {
      maxRetriesPerRequest: 2,
      // The offline queue stays ON here, unlike the cache client in
      // backend.server.ts, and the difference is deliberate.
      //
      // With it off, any command issued while the socket is not yet `ready`
      // throws "Stream isn't writeable and enableOfflineQueue options is
      // false" instead of waiting. For a cache that is correct: fail fast,
      // degrade to the in-process layer, nobody notices. For the session
      // store it is not optional, so the same throw becomes an unhandled 500
      // on /auth/login and the dashboard is simply unreachable.
      //
      // Seen live after a redeploy: every login returned 500 while redis was
      // healthy the whole time -- reachable from the container, answering
      // PING, no password, correct DNS. Restarting the dashboard and redis
      // both changed nothing, because the problem was never the connection.
      //
      // Queuing is bounded, not unbounded: maxRetriesPerRequest above and
      // connectTimeout below mean a genuinely dead redis still fails, it
      // just fails after trying rather than before.
      enableOfflineQueue: true,
      connectTimeout: 5000,
      lazyConnect: false,
    })
    client.on('error', (error: Error) => {
      // Never crash the server on a redis flap -- but do not swallow it
      // silently either. The previous empty handler is why the failure above
      // was invisible: the only symptom anywhere was a 500 with a stack that
      // pointed at beginLogin, and nothing said what redis was doing.
      // Throttled so a reconnect loop cannot flood the log.
      const now = Date.now()
      if (now - lastRedisError > 30_000) {
        lastRedisError = now
        console.warn('[session] redis error:', error.message)
      }
    })
  }
  return client
}

export async function createSession(data: Omit<Session, 'createdAt'>): Promise<string> {
  const sid = randomBytes(32).toString('base64url')
  const session: Session = { ...data, createdAt: Date.now() }
  await redis().set(PREFIX + sid, JSON.stringify(session), 'EX', SESSION_TTL_SECONDS)
  return sid
}

export async function getSession(sid: string | undefined): Promise<Session | null> {
  if (!sid || sid.length > 128) return null
  try {
    const raw = await redis().get(PREFIX + sid)
    return raw ? (JSON.parse(raw) as Session) : null
  } catch {
    return null
  }
}

export async function destroySession(sid: string | undefined): Promise<void> {
  if (!sid) return
  try {
    await redis().del(PREFIX + sid)
  } catch {
    /* best effort */
  }
}

export function sessionCookie(sid: string): string {
  return `${SESSION_COOKIE}=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
}

export function sidFrom(request: Request): string | undefined {
  const header = request.headers.get('cookie') ?? ''
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=')
    if (name === SESSION_COOKIE) return rest.join('=')
  }
  return undefined
}
