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

function redis(): Redis {
  if (!client) {
    client = new Redis(process.env.OIDC_SESSION_REDIS_URL ?? 'redis://127.0.0.1:6379/0', {
      maxRetriesPerRequest: 2,
      enableOfflineQueue: false,
      lazyConnect: false,
    })
    client.on('error', () => {
      /* logged by caller paths; never crash the server on redis flaps */
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
