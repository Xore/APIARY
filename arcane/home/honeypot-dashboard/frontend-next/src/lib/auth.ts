// Session gate used by the root route: resolves the redis-backed session
// on the server for both SSR and client navigations.
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { oidcDisabled } from './oidc.server'
import { getSession, sidFrom } from './session.server'

export type User = {
  sub: string
  username: string
  displayName: string
  role: 'admin' | 'user'
}

export type AccountActions = { manageAccount: string; profile: string; security: string; sessions: string } | null

export const getAccountActions = createServerFn({ method: 'GET' }).handler(async (): Promise<AccountActions> => {
  const { accountConsoleActions } = await import('./oidc.server')
  return accountConsoleActions()
})

export const getSessionUser = createServerFn({ method: 'GET' }).handler(async (): Promise<User | null> => {
  const request = getRequest()
  const session = await getSession(sidFrom(request))
  if (session) {
    return {
      sub: session.sub,
      username: session.username,
      displayName: session.displayName,
      role: session.role,
    }
  }
  if (oidcDisabled()) {
    return { sub: 'dev', username: 'dev', displayName: 'Dev Operator', role: 'admin' }
  }
  return null
})
