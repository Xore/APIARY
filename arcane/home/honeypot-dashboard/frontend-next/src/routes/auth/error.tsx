import { createFileRoute } from '@tanstack/react-router'
import { Button } from '../../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card'

const messages = {
  unavailable: ['Sign-in is temporarily unavailable', 'The identity provider or session store did not answer, so this sign-in could not start. Reload to retry; if it persists the Keycloak tier may be degraded.'],
  refused: ['Sign-in was not completed', 'The identity provider refused this sign-in attempt. This usually means the attempt expired or was already used.'],
  expired: ['Login attempt expired', 'This sign-in took too long or was already completed. Start again to continue.'],
  exchange: ['Sign-in could not be completed', 'The identity provider did not accept the token exchange. If this keeps happening, the Keycloak tier may be degraded.'],
} as const

export const Route = createFileRoute('/auth/error')({
  validateSearch: (search: Record<string, unknown>) => ({ kind: typeof search.kind === 'string' ? search.kind : 'unavailable' }),
  component: AuthError,
})

function AuthError() {
  const { kind } = Route.useSearch()
  const [heading, detail] = messages[kind as keyof typeof messages] ?? messages.unavailable
  return <main className="flex min-h-screen items-center justify-center p-4">
    <Card className="w-full max-w-lg">
      <CardHeader><CardTitle><h1>{heading}</h1></CardTitle><CardDescription>{detail}</CardDescription></CardHeader>
      <CardContent><Button asChild variant="secondary"><a href="/auth/login">Try signing in again</a></Button></CardContent>
    </Card>
  </main>
}
