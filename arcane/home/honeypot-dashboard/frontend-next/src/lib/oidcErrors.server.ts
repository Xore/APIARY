// Failure routing for the /auth/* OIDC endpoints (#1942).
//
// Before this module, a provider-side `error=invalid_request` on
// /auth/callback became a 53-byte plaintext 502. An authorization-protocol error is a normal part of OIDC
// (RFC 6749 §4.1.2.1 sends failures as query parameters on the callback,
// not as HTTP errors) and must render as a page.
//
// The login-start side had the sibling problem: any beginLogin throw
// (discovery unreachable, redis write rejected) escaped the handler and
// came back as a framework-generated bare 500 with nothing logged by us.
// Both endpoints log failures server-side and redirect to the bundled
// pre-auth app route, which requires application assets to load.

/** A provider error per RFC 6749 §4.1.2.1: the IdP redirects back with
 *  error=/error_description= in the query instead of a code=. */
export function providerErrorFrom(url: URL): { error: string; description: string } | null {
  const error = url.searchParams.get('error')
  if (!error) return null
  // error_description is optional; error_code/realm params appear from
  // some gateways. Description falls back to the raw code either way.
  const description = url.searchParams.get('error_description') ?? error
  return { error, description }
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export function authErrorPage(opts: {
  status: number
  heading: string
  detail: string
  retryHref?: string
}): Response {
  const kind = opts.status === 503 ? 'unavailable'
    : opts.status === 502 ? 'exchange'
    : opts.heading === 'Login attempt expired' ? 'expired' : 'refused'
  return new Response(null, { status: 303, headers: { location: `/auth/error?kind=${kind}` } })
}
