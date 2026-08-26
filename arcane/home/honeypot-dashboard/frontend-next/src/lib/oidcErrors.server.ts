// Rendered error pages for the /auth/* OIDC endpoints (#1942).
//
// Before this module, a provider-side `error=invalid_request` on
// /auth/callback became a 53-byte plaintext 502 — the same body Traefik
// serves when a backend is down, so the user's one signal was "the whole
// dashboard is broken" instead of "your login attempt expired, try
// again". An authorization-protocol error is a normal part of OIDC
// (RFC 6749 §4.1.2.1 sends failures as query parameters on the callback,
// not as HTTP errors) and must render as a page.
//
// The login-start side had the sibling problem: any beginLogin throw
// (discovery unreachable, redis write rejected) escaped the handler and
// came back as a framework-generated bare 500 with nothing logged by us.
// Both endpoints now log the real failure server-side and return one of
// these small self-contained pages. Deliberately inline-styled and
// dependency-free: this renders before the session exists, so it cannot
// assume assets, cookies, or cached CSS are available.

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
  const parts = [
    '<!doctype html>',
    '<html lang="en">',
    '<head><meta charset="utf-8"><title>APIARY — sign-in</title>',
    '<meta name="viewport" content="width=device-width, initial-scale=1"></head>',
    '<body style="font-family: system-ui, sans-serif; background:#16181d; color:#e8e8e8;',
    ' display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0">',
    '<main style="max-width:34rem; padding:2rem">',
    `<h1 style="font-size:1.25rem">${escapeHtml(opts.heading)}</h1>`,
    `<p style="line-height:1.5">${escapeHtml(opts.detail)}</p>`,
    opts.retryHref ? `<p><a href="${escapeHtml(opts.retryHref)}">Try signing in again</a></p>` : '',
    '</main></body></html>',
  ]
  return new Response(parts.join('\n'), {
    status: opts.status,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  })
}
