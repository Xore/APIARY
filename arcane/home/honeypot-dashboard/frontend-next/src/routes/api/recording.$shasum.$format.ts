// GET /api/recording/{shasum}/{cast|raw} — the two recording downloads the
// Go tier served at /tty/<shasum>.cast and /tty/<shasum>.raw
// (dashboard/tty_replay.go). The port kept only the in-browser viewer, so
// a session could be watched but never exported to asciinema or kept as
// the original cowrie ttylog.
//
// Session-gated but not admin-gated, deliberately: the same recording is
// already fully viewable in-browser at /tty-replay/{shasum} by anyone
// signed in, so requiring more to download the identical bytes would be
// arbitrary rather than protective. Payload downloads are admin-gated
// because those are live malware; this is a terminal transcript.
//
// #1616 posture: its own admission gate rather than sharing
// backendLimiter's budget with cheap JSON calls — a recording can be large
// and is streamed, not buffered.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, limitedStreamProxy } from '../../lib/backpressure.server'
import { getSession, sidFrom } from '../../lib/session.server'

const HASH_RE = /^[0-9a-fA-F]{32,64}$/
const recordingLimiter = new ConcurrencyLimiter(envInt('RECORDING_DOWNLOAD_MAX_CONCURRENT', 8), 4)

// Attacker-controlled terminal bytes either way, so both go out as
// downloads with nosniff — never something the browser should try to
// render or guess a type for.
const CONTENT_TYPE: Record<string, string> = {
  cast: 'application/x-asciicast+json',
  raw: 'application/octet-stream',
}

export const Route = createFileRoute('/api/recording/$shasum/$format')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        if (!HASH_RE.test(params.shasum)) return new Response('invalid recording id', { status: 400 })
        const contentType = CONTENT_TYPE[params.format]
        if (!contentType) return new Response('unknown recording format', { status: 404 })
        return limitedStreamProxy(
          request,
          recordingLimiter,
          `${backendURL()}/api/v1/recordings/${encodeURIComponent(params.shasum)}/${params.format}`,
          (upstream) => ({
            'content-type': contentType,
            'x-content-type-options': 'nosniff',
            'content-disposition': upstream.headers.get('content-disposition') ?? 'attachment',
          }),
          { message: 'recording unavailable' },
        )
      },
    },
  },
})
