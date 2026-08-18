// TTY replay — a linkable page for one Cowrie recording's decoded
// terminal transcript (the recordings inspector shows the same data
// inline; this page is the shareable deep link).
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'

type Replay = {
  shasum: string
  size_bytes: number
  imported_at: string
  frames: number
  duration_seconds: number
  transcript: string
}

const fetchReplay = createServerFn({ method: 'GET' })
  .inputValidator((input: { shasum: string }) => input)
  .handler(async ({ data }): Promise<Replay | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Replay>(`/api/v1/recordings/${encodeURIComponent(data.shasum)}`)
  })

export const Route = createFileRoute('/tty-replay/$shasum')({
  loader: async ({ params }) => ({ first: fetchReplay({ data: { shasum: params.shasum } }) }),
  component: TtyReplay,
})

function plainTranscript(transcript: string): string {
  // eslint-disable-next-line no-control-regex
  return transcript
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?/g, '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
}

function TtyReplay() {
  const { first } = Route.useLoaderData()
  const { shasum } = Route.useParams()
  const [replay, setReplay] = useState<Replay | null | 'missing'>(null)
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (!cancelled) setReplay(result ?? 'missing')
    })
    return () => {
      cancelled = true
    }
  }, [first])

  if (replay === 'missing') {
    return <InvestigateHeader label="Attacker behavior" title={shasum} subtitle="No recording found for this id." />
  }

  return (
    <>
      <InvestigateHeader
        label="Attacker behavior"
        title={shasum.slice(0, 40)}
        subtitle="Decoded terminal output of one interactive session — everything the attacker's shell printed, in order."
        chips={
          replay ? (
            <>
              <span className="chip">{replay.frames.toLocaleString('en-US')} frames</span>
              <span className="chip">{replay.duration_seconds.toFixed(1)}s terminal time</span>
              <span className="chip">{(replay.size_bytes / 1024).toFixed(1)} KB</span>
              <Link className="chip" to="/recordings">← all recordings</Link>
            </>
          ) : undefined
        }
      />
      <div className="card wide">
        {replay === null ? (
          <>
            <span className="skeleton-line" aria-hidden="true" />
            <span className="skeleton-line" aria-hidden="true" />
          </>
        ) : (
          <div className="card__scroll">
            <pre className="code">{plainTranscript(replay.transcript)}</pre>
          </div>
        )}
      </div>
    </>
  )
}
