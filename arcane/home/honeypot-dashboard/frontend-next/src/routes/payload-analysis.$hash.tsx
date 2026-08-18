// Payload analysis — one captured artifact's full picture: inventory
// metadata, hex preview, static analysis, and YARA verdicts. Static
// analysis never executes the payload.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'

type PayloadDetail = {
  hash: string
  inventory: Record<string, unknown> | null
  analysis: Record<string, unknown> | null
  yara: Record<string, unknown>[]
  size_bytes: number
  hex_preview: string[]
}

const fetchDetail = createServerFn({ method: 'GET' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<PayloadDetail | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<PayloadDetail>(`/api/v1/payloads/${encodeURIComponent(data.hash)}`)
  })

export const Route = createFileRoute('/payload-analysis/$hash')({
  loader: async ({ params }) => ({ first: fetchDetail({ data: { hash: params.hash } }) }),
  component: PayloadAnalysis,
})

function PayloadAnalysis() {
  const { first } = Route.useLoaderData()
  const { hash } = Route.useParams()
  const [detail, setDetail] = useState<PayloadDetail | null | 'missing'>(null)
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (!cancelled) setDetail(result ?? 'missing')
    })
    return () => {
      cancelled = true
    }
  }, [first])

  if (detail === 'missing') {
    return (
      <InvestigateHeader
        label="Evidence"
        title="Payload analysis"
        subtitle={`No analysis found for ${hash.slice(0, 24)}…`}
      />
    )
  }

  const inventory = detail && detail.inventory ? detail.inventory : null
  const kind = inventory && typeof inventory.Kind === 'string' ? inventory.Kind : ''

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title="Payload analysis"
        subtitle="Static analysis of one captured artifact — metadata, bytes, strings and rule matches. The payload is never executed here."
        chips={
          detail ? (
            <>
              <span className="chip"><code>{detail.hash.slice(0, 32)}</code></span>
              {kind ? <span className="badge badge--muted">{kind}</span> : null}
              <span className="chip">{(detail.size_bytes / 1024).toFixed(1)} KB</span>
              <a
                className="chip"
                href={`https://www.virustotal.com/gui/search/${encodeURIComponent(detail.hash)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                VirusTotal →
              </a>
              <Link className="chip" to="/payloads">← all payloads</Link>
            </>
          ) : undefined
        }
      />
      {detail === null ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : (
        <>
          {detail.hex_preview.length > 0 ? (
            <div className="card wide">
              <h2>Hex preview — first 512 bytes</h2>
              <div className="card__scroll">
                <pre className="code">{detail.hex_preview.join('\n')}</pre>
              </div>
            </div>
          ) : null}
          {detail.analysis ? (
            <div className="card wide">
              <h2>Static analysis</h2>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(detail.analysis, null, 2)}</pre>
              </div>
            </div>
          ) : null}
          {detail.yara.length > 0 ? (
            <div className="card wide">
              <h2>YARA verdicts</h2>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(detail.yara, null, 2)}</pre>
              </div>
            </div>
          ) : null}
          {inventory ? (
            <div className="card wide">
              <h2>Inventory record</h2>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(inventory, null, 2)}</pre>
              </div>
            </div>
          ) : null}
        </>
      )}
    </>
  )
}
