// Captured payloads — dashboard-payload-inventory-v1 cards with the hex
// preview, View-more + skeleton-first.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'

type PayloadRow = {
  Hash: string
  Size: number
  SizeH: string
  MtimeUTC: string
  MIME: string
  Kind: string
  Platform: string
  AnalysisPath: string
  Sources: string[]
  Copies: number
  Preview: string
  PreviewTruncated: boolean
}

type Page = { total: number; rows: PayloadRow[] }

const fetchPayloads = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/payloads?offset=${data.offset}&size=12`)
  })

export const Route = createFileRoute('/payloads')({
  loader: async () => ({ first: fetchPayloads({ data: { offset: 0 } }) }),
  component: Payloads,
})

function SkeletonCards({ count }: { count: number }) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <div key={`skel-${i}`} className="hp-skel-batch" aria-hidden="true">
          <div className="skeleton-line" />
          <div className="skeleton-line" />
          <div className="skeleton-line" />
        </div>
      ))}
    </>
  )
}

function Payloads() {
  const { first } = Route.useLoaderData()
  const [rows, setRows] = useState<PayloadRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  useEffect(() => {
    let cancelled = false
    first.then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
    })
    return () => {
      cancelled = true
    }
  }, [first])
  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchPayloads({ data: { offset: rows.length } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore])
  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title="Captured payloads"
        subtitle="Unified inventory of Dionaea captures, Cowrie uploads/downloads, and retained script artifacts. Files are inert on disk but hostile — handle only in an isolated analysis VM."
        chips={<span className="chip">{total.toLocaleString('en-US')} unique payloads</span>}
      />
      <div className="card wide">
        <div className="hp-src-grid">
          {rows === null ? (
            <SkeletonCards count={8} />
          ) : (
            rows.map((row) => (
              <div key={row.Hash} className="hp-src-card">
                <div className="hp-src-card__head">
                  <span className="hp-src-card__ip" title={row.Hash}>
                    {row.Hash.slice(0, 18)}…
                  </span>
                  <span className="badge badge--muted">{row.Sources.join(' ') || 'unknown'}</span>
                </div>
                <span className="hp-src-card__sensors">
                  <strong>{row.Kind}</strong> · {row.Platform} · {row.MIME} · {row.SizeH} · {row.AnalysisPath}
                </span>
                {row.Preview ? (
                  <pre className="hp-md__preview" aria-label="hex preview">
                    {row.Preview.slice(0, 600)}
                  </pre>
                ) : null}
                <div className="hp-src-card__when">
                  {row.MtimeUTC.replace('T', ' ').slice(0, 19)} · {row.Copies} {row.Copies === 1 ? 'copy' : 'copies'} ·{' '}
                  <a className="lnk" href={`/payload-analysis/${encodeURIComponent(row.Hash)}`}>
                    static analysis →
                  </a>
                </div>
              </div>
            ))
          )}
          {loadingMore ? <SkeletonCards count={4} /> : null}
        </div>
        {rows !== null && rows.length < total ? (
          <div className="hp-lazy-controls" aria-live="polite">
            <span>
              {rows.length.toLocaleString('en-US')} of {total.toLocaleString('en-US')} entries
            </span>
            <button className="btn btn-secondary btn-sm" type="button" onClick={viewMore} disabled={loadingMore}>
              View more
            </button>
          </div>
        ) : null}
      </div>
    </>
  )
}
