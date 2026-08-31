// .index leaf for the same reason as cape.index.tsx (#2127): a
// component-ful github-analysis.tsx swallowed github-analysis.$sha whole.
// GitHub analysis — VirusTotal-style multi-engine results for payloads
// published to the analysis repo (github-analysis-v1). Empty until the
// publisher is armed; submissions land with #1612.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, sha256Of, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'
import { ShieldIcon } from '../components/CardIcons'
import { pathString } from '../lib/json'

const fetchPage = createServerFn({ method: 'GET' })
  .validator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/github-analysis?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  // Card layout promotes this into `.project-card__badges`; keeping it
  // detail-only stops it rendering twice on the same card.
  { header: 'status', detail: true, render: (row) => <span className="badge badge--muted">{str(row, 'status') || str(row, 'exit_status')}</span> },
  {
    header: 'file',
    className: 'v',
    primary: true,
    render: (row) => {
      const sha = sha256Of(row)
      return sha ? <span className="mono">{sha.slice(0, 16)}</span> : <span className="text-muted">no source hash</span>
    },
  },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row, null, 2)}</pre>,
  },
]

export const Route = createFileRoute('/github-analysis/')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      pageSize={25}
      label="Evidence"
      title="GitHub analysis"
      subtitle="Multi-engine verdicts for captured payloads published to the private analysis repository."
      columns={COLUMNS}
      rowKey={(_, index) => String(index)}
      inspectorTitle="Analysis run"
      chipNoun="runs"
      emptyState={{
        title: 'No GitHub analyses match this view',
        hint: 'Runs appear here once a payload is correlated against published source.',
      }}
      layout="cards"
      gridId="github-analysis-results"
      cardIcon={() => ShieldIcon}
      cardBadges={(row) => {
        const status = str(row, 'status') || str(row, 'exit_status')
        const family = pathString(row, 'family')
        return (
          <>
            {status ? <span className={status === 'error' ? 'badge badge--muted text-danger' : 'badge badge--muted'}>{status}</span> : null}
            {family ? <span className="badge badge--accent">{family}</span> : null}
          </>
        )
      }}
      cardDesc={(row) => {
        const malicious = pathString(row, 'verdict', 'malicious')
        const total = pathString(row, 'verdict', 'total')
        const level = pathString(row, 'verdict', 'level')
        if (!malicious && !total) return 'no verdict recorded'
        return `${malicious || 0} / ${total || 0} detections${level ? ` • ${level}` : ''}`
      }}
      cardHref={(row) => {
        const sha = sha256Of(row)
        return sha ? `/github-analysis/${encodeURIComponent(sha)}` : undefined
      }}
    />
  )
}
