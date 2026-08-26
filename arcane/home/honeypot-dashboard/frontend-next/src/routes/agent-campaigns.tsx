// Agent campaigns — agent-intrusion-worker's correlated AI-agent activity.
// Category KPI tiles, ?category= filtering, and the per-campaign evidence
// timeline mirror dashboard/ui/agent_campaigns.html + agent_campaigns.go.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import type { StorePage } from '../components/StoreList'
import { formatTimestamp } from '../lib/time'

// Matches build_campaign_verdict's document shape
// (honeypot-agent-intrusion-worker/analysis/agent-intrusion-corpus/worker.py)
// exactly — this store has one real shape, unlike the generic StoreRow
// pages that proxy several heterogeneous sources. events[]/matched_rules
// mirror dashboard/agent_campaigns.go's campaignEvent/campaignMatchedRule.
type DecodeStep = {
  transform: string
  input_sha256: string
  output_sha256: string
  output_len: number
}

type MatchedRule = {
  rule: string
  reason: string
  trust_boundary: string
  decode_chain?: DecodeStep[]
}

type CampaignEvent = {
  event_id: string
  source_index: string
  timestamp: string
  matched_rules?: MatchedRule[]
}

type AgentCampaignRow = {
  '@timestamp': string
  campaign_id: string
  start: string
  end: string
  severity: string
  matched_categories: string[]
  correlation_identifiers: string[]
  event_count: number
  events?: CampaignEvent[]
}

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage<AgentCampaignRow> | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage<AgentCampaignRow>>(`/api/v1/store/agent-campaigns?offset=${data.offset}&size=25`)
  })

// Severity → badge mapping from agent_campaigns.html: critical is the
// danger tier, high the warning tier, everything else informational.
function severityBadge(severity: string) {
  const cls =
    severity === 'critical' ? 'badge badge--danger' : severity === 'high' ? 'badge badge--warning' : 'badge badge--info'
  return <span className={cls}>{severity}</span>
}

const COLUMNS: Column<AgentCampaignRow>[] = [
  { header: 'detected', render: (row) => formatTimestamp(row['@timestamp']) },
  { header: 'severity', render: (row) => severityBadge(row.severity) },
  { header: 'campaign', className: 'v', render: (row) => row.campaign_id },
  { header: 'categories', className: 'v', render: (row) => row.matched_categories.join(' ') },
  { header: 'events', className: 'n', render: (row) => row.event_count.toLocaleString('en-US') },
  { header: 'window', detail: true, render: (row) => `${formatTimestamp(row.start)} → ${formatTimestamp(row.end)}` },
  { header: 'identifiers', detail: true, render: (row) => row.correlation_identifiers.join(', ') },
]

// Pivot from a campaign member event back to the raw sensor document that
// produced it — agent_campaigns.go's campaignEvent.SourceLink (a raw
// Elasticsearch _id is only unique within its own source index, so both
// are pinned together).
function sourceLink(event: CampaignEvent): string {
  if (!event.event_id || !event.source_index) return ''
  return `/history?q=${encodeURIComponent(`_id:"${event.event_id}" AND _index:"${event.source_index}"`)}`
}

function transformPath(rule: MatchedRule): string {
  return (rule.decode_chain ?? []).map((step) => step.transform).join(' → ')
}

// The one hash an operator wants at a glance: the artifact as it existed
// after the last decode layer (agent_campaigns.go's FinalArtifactHash).
function finalArtifactHash(rule: MatchedRule): string {
  const chain = rule.decode_chain ?? []
  return chain.length > 0 ? chain[chain.length - 1].output_sha256 : ''
}

function EvidenceTimeline({ row }: { row: AgentCampaignRow }) {
  const events = row.events ?? []
  if (events.length === 0) return null
  return (
    <section aria-label="Evidence timeline">
      <h3>
        Evidence timeline <span className="text-muted">({events.length} event{events.length === 1 ? '' : 's'})</span>
      </h3>
      <div className="card__scroll">
        <table className="recent data-table hp-flow--tight">
          <thead>
            <tr>
              <th>time</th>
              <th>rule</th>
              <th>trust boundary crossed</th>
              <th>reason</th>
              <th>decoded artifact</th>
              <th>source event</th>
            </tr>
          </thead>
          <tbody>
            {events.flatMap((event, eventIndex) => {
              const link = sourceLink(event)
              const sourceCell = (
                <td className="v">
                  {link ? <a href={link}>view source</a> : <span className="text-muted">&mdash;</span>}
                </td>
              )
              const rules = event.matched_rules ?? []
              if (rules.length === 0) {
                return [
                  <tr key={`e${eventIndex}`}>
                    <td>{formatTimestamp(event.timestamp)}</td>
                    <td className="v" colSpan={4}>
                      <span className="text-muted">correlated into this campaign, no rule matched on its own</span>
                    </td>
                    {sourceCell}
                  </tr>,
                ]
              }
              return rules.map((rule, ruleIndex) => (
                <tr key={`e${eventIndex}r${ruleIndex}`}>
                  <td>{formatTimestamp(event.timestamp)}</td>
                  <td className="v">{rule.rule}</td>
                  <td className="v">{rule.trust_boundary}</td>
                  <td className="v">{rule.reason}</td>
                  <td className="v">
                    {(rule.decode_chain ?? []).length > 0 ? (
                      <small>
                        {transformPath(rule)} <span className="text-muted">sha256:{finalArtifactHash(rule)}</span>
                      </small>
                    ) : (
                      <span className="text-muted">&mdash;</span>
                    )}
                  </td>
                  {sourceCell}
                </tr>
              ))
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}

/** `encoded-egress-external` -> `Encoded egress external`.
 *
 * The categories come from criticality_rules.py as dashed identifiers. They
 * are readable words already; they just are not written as words. Only the
 * separators and the first letter change, so a category added upstream reads
 * correctly here without anyone maintaining a translation table -- and a
 * table would silently fall back to the raw slug for anything new, which is
 * the state this replaces.
 */
function categoryLabel(category: string): string {
  const words = category.replace(/[-_]+/g, ' ').trim()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

export const Route = createFileRoute('/agent-campaigns')({
  // ?category= mirrors agent_campaigns.go's parseAgentCampaignFilter — the
  // KPI tiles link here with it set.
  validateSearch: (search: Record<string, unknown>): { category?: string } => ({
    category: typeof search.category === 'string' && search.category ? search.category : undefined,
  }),
  component: Page,
})

function Page() {
  const { category } = Route.useSearch()
  const [rows, setRows] = useState<AgentCampaignRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)

  useEffect(() => {
    let cancelled = false
    fetchPage({ data: { offset: 0 } }).then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
    })
    return () => {
      cancelled = true
    }
  }, [])

  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchPage({ data: { offset: rows.length } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore])

  // Per-category counts over the loaded campaigns (agent_campaigns.go's
  // CountByCat, sorted count-desc then name).
  const countByCat = new Map<string, number>()
  for (const row of rows ?? []) {
    for (const cat of row.matched_categories) countByCat.set(cat, (countByCat.get(cat) ?? 0) + 1)
  }
  const kpis = [...countByCat.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))

  const visible = rows === null ? null : category ? rows.filter((row) => row.matched_categories.includes(category)) : rows

  return (
    <>
      <InvestigateHeader
        label="Monitor"
        title="Agent campaigns"
        subtitle="Correlated AI-agent intrusion activity — encoded egress, tool-use fingerprints, and cross-sensor automation patterns."
        chips={
          <>
            <span className="chip">
              {category && visible ? `${visible.length} of ${total.toLocaleString('en-US')} campaigns` : `${total.toLocaleString('en-US')} campaigns`}
            </span>
            {category ? (
              <Link className="chip" to="/agent-campaigns" search={{}} title="clear the category filter">
                category: {category} ✕
              </Link>
            ) : null}
            {rows && rows.length > 0 ? <span className="chip">generated {formatTimestamp(rows[0]['@timestamp'])}</span> : null}
          </>
        }
      />
      <p className="note">
        Correlated, deterministically-scored campaigns from agent-intrusion-worker — every entry here crossed a named
        trust boundary via a rule in criticality_rules.py, not a model's own judgment call.
      </p>
      {/* #2179: the per-category tiles count the campaigns that have loaded,
          which lags the store until every page is fetched — say so next to
          the numbers they count rather than presenting a prefix as the
          fleet-wide breakdown. */}
      {rows !== null && rows.length < total ? (
        <p className="note">
          Category counts cover the {rows.length.toLocaleString('en-US')} loaded campaigns of{' '}
          {total.toLocaleString('en-US')} on record — view more to widen them.
        </p>
      ) : null}
      {kpis.length > 0 ? (
        <div className="metric-grid">
          {kpis.map(([cat, count]) => {
            const selected = cat === category
            return (
              <div className="metric" key={cat} aria-current={selected ? 'true' : undefined}>
                {/* #1855: this read as a bare count stacked over a raw slug,
                    and clicking it looked inert -- it did navigate, but the
                    tile itself never showed that it was now the active
                    filter. It says what it counts, reads as words rather
                    than an identifier, and marks itself when selected.
                    Clicking the selected one clears the filter, so the tile
                    is a toggle rather than a one-way trip. */}
                <Link
                  to="/agent-campaigns"
                  search={selected ? {} : { category: cat }}
                  title={selected ? 'clear this filter' : `show only ${categoryLabel(cat)} campaigns`}
                >
                  <div className="metric__value">{count.toLocaleString('en-US')}</div>
                  <div className="metric__label">
                    {categoryLabel(cat)} {count === 1 ? 'campaign' : 'campaigns'}
                  </div>
                </Link>
              </div>
            )
          })}
        </div>
      ) : null}
      <MasterDetailTable
        rows={visible}
        columns={COLUMNS}
        rowKey={(row, index) => `${row.campaign_id}-${index}`}
        emptyState={{
          title: 'No campaign has crossed a criticality-rule threshold yet',
          hint: 'Campaigns surface here once agent-intrusion-worker scores one past a rule.',
        }}
        total={category ? undefined : total}
        onViewMore={category ? undefined : viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Campaign details"
        inspectorExtra={(row) => <EvidenceTimeline row={row} />}
      />
    </>
  )
}
