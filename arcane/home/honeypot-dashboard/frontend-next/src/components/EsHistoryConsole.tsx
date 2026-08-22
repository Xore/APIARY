// The settings modal's admin "Elasticsearch history" pane (#1653):
// settings_modal.html:735-762 / hp-settings.js:1326-1412 — a metric-grid
// storage glance (the storage summary that used to live as its own card
// on the settings page, reshaped into the pane per #647's "brief glance
// above the query tool, not a second Kibana") plus the raw query_string
// console. The console runs against the same /api/v1/events?q=…&size=50
// passthrough the /history page uses, and the Export JSON link targets
// the same /api/export/history.json server-side export.
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import type { JsonRecord } from '../lib/json'

export type EsStorage = { cluster_status: string; index_count: number; doc_count: number; store_bytes: number }

type ConsoleRow = { record: JsonRecord }
type ConsolePage = { total: number; rows: ConsoleRow[] }

const fetchConsoleHistory = createServerFn({ method: 'GET' })
  .inputValidator((input: { q: string }) => input)
  .handler(async ({ data }): Promise<ConsolePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const query = data.q ? `&q=${encodeURIComponent(data.q)}` : ''
    return serviceJSON<ConsolePage>(`/api/v1/events?offset=0&size=50&since=90d${query}`)
  })

function bytesHuman(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`
  return `${bytes} B`
}

/**
 * storage: null while loading/unavailable. hidden: search-filter flag from
 * the settings page (the console card is one .hp-field in the pane).
 */
export function EsHistoryConsole({ storage, hidden }: { storage: EsStorage | null; hidden: boolean }) {
  const [query, setQuery] = useState('')
  // Go's console starts with the placeholder copy and a "waiting" result
  // block (settings_modal.html:760-761); results replace them in place.
  const [meta, setMeta] = useState('Enter an Elasticsearch query or leave blank for newest documents.')
  const [results, setResults] = useState('waiting')
  const activeQuery = query.trim()

  const run = async () => {
    setMeta('loading…')
    try {
      const page = await fetchConsoleHistory({ data: { q: activeQuery } })
      if (!page) throw new Error('query failed')
      setMeta(`${page.rows.length} documents shown`)
      // hp-settings.js:1404's exact result shape: raw _source JSON blocks
      // separated by blank lines.
      setResults(page.rows.map((row) => JSON.stringify(row.record, null, 2)).join('\n\n'))
    } catch (error) {
      setMeta('query failed')
      setResults(error instanceof Error ? error.message : String(error))
    }
  }

  const statusTrendClass =
    storage?.cluster_status === 'green'
      ? 'metric__trend text-secondary'
      : storage?.cluster_status === 'yellow'
        ? 'metric__trend text-warning'
        : 'metric__trend text-danger'

  return (
    <>
      {/* #647: the storage glance — same metric-grid shape as the Services
          pane summary (settings_modal.html:745-750). */}
      {storage === null ? (
        <p className="card__meta">Storage stats unavailable.</p>
      ) : (
        <div className="metric-grid">
          <div className="metric">
            <div className="metric__label">Cluster</div>
            <div className="metric__value">{storage.cluster_status || '—'}</div>
            <div className={statusTrendClass}>Cluster health</div>
          </div>
          <div className="metric">
            <div className="metric__label">Indices</div>
            <div className="metric__value">{storage.index_count.toLocaleString('en-US')}</div>
            <div className="metric__trend text-secondary">Tracked indices</div>
          </div>
          <div className="metric">
            <div className="metric__label">Documents</div>
            <div className="metric__value">{storage.doc_count.toLocaleString('en-US')}</div>
            <div className="metric__trend text-secondary">Across every index</div>
          </div>
          <div className="metric">
            <div className="metric__label">Storage</div>
            <div className="metric__value">{bytesHuman(storage.store_bytes)}</div>
            <div className="metric__trend text-secondary">Primary + replica shards</div>
          </div>
        </div>
      )}
      <section className="card hp-field" hidden={hidden}>
        <div className="card__header">
          <div>
            <h3>Elasticsearch history</h3>
            <p className="card__meta">Run a query_string search across every indexed honeypot and Suricata document.</p>
          </div>
          <div className="hp-head-actions">
            <a
              className="btn btn-ghost btn-sm"
              href={`/api/export/history.json${activeQuery ? `?q=${encodeURIComponent(activeQuery)}` : ''}`}
              title="Download the current result set as JSON"
            >
              Export JSON
            </a>
          </div>
        </div>
        <div className="filters">
          <input
            className="search"
            placeholder="query_string, e.g. honeypot.sensor:cowrie AND honeypot.username:root"
            aria-label="Elasticsearch query"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') void run()
            }}
          />
          <button className="copy" type="button" onClick={() => void run()}>
            search
          </button>
        </div>
        <p className="card__meta">{meta}</p>
        <pre className="code">{results}</pre>
      </section>
    </>
  )
}
