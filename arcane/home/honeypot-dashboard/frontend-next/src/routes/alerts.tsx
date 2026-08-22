// Alerts — dashboard-alert-state-v1 (the notifier's own state store:
// counts, first/last seen, last-notified, acknowledge flags). Mirrors
// alerts.html's #1535 New/Acknowledged split: one always-unfiltered fetch,
// two client-side partitions, so acknowledging in New and reopening in
// Acknowledged both take effect on the next reload without a page reload.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { Tabs, TabPanel } from '../components/Tabs'
import { formatTimestamp } from '../lib/time'

type AlertRow = {
  Key: string
  Message: string
  Link: string
  FirstSeen: string
  LastSeen: string
  LastNotified: string | null
  Count: number
  Acknowledged: boolean
}

type Page = { total: number; rows: AlertRow[] }

// The Go alert board renders the whole store at once (capped at 200 records,
// alerts.html #301 — no server-side pagination); store_page caps each read at
// 100, so page up to that same 200 cap here.
const BOARD_CAP = 200

const fetchAlerts = createServerFn({ method: 'GET' }).handler(async (): Promise<AlertRow[]> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const rows: AlertRow[] = []
  for (let offset = 0; offset < BOARD_CAP; offset += 100) {
    const page = await serviceJSON<Page>(`/api/v1/alerts?offset=${offset}&size=100`)
    if (!page || page.rows.length === 0) break
    rows.push(...page.rows)
    if (rows.length >= page.total) break
  }
  return rows.slice(0, BOARD_CAP)
})

const acknowledgeAlert = createServerFn({ method: 'POST' })
  .inputValidator((input: { key: string; ack: boolean }) => input)
  .handler(async ({ data }): Promise<void> => {
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/alerts/${encodeURIComponent(data.key)}/ack`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ack: data.ack }),
    })
    if (!response.ok) throw new Error(`Alert update failed (${response.status})`)
  })

// The Go tier's POST /api/alerts scope=all acknowledged every open alert
// server-side in one call (hp-modals.js:164-186). The Rust endpoint only
// flips one key at a time, so walk the store beyond the board cap and ack
// each open record, returning the changed count the confirm dialog reports.
const acknowledgeAll = createServerFn({ method: 'POST' }).handler(async (): Promise<number> => {
  const { serviceJSON, serviceFetch } = await import('../lib/backend.server')
  const open: string[] = []
  for (let offset = 0; ; offset += 100) {
    const page = await serviceJSON<Page>(`/api/v1/alerts?offset=${offset}&size=100`)
    if (!page || page.rows.length === 0) break
    for (const row of page.rows) if (!row.Acknowledged) open.push(row.Key)
    if (offset + 100 >= page.total) break
  }
  let changed = 0
  for (const key of open) {
    const response = await serviceFetch(`/api/v1/alerts/${encodeURIComponent(key)}/ack`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ack: true }),
    })
    if (!response.ok) throw new Error(`Alert update failed (${response.status})`)
    changed += 1
  }
  return changed
})

export const Route = createFileRoute('/alerts')({
  loader: async () => ({ first: fetchAlerts() }),
  component: Alerts,
})

function buildColumns(onToggle: (row: AlertRow) => void): Column<AlertRow>[] {
  const linkCell = (row: AlertRow, text: string) =>
    row.Link ? (
      <a className="lnk" href={row.Link} title="show the events behind this alert" onClick={(event) => event.stopPropagation()}>
        {text}
      </a>
    ) : (
      text
    )
  return [
    {
      header: 'state',
      render: (row) =>
        row.Acknowledged ? (
          <span className="badge badge--muted">acknowledged</span>
        ) : (
          <span className="badge badge--warning">open</span>
        ),
    },
    { header: 'key', className: 'v', render: (row) => linkCell(row, row.Key) },
    { header: 'message', className: 'v', render: (row) => linkCell(row, row.Message) },
    { header: 'observed', className: 'n', render: (row) => row.Count.toLocaleString('en-US') },
    { header: 'last seen', render: (row) => formatTimestamp(row.LastSeen) },
    { header: 'last notified', render: (row) => (row.LastNotified ? formatTimestamp(row.LastNotified) : '—') },
    { header: 'first seen', detail: true, render: (row) => formatTimestamp(row.FirstSeen) },
    {
      header: 'action',
      render: (row) => (
        <button
          className="copy"
          type="button"
          onClick={(event) => {
            event.stopPropagation()
            onToggle(row)
          }}
        >
          {row.Acknowledged ? 'reopen' : 'acknowledge'}
        </button>
      ),
    },
  ]
}

function Alerts() {
  const { first } = Route.useLoaderData()
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null)
  const [tab, setTab] = useState('new')
  const [query, setQuery] = useState('')

  useEffect(() => {
    let cancelled = false
    first.then((rows) => {
      if (!cancelled) setAlerts(rows)
    })
    return () => {
      cancelled = true
    }
  }, [first])

  const reload = useCallback(async () => {
    setAlerts(await fetchAlerts())
  }, [])

  // Per-row acknowledge/reopen — same confirm surface and copy as
  // hp-modals.js's data-hp-alert-ack handler.
  const toggle = useCallback(
    (row: AlertRow) => {
      const acknowledge = !row.Acknowledged
      confirmAction({
        title: acknowledge ? 'Acknowledge this alert?' : 'Reopen this alert?',
        description: acknowledge
          ? 'Acknowledging suppresses repeat notifications until the alert is reopened.'
          : 'Reopening makes the alert active and eligible for notifications again.',
        warning: row.Message || row.Key,
        confirmLabel: acknowledge ? 'Acknowledge alert' : 'Reopen alert',
        danger: acknowledge,
        onConfirm: async () => {
          await acknowledgeAlert({ data: { key: row.Key, ack: acknowledge } })
          await reload()
          return acknowledge ? 'Alert acknowledged.' : 'Alert reopened.'
        },
      })
    },
    [reload],
  )

  const openCount = alerts ? alerts.filter((row) => !row.Acknowledged).length : 0

  const ackAll = useCallback(() => {
    confirmAction({
      title: 'Acknowledge every open alert?',
      description: 'Acknowledging suppresses repeat notifications until each alert is reopened. Reopening is one alert at a time.',
      warning: `${openCount} open alert${openCount === 1 ? '' : 's'} listed here, plus any older ones this page does not show.`,
      confirmLabel: 'Acknowledge all',
      danger: true,
      onConfirm: async () => {
        const changed = await acknowledgeAll()
        await reload()
        return `${changed} alert${changed === 1 ? '' : 's'} acknowledged.`
      },
    })
  }, [openCount, reload])

  const columns = buildColumns(toggle)
  const q = query.trim().toLowerCase()
  const matches = (row: AlertRow) => !q || `${row.Key} ${row.Message}`.toLowerCase().includes(q)
  const partition = (acknowledged: boolean) => (alerts ? alerts.filter((row) => row.Acknowledged === acknowledged && matches(row)) : null)

  const panel = (id: string, acknowledged: boolean) => {
    const rows = partition(acknowledged)
    return (
      <TabPanel id={id} active={tab} idPrefix="alerts" className="dashboard-panel">
        {rows && rows.length === 0 ? (
          <p className="empty" role="status" aria-live="polite">
            {alerts && alerts.length ? 'No alerts match this filter.' : 'No alerts recorded.'}
          </p>
        ) : (
          <MasterDetailTable
            rows={rows}
            columns={columns}
            rowKey={(row) => row.Key}
            inspectorTitle="Alert details"
          />
        )}
      </TabPanel>
    )
  }

  return (
    <>
      <InvestigateHeader
        label="Security operations"
        title="Alerts"
        subtitle="Persistent alert state, cooldowns and acknowledgments — acknowledging an alert moves it out of New and into Acknowledged until it is reopened."
        chips={
          <>
            <button className="copy" type="button" onClick={() => void reload()}>
              refresh
            </button>
            {openCount > 0 ? (
              <button className="copy" type="button" onClick={ackAll}>
                acknowledge all ({openCount})
              </button>
            ) : null}
            <input
              className="search"
              placeholder="filter by message or key"
              aria-label="Filter alerts"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </>
        }
      />
      <Tabs
        tabs={[
          { id: 'new', label: 'New' },
          { id: 'acknowledged', label: 'Acknowledged' },
        ]}
        active={tab}
        onSelect={setTab}
        label="Alert views"
        idPrefix="alerts"
      />
      {panel('new', false)}
      {panel('acknowledged', true)}
    </>
  )
}
