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
import { ErrorStateBlock } from '../components/ErrorState'
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

// #1566: 200 same-rule YARA hits (one row per file hash) flooded the New
// tab as visually-identical rows. Collapse same-class alerts into one
// group — same Key prefix (the alert kind, e.g. "yara"/"campaign") plus
// the Message with any hash-like or dotted-quad token blanked out, so
// "YARA payload match: <hash> rules=X source=dionaea" for 200 different
// hashes becomes one group instead of 200 rows.
const VARIABLE_TOKEN = /\b(?:[0-9a-fA-F]{12,64}|(?:\d{1,3}\.){3}\d{1,3})\b/g

function groupSignature(row: AlertRow): string {
  const prefix = row.Key.slice(0, row.Key.indexOf(':')) || row.Key
  return `${prefix}::${row.Message.replace(VARIABLE_TOKEN, '…')}`
}

type AlertGroup = {
  signature: string
  label: string
  members: AlertRow[]
  count: number
  lastSeen: string
  firstSeen: string
  acknowledged: boolean
}

function groupAlerts(rows: AlertRow[]): AlertGroup[] {
  const groups = new Map<string, AlertGroup>()
  for (const row of rows) {
    const signature = groupSignature(row)
    const existing = groups.get(signature)
    if (existing) {
      existing.members.push(row)
      existing.count += row.Count
      if (row.LastSeen > existing.lastSeen) existing.lastSeen = row.LastSeen
      if (row.FirstSeen < existing.firstSeen) existing.firstSeen = row.FirstSeen
    } else {
      groups.set(signature, {
        signature,
        label: row.Message,
        members: [row],
        count: row.Count,
        lastSeen: row.LastSeen,
        firstSeen: row.FirstSeen,
        acknowledged: row.Acknowledged,
      })
    }
  }
  return [...groups.values()].sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1))
}

// The Go alert board renders the whole store at once (capped at 200 records,
// alerts.html #301 — no server-side pagination); store_page caps each read at
// 100, so page up to that same 200 cap here.
const BOARD_CAP = 200

// #2178: a failed store read used to break the paging loop and return
// whatever prefix had loaded — a backend outage rendered as an empty board,
// i.e. the exact "quiet" an operator reads as healthy. complete:false lets
// the component say "failed outright" vs "partial board" instead of either
// masquerading as no-alerts.
type BoardFetch = { rows: AlertRow[]; complete: boolean }

const fetchAlerts = createServerFn({ method: 'GET' }).handler(async (): Promise<BoardFetch> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const rows: AlertRow[] = []
  for (let offset = 0; offset < BOARD_CAP; offset += 100) {
    const page = await serviceJSON<Page>(`/api/v1/alerts?offset=${offset}&size=100`)
    if (!page) return { rows, complete: false }
    if (page.rows.length === 0) break
    rows.push(...page.rows)
    if (rows.length >= page.total) break
  }
  return { rows: rows.slice(0, BOARD_CAP), complete: true }
})

const acknowledgeAlert = createServerFn({ method: 'POST' })
  .inputValidator((input: { key: string; ack: boolean }) => input)
  .handler(async ({ data }): Promise<void> => {
    // Session-checked here as defense in depth (#2123); the global
    // function middleware rejects unauthenticated calls before this runs.
    const { getSessionUser } = await import('../lib/auth')
    if (!(await getSessionUser())) throw new Error('Sign in required.')
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/alerts/${encodeURIComponent(data.key)}/ack`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ack: data.ack }),
    })
    if (!response.ok) throw new Error(`Alert update failed (${response.status})`)
  })

// Group-level acknowledge/reopen — one call per member key, same endpoint
// per-row acknowledge uses. Bounded by a rule-group's member count (never
// the whole board), so no offset-walk like acknowledgeAll needs.
const acknowledgeKeys = createServerFn({ method: 'POST' })
  .inputValidator((input: { keys: string[]; ack: boolean }) => input)
  .handler(async ({ data }): Promise<number> => {
    // Same defense-in-depth session check as acknowledgeAlert (#2123).
    const { getSessionUser } = await import('../lib/auth')
    if (!(await getSessionUser())) throw new Error('Sign in required.')
    const { serviceFetch } = await import('../lib/backend.server')
    let changed = 0
    for (const key of data.keys) {
      const response = await serviceFetch(`/api/v1/alerts/${encodeURIComponent(key)}/ack`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ack: data.ack }),
      })
      if (!response.ok) throw new Error(`Alert update failed (${response.status})`)
      changed += 1
    }
    return changed
  })

// The Go tier's POST /api/alerts scope=all acknowledged every open alert
// server-side in one call (hp-modals.js:164-186). The Rust endpoint only
// flips one key at a time, so walk the store beyond the board cap and ack
// each open record, returning the changed count the confirm dialog reports.
const acknowledgeAll = createServerFn({ method: 'POST' }).handler(async (): Promise<number> => {
  // Same defense-in-depth session check as acknowledgeAlert (#2123).
  const { getSessionUser } = await import('../lib/auth')
  if (!(await getSessionUser())) throw new Error('Sign in required.')
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

function buildColumns(onToggleGroup: (group: AlertGroup) => void, onToggleMember: (row: AlertRow) => void): Column<AlertGroup>[] {
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
      render: (group) =>
        group.acknowledged ? (
          <span className="badge badge--muted">acknowledged</span>
        ) : (
          <span className="badge badge--warning">open</span>
        ),
    },
    {
      header: 'message',
      className: 'v',
      render: (group) => (
        <>
          {group.label}
          {group.members.length > 1 ? <span className="badge badge--muted" title="alerts of this same rule/kind, grouped by hash"> ×{group.members.length}</span> : null}
        </>
      ),
    },
    { header: 'observed', className: 'n', render: (group) => group.count.toLocaleString('en-US') },
    { header: 'last seen', render: (group) => formatTimestamp(group.lastSeen) },
    { header: 'first seen', detail: true, render: (group) => formatTimestamp(group.firstSeen) },
    {
      header: 'members',
      detail: true,
      render: (group) => (
        <ul>
          {group.members.map((member) => (
            <li key={member.Key}>
              {linkCell(member, member.Key)} — {member.Count.toLocaleString('en-US')} observed, last {formatTimestamp(member.LastSeen)}{' '}
              <button
                className="copy"
                type="button"
                onClick={(event) => {
                  event.stopPropagation()
                  onToggleMember(member)
                }}
              >
                {member.Acknowledged ? 'reopen' : 'acknowledge'}
              </button>
            </li>
          ))}
        </ul>
      ),
    },
    {
      header: 'action',
      render: (group) => (
        <button
          className="copy"
          type="button"
          onClick={(event) => {
            event.stopPropagation()
            onToggleGroup(group)
          }}
        >
          {group.acknowledged ? 'reopen' : `acknowledge${group.members.length > 1 ? ` (${group.members.length})` : ''}`}
        </button>
      ),
    },
  ]
}

function Alerts() {
  const { first } = Route.useLoaderData()
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null)
  const [complete, setComplete] = useState(true)
  const [tab, setTab] = useState('new')
  const [query, setQuery] = useState('')

  const applyBoard = useCallback((result: BoardFetch) => {
    setAlerts(result.rows)
    setComplete(result.complete)
  }, [])

  useEffect(() => {
    let cancelled = false
    setAlerts(null)
    setComplete(true)
    first.then((result) => {
      if (!cancelled) applyBoard(result)
    })
    return () => {
      cancelled = true
    }
  }, [first, applyBoard])

  const reload = useCallback(async () => {
    applyBoard(await fetchAlerts())
  }, [applyBoard])

  // Per-member acknowledge/reopen (from a group's expanded member list) —
  // same confirm surface and copy as hp-modals.js's data-hp-alert-ack
  // handler.
  const toggleMember = useCallback(
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

  // Group-level acknowledge/reopen — every member of a rule-group at once,
  // restoring the old dashboard's grouped-flood cleanup in one click.
  const toggleGroup = useCallback(
    (group: AlertGroup) => {
      const acknowledge = !group.acknowledged
      const keys = group.members.map((member) => member.Key)
      confirmAction({
        title: acknowledge ? 'Acknowledge this alert group?' : 'Reopen this alert group?',
        description: acknowledge
          ? 'Acknowledging suppresses repeat notifications for every alert in this group until reopened.'
          : 'Reopening makes every alert in this group active and eligible for notifications again.',
        warning: `${group.label} — ${keys.length} alert${keys.length === 1 ? '' : 's'} in this group.`,
        confirmLabel: acknowledge ? `Acknowledge ${keys.length === 1 ? 'alert' : `all ${keys.length}`}` : `Reopen ${keys.length === 1 ? 'alert' : `all ${keys.length}`}`,
        danger: acknowledge,
        onConfirm: async () => {
          const changed = await acknowledgeKeys({ data: { keys, ack: acknowledge } })
          await reload()
          return acknowledge ? `${changed} alert${changed === 1 ? '' : 's'} acknowledged.` : `${changed} alert${changed === 1 ? '' : 's'} reopened.`
        },
      })
    },
    [reload],
  )

  const openCount = alerts ? alerts.filter((row) => !row.Acknowledged).length : 0

  // #2178 tri-state: a walk that failed on its very first read is not a
  // quiet board; a walk that died partway shows what loaded plus a note.
  const boardFailed = alerts !== null && alerts.length === 0 && !complete
  const boardPartial = alerts !== null && alerts.length > 0 && !complete

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

  const columns = buildColumns(toggleGroup, toggleMember)
  const q = query.trim().toLowerCase()
  const matches = (row: AlertRow) => !q || `${row.Key} ${row.Message}`.toLowerCase().includes(q)
  const partition = (acknowledged: boolean) =>
    alerts ? groupAlerts(alerts.filter((row) => row.Acknowledged === acknowledged && matches(row))) : null

  const panel = (id: string, acknowledged: boolean) => {
    const groups = partition(acknowledged)
    return (
      <TabPanel id={id} active={tab} idPrefix="alerts" className="dashboard-panel">
        {boardFailed ? (
          <ErrorStateBlock
            title="The alert board failed to load"
            hint="The backend request failed — an outage looks like silence here, so it names itself instead."
            onRetry={reload}
          />
        ) : (
          <>
            {boardPartial ? (
              <p className="note">
                A read against the alert state store failed mid-walk; showing the {alerts?.length.toLocaleString('en-US')}{' '}
                record{alerts?.length === 1 ? '' : 's'} that did load.
              </p>
            ) : null}
            {groups && groups.length === 0 ? (
              <p className="empty" role="status" aria-live="polite">
                {alerts && alerts.length ? 'No alerts match this filter.' : 'No alerts recorded.'}
              </p>
            ) : (
              <MasterDetailTable
                rows={groups}
                columns={columns}
                rowKey={(group) => group.signature}
                emptyState={{
                  title: 'No alerts match this filter',
                  hint: 'Nothing is open right now, or a filter above is excluding it.',
                }}
                inspectorTitle="Alert group details"
              />
            )}
          </>
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
