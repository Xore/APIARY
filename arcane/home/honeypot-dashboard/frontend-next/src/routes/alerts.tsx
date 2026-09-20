// Alerts — dashboard-alert-state-v1 (the notifier's own state store:
// counts, first/last seen, last-notified, acknowledge flags). Mirrors
// alerts.html's #1535 New/Acknowledged split: one always-unfiltered fetch,
// two client-side partitions, so acknowledging in New and reopening in
// Acknowledged both take effect on the next reload without a page reload.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'
import type { ConfirmOptions } from '../components/ConfirmDialog'
import { Dialog, DialogContent, DialogTitle } from '../components/ui/dialog'
import { Bell, CheckCheck, RefreshCw } from 'lucide-react'
import { Badge } from '../components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from '../components/ui/sheet'
import { Skeleton } from '../components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { formatTimestamp } from '../lib/time'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'

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
  .validator((input: { key: string; ack: boolean }) => input)
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
  .validator((input: { keys: string[]; ack: boolean }) => input)
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

function Alerts() {
  const { first } = Route.useLoaderData()
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null)
  const [complete, setComplete] = useState(true)
  const [tab, setTab] = useState('new')
  const [query, setQuery] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [notice, setNotice] = useState('')
  const [confirmation, setConfirmation] = useState<ConfirmOptions | null>(null)
  const [running, setRunning] = useState(false)
  const [failure, setFailure] = useState('')
  const triggerRef = useRef<HTMLElement | null>(null)
  const refreshRef = useRef<HTMLButtonElement>(null)
  const confirmAction = useCallback((options: ConfirmOptions) => {
    triggerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    setFailure('')
    setNotice('')
    setConfirmation(options)
  }, [])

  const runConfirm = async () => {
    if (!confirmation || running) return
    setRunning(true)
    setFailure('')
    try {
      const message = await confirmation.onConfirm()
      setNotice(typeof message === 'string' ? message : 'Alert updated.')
      setConfirmation(null)
    } catch (error) {
      setFailure(error instanceof Error ? error.message : String(error))
    } finally {
      setRunning(false)
    }
  }

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
    }).catch(() => {
      if (!cancelled) applyBoard({ rows: [], complete: false })
    })
    return () => {
      cancelled = true
    }
  }, [first, applyBoard])

  const reload = useCallback(async () => {
    setRefreshing(true)
    try {
      applyBoard(await fetchAlerts())
    } catch (error) {
      setComplete(false)
      throw error
    } finally {
      setRefreshing(false)
    }
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
    [reload, confirmAction],
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
    [reload, confirmAction],
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
  }, [openCount, reload, confirmAction])

  const q = query.trim().toLowerCase()
  const matches = (row: AlertRow) => !q || `${row.Key} ${row.Message}`.toLowerCase().includes(q)
  const partition = (acknowledged: boolean) =>
    alerts ? groupAlerts(alerts.filter((row) => row.Acknowledged === acknowledged && matches(row))) : null
  const refresh = () => { void reload().catch(() => setNotice('Refresh failed. Retry to load the current alert state.')) }
  const status = (acknowledged: boolean) => <Badge variant={acknowledged ? 'secondary' : 'outline'}>{acknowledged ? 'Acknowledged' : 'Open'}</Badge>
  const actionLabel = (group: AlertGroup) => group.acknowledged ? 'Reopen' : `Acknowledge${group.members.length > 1 ? ` (${group.members.length})` : ''}`
  const groupDetails = (group: AlertGroup) => <Sheet>
    <SheetTrigger asChild><Button variant="ghost" className="h-auto w-full justify-start whitespace-normal px-0 text-left font-medium break-all">{group.label}</Button></SheetTrigger>
    {group.members.length > 1 && <Badge variant="secondary">{group.members.length} members</Badge>}
    <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
      <SheetHeader className="pr-6 text-left"><SheetTitle>Alert group details</SheetTitle><SheetDescription className="break-all">{group.label}</SheetDescription></SheetHeader>
      <div className="my-6 flex flex-wrap items-center gap-2">{status(group.acknowledged)}<Badge variant="outline">{group.members.length} members</Badge><Button size="sm" variant="outline" onClick={() => toggleGroup(group)}>{actionLabel(group)}</Button></div>
      <dl className="grid grid-cols-2 gap-4 border-y py-4 text-sm">
        <div><dt className="text-muted-foreground">Observed</dt><dd className="tabular-nums">{group.count.toLocaleString('en-US')}</dd></div>
        <div><dt className="text-muted-foreground">First seen</dt><dd>{formatTimestamp(group.firstSeen)}</dd></div>
        <div><dt className="text-muted-foreground">Last seen</dt><dd>{formatTimestamp(group.lastSeen)}</dd></div>
      </dl>
      <h3 className="my-4 font-semibold">Members</h3>
      <ul className="space-y-3">{group.members.map((member) => <li key={member.Key} className="space-y-3 rounded-lg border p-4">
        <p className="break-all text-sm font-medium">{member.Message}</p>
        {member.Link ? <Button asChild variant="link" className="h-auto max-w-full whitespace-normal p-0 text-left break-all"><a href={member.Link} title="Show the events behind this alert">{member.Key}</a></Button> : <p className="break-all font-mono text-xs">{member.Key}</p>}
        <dl className="grid grid-cols-2 gap-3 text-xs"><div><dt className="text-muted-foreground">Observed</dt><dd>{member.Count.toLocaleString('en-US')}</dd></div><div><dt className="text-muted-foreground">First seen</dt><dd>{formatTimestamp(member.FirstSeen)}</dd></div><div><dt className="text-muted-foreground">Last seen</dt><dd>{formatTimestamp(member.LastSeen)}</dd></div><div><dt className="text-muted-foreground">Last notified</dt><dd>{member.LastNotified ? formatTimestamp(member.LastNotified) : 'Never'}</dd></div></dl>
        <Button variant="outline" size="sm" onClick={() => toggleMember(member)}>{member.Acknowledged ? 'Reopen' : 'Acknowledge'}</Button>
      </li>)}</ul>
    </SheetContent>
  </Sheet>

  return (
    <section className="min-w-0 space-y-6" aria-labelledby="alerts-title">
      <header className="space-y-2">
        <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Security operations</p>
        <h1 id="alerts-title" className="text-3xl tracking-tight">Alerts</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">Persistent alert state, cooldowns and acknowledgments. Acknowledge alerts to move them out of New; reopen them to resume notifications.</p>
      </header>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="w-full space-y-1.5 sm:max-w-sm">
          <Label htmlFor="alerts-filter" className="text-sm font-medium">Filter alerts</Label>
          <Input id="alerts-filter" type="search" placeholder="Filter by message or key" value={query} onChange={(event) => setQuery(event.target.value)} />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button ref={refreshRef} variant="outline" onClick={refresh} disabled={refreshing || alerts === null}>
            <RefreshCw aria-hidden="true" className={refreshing ? 'animate-spin motion-reduce:animate-none' : ''} />{refreshing ? 'Refreshing…' : 'Refresh'}
          </Button>
          {openCount > 0 && <Button variant="outline" onClick={ackAll} disabled={refreshing}><CheckCheck aria-hidden="true" />Acknowledge all ({openCount})</Button>}
        </div>
      </div>
      <p role="status" className={notice ? 'text-sm text-muted-foreground' : 'sr-only'}>{notice}</p>
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList aria-label="Alert views" className="max-w-full">
          <TabsTrigger value="new" className="gap-2">New <span className="tabular-nums">{alerts ? openCount : '…'}</span></TabsTrigger>
          <TabsTrigger value="acknowledged" className="gap-2">Acknowledged <span className="tabular-nums">{alerts ? alerts.length - openCount : '…'}</span></TabsTrigger>
        </TabsList>
        {(['new', 'acknowledged'] as const).map((id) => {
          const groups = partition(id === 'acknowledged')
          return <TabsContent key={id} value={id} className="mt-4 space-y-4">
            {boardPartial && <Card role="alert"><CardHeader className="p-4"><CardTitle>Partial alert board</CardTitle><CardDescription>A read against the alert state store failed mid-walk; showing the {alerts?.length.toLocaleString('en-US')} records that did load. Counts and actions cover only loaded groups; acknowledge all also includes older alerts.</CardDescription></CardHeader><CardContent className="px-4 pb-4"><Button size="sm" variant="outline" disabled={refreshing} onClick={refresh}>Retry</Button></CardContent></Card>}
            <Card className="min-w-0 overflow-hidden shadow-none">
              <CardHeader className="p-4">
                <CardTitle><h2>{id === 'new' ? 'New alerts' : 'Acknowledged alerts'}</h2></CardTitle>
                <CardDescription>{groups ? `${groups.length} groups · ${groups.reduce((n, group) => n + group.members.length, 0)} matching alerts` : 'Loading alert state…'} · newest activity first</CardDescription>
              </CardHeader>
              {boardFailed ? <div role="alert" className="space-y-3 border-t p-6"><h3 className="font-semibold">The alert board failed to load</h3><p className="text-sm text-muted-foreground">The backend request failed. An unavailable board does not mean there are no alerts.</p><Button variant="outline" onClick={refresh} disabled={refreshing}>Retry</Button></div>
              : groups?.length === 0 ? <div role="status" className="flex flex-col items-center gap-3 border-t px-6 py-12 text-center"><Bell className="size-8 text-muted-foreground" aria-hidden="true" /><h3 className="font-semibold">{q ? 'No alerts match this filter' : alerts?.length === 0 ? 'No alerts recorded' : id === 'new' ? 'No new alerts' : 'No acknowledged alerts'}</h3><p className="max-w-sm text-sm text-muted-foreground">{q ? 'Try another message or key, or clear the filter.' : id === 'new' ? 'New notifications will appear here. Acknowledged alerts remain in their own tab.' : 'Acknowledged alerts stay here until reopened.'}</p>{q && <Button variant="outline" onClick={() => setQuery('')}>Clear filter</Button>}</div>
              : <><Table aria-label={id === 'new' ? 'New alert groups' : 'Acknowledged alert groups'} className="border-t max-[391px]:hidden">
                <TableHeader><TableRow><TableHead>State</TableHead><TableHead>Message</TableHead><TableHead className="text-right">Observed</TableHead><TableHead>Last seen</TableHead><TableHead className="text-right">Action</TableHead></TableRow></TableHeader>
                <TableBody>
                  {groups === null ? Array.from({ length: 8 }, (_, i) => <TableRow key={i}><TableCell colSpan={5}><Skeleton className="h-8 w-full" /></TableCell></TableRow>) : groups.map((group) => <TableRow key={group.signature}>
                    <TableCell>{status(group.acknowledged)}</TableCell>
                    <TableCell className="min-w-48 max-w-md">{groupDetails(group)}</TableCell>
                    <TableCell className="text-right tabular-nums">{group.count.toLocaleString('en-US')}</TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatTimestamp(group.lastSeen)}</TableCell>
                    <TableCell className="text-right"><Button variant="outline" size="sm" onClick={() => toggleGroup(group)}>{actionLabel(group)}</Button></TableCell>
                  </TableRow>)}
                </TableBody>
              </Table><div role="list" className="hidden border-t max-[391px]:block" aria-label={id === 'new' ? 'New alert groups' : 'Acknowledged alert groups'}>
                {groups === null ? Array.from({ length: 4 }, (_, i) => <Card role="listitem" key={i} className="rounded-none border-x-0 border-t-0 shadow-none"><CardContent className="p-4"><Skeleton className="h-32 w-full" /></CardContent></Card>) : groups.map((group) => <Card role="listitem" key={group.signature} className="rounded-none border-x-0 border-t-0 shadow-none">
                  <CardContent className="p-4">
                    <dl className="space-y-3 text-sm">
                      <div><dt className="text-xs font-medium text-muted-foreground">State</dt><dd className="mt-1">{status(group.acknowledged)}</dd></div>
                      <div><dt className="text-xs font-medium text-muted-foreground">Message</dt><dd>{groupDetails(group)}</dd></div>
                      <div><dt className="text-xs font-medium text-muted-foreground">Observed</dt><dd className="tabular-nums">{group.count.toLocaleString('en-US')}</dd></div>
                      <div><dt className="text-xs font-medium text-muted-foreground">Last seen</dt><dd>{formatTimestamp(group.lastSeen)}</dd></div>
                      <div><dt className="text-xs font-medium text-muted-foreground">Action</dt><dd className="mt-1"><Button variant="outline" size="sm" onClick={() => toggleGroup(group)}>{actionLabel(group)}</Button></dd></div>
                    </dl>
                  </CardContent>
                </Card>)}
              </div></>}
            </Card>
            <p className="text-xs text-muted-foreground">Board shows up to {BOARD_CAP} records. Same-kind alerts are grouped; filtering applies to individual members before grouping.</p>
          </TabsContent>
        })}
      </Tabs>
      <Dialog open={confirmation !== null} onOpenChange={(open) => { if (!open && !running) setConfirmation(null) }}>
        <DialogContent role="alertdialog" aria-describedby={undefined} className="max-h-[90dvh] w-[calc(100%-2rem)] max-w-lg gap-4 overflow-y-auto rounded-lg p-6 text-foreground"
          onEscapeKeyDown={(event) => { if (running) event.preventDefault() }}
          onInteractOutside={(event) => { if (running) event.preventDefault() }}
          onCloseAutoFocus={(event) => { event.preventDefault(); (triggerRef.current?.isConnected ? triggerRef.current : refreshRef.current)?.focus() }}>
          <div className="space-y-2"><DialogTitle className="text-lg font-semibold">{confirmation?.title}</DialogTitle><p className="text-sm text-muted-foreground">{confirmation?.description}</p></div>
          {confirmation?.warning && <p className="rounded-md border bg-muted p-3 text-sm break-all">{confirmation.warning}</p>}
          {failure && <p role="alert" className="text-sm text-destructive">{failure}</p>}
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end"><Button variant="outline" disabled={running} onClick={() => setConfirmation(null)}>Cancel</Button><Button autoFocus variant={confirmation?.danger ? 'destructive' : 'default'} disabled={running} onClick={() => void runConfirm()}>{running ? 'Working…' : failure ? 'Try again' : confirmation?.confirmLabel}</Button></div>
        </DialogContent>
      </Dialog>
    </section>
  )
}
