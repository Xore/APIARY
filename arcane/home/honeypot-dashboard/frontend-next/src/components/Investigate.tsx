// Shared Investigate primitives: page header, and the generic
// master-detail table — full-width list, click-open "Row details"
// inspector (outside-click + × close), skeleton-first first paint.
// Mirrors the legacy generic inspector's semantics 1:1.
import { Skeleton } from './ui/skeleton'
import { useEffect, useRef, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { RowActions, RowIcons } from './RowActions'
import { Button } from './ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'

export function InvestigateHeader({
  label,
  title,
  subtitle,
  chips,
}: {
  label: string
  title: string
  subtitle: string
  chips?: React.ReactNode
}) {
  return (
    <>
      <header className="col-span-full flex min-w-0 flex-col gap-2">
        <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
        <h1 className="heading-serif break-all text-[clamp(1.5rem,2.2vw,2rem)] leading-[1.1] text-foreground">{title}</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">{subtitle}</p>
      </header>
      {chips ? <div className="col-span-full flex min-w-0 flex-wrap items-center gap-2">{chips}</div> : null}
    </>
  )
}

export type Column<Row> = {
  header: string
  render: (row: Row) => React.ReactNode
  /** Pane-only column: hidden in the list, shown in the inspector. */
  detail?: boolean
  className?: string
  /** Card layout only (`layout="cards"`): this column's render() becomes
   * the card title instead of a meta field.
   * Defaults to the first non-detail column when none is marked. */
  primary?: boolean
}

/** A result surface with nothing to show: a calm serif sentence, a muted
 * hint, and at most one surface-pill action. */
export type EmptyState = {
  title: string
  hint?: string
  /** Defaults to a magnifier, matching the legacy events empty state.
   * Pass `null` for a surface that should render the sentence alone. */
  icon?: React.ReactNode | null
  action?: { href: string; label: string; icon?: React.ReactNode }
}

const MagnifierIcon = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="11" cy="11" r="7" />
    <line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
)

export function EmptyStateBlock({ state }: { state: EmptyState }) {
  const icon = state.icon === undefined ? MagnifierIcon : state.icon
  return (
    <Card className="grid place-items-center px-5 py-6 text-center">
      <div>
        {icon ? (
          <div className="text-muted-foreground opacity-60 [&_svg]:size-[26px]" aria-hidden="true">
            {icon}
          </div>
        ) : null}
        <CardTitle className="heading-serif mb-0.5 mt-2 text-[17px] font-medium">{state.title}</CardTitle>
        {state.hint ? <CardDescription className="mx-auto max-w-[420px] text-[12.5px]">{state.hint}</CardDescription> : null}
        {state.action ? (
          <a className="empty-state__action" href={state.action.href}>
            {state.action.icon}
            {state.action.label}
          </a>
        ) : null}
      </div>
    </Card>
  )
}

const DEFAULT_EMPTY: EmptyState = { title: 'Nothing to show here' }

// Shape-true table ghosts (#1967): one bar per real column instead of a
// single colSpan blob, so swap-in moves text rather than geometry. `wide`
// marks the columns that carry long values (a hash, a path, an IP) and get
// long bars; everything else gets a short one; `stub` marks row-actions
// cells and gets a small square. Widths are deterministic per column --
// theme.css's tr.hp-skel-batch nth-child variation is row-scoped so it
// cannot express column shape, and it would silently change meaning under
// any future virtualization that reorders or windows rows -- which is also
// why these ghosts don't carry the class at all.
export function SkeletonRows({
  count,
  cols,
  wide = [],
  stub = [],
}: {
  count: number
  cols: number
  wide?: number[]
  stub?: number[]
}) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <TableRow key={`skel-${i}`} aria-hidden="true">
          {Array.from({ length: cols }, (_, col) => {
            const width = stub.includes(col) ? 24 : wide.includes(col) ? '72%' : '42%'
            return (
              <TableCell key={col}>
                <Skeleton className="h-4 w-full" style={{ display: 'block', width }} />
              </TableCell>
            )
          })}
        </TableRow>
      ))}
    </>
  )
}

// Shape-true card ghosts (#1967): the five parts a hydrated result card
// carries (icon slot, title, badge pill, two-line desc, meta row), each as
// its real shell with a skeleton fill inside -- so mid-load the grid reads
// as the result cards it becomes, and swap-in shifts text instead of box
// positions. Every part after `count` is opt-in so a surface mirrors only
// what its loaded cards actually render.
export function SkeletonCards({
  count,
  icon = false,
  badges = false,
  desc = false,
  metaCols = 0,
}: {
  count: number
  icon?: boolean
  badges?: boolean
  desc?: boolean
  /** How many spans the hydrated card's meta row renders. */
  metaCols?: number
}) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <Card key={`skel-${i}`} className="min-w-0 p-4" aria-hidden="true">
          <div className="flex items-center gap-3">
            {icon ? (
              // The real slot paints the accent chip; the ghost fills only
              // where the svg will land.
              <span className="grid size-8 shrink-0 place-items-center rounded-md bg-accent text-accent-foreground">
                <Skeleton className="h-4 w-full" style={{ display: 'block', width: 16, height: 16 }} />
              </span>
            ) : null}
            <span className="min-w-0 flex-1">
              <Skeleton className="h-4 w-full" style={{ display: 'block', width: '68%' }} />
            </span>
            {badges ? (
              <div className="flex flex-wrap gap-1">
                <Skeleton className="h-4 w-full" style={{ display: 'block', width: 56, height: 18, borderRadius: 999 }} />
              </div>
            ) : null}
          </div>
          {desc ? (
            <p className="mt-2 space-y-1 text-sm text-muted-foreground">
              {/* Two lines: __desc clamps at two, so the ghost claims the
                  same vertical budget the loaded text will. */}
              <Skeleton className="h-4 w-full" style={{ display: 'block', width: '88%' }} />
              <Skeleton className="h-4 w-full" style={{ display: 'block', width: '55%' }} />
            </p>
          ) : null}
          {metaCols > 0 ? (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {Array.from({ length: metaCols }, (_, j) => (
                <span key={j}>
                  <Skeleton className="h-4 w-full" style={{ display: 'block', width: 64 }} />
                </span>
              ))}
            </div>
          ) : null}
        </Card>
      ))}
    </>
  )
}

export function MasterDetailTable<Row>({
  rows,
  columns,
  rowKey,
  total,
  onViewMore,
  loadingMore,
  inspectorTitle = 'Row details',
  inspectorExtra,
  layout = 'table',
  gridId,
  cardHref,
  detailHref,
  cardIcon,
  cardBadges,
  cardDesc,
  emptyState,
  pageSize,
}: {
  rows: Row[] | null
  columns: Column<Row>[]
  rowKey: (row: Row, index: number) => string
  total?: number
  onViewMore?: () => void
  loadingMore?: boolean
  inspectorTitle?: string
  inspectorExtra?: (row: Row) => React.ReactNode
  /** 'cards' renders a result-card grid (theme.css's result-surface
   * pattern — payloads-results/github-analysis-results/etc.) instead of a
   * `.data-table`. Selection, the inspector pane, skeleton-first, and
   * View-more pagination are unchanged either way. */
  layout?: 'table' | 'cards'
  /** `layout="cards"` only: id on the `.project-grid` container. */
  gridId?: string
  /** `layout="cards"` only: when a row has exactly one detail page to go
   * to (sandbox/ghidra/github-analysis/cape/revdeck/a payload's own
   * analysis page — the legacy Go templates rendered these result grids
   * as linked cards, not click-to-inspect), the
   * whole card becomes that link and the inspector pane is skipped for
   * it. Return undefined for a row with nothing to link to (falls back
   * to opening the inspector, same as when this prop is omitted). */
  cardHref?: (row: Row) => string | undefined
  /** Rendered when the result set comes back empty (`rows === []`).
   * Without it the empty array fell straight into `.map()` and the surface
   * rendered a header with no body at all, which reads as a broken page
   * rather than as "nothing matched". Word it for the *filtered* case
   * ("No X match this view"); a surface whose emptiness means nothing has
   * been ingested yet should say "no X yet" instead — the legacy
   * templates kept those two claims apart and so should this. */
  emptyState?: EmptyState
  /** `layout="cards"` only — the three parts of the legacy result card the
   * port dropped. Every result card in the Go templates
   * (payload_workbench/sandbox/ghidra/github_analysis/payloads) was five
   * parts: an icon and a badge row flanking the title, a one-line
   * description under it, then the meta row. Only title and meta were being emitted, which is what
   * made the ported cards read flat. Omit any of these for a surface that
   * genuinely has nothing to put there. */
  /** Where a row's own, fuller detail page lives. When this resolves, the
   * inspector grows an "Open full details" action — the inspector shows a
   * row's fields, but several surfaces have a whole page behind the row
   * (a session, a CIDR, a cluster, a recording) that renders far more than
   * a field list, and until now nothing linked to it: clicking a row only
   * ever opened the pane. Return undefined for a row with no such page. */
  detailHref?: (row: Row) => string | undefined
  cardIcon?: (row: Row) => React.ReactNode
  cardBadges?: (row: Row) => React.ReactNode
  cardDesc?: (row: Row) => React.ReactNode
  /** The surface's fetch page size, when known (#1967): the first-load
   * ghosts preview one full page instead of a hardcoded dozen. A short
   * result set still swaps most ghosts for its empty state — that is the
   * honest outcome, not a defect; the count exists so a full page doesn't
   * materialize into more rows than were ever promised. */
  pageSize?: number
}) {
  const [selected, setSelected] = useState<number | null>(null)
  const paneRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const listColumns = columns.filter((column) => !column.detail)
  // One actions column for the whole table, present when any row has a
  // page behind it — a column that appears and disappears per row would
  // shift every other cell sideways as the list refreshes.
  const anyDetailHref = Boolean(detailHref && rows?.some((row) => detailHref(row)))
  const bodyColumnCount = listColumns.length + (anyDetailHref ? 1 : 0)
  const primaryColumn = columns.find((column) => column.primary) ?? listColumns[0]
  const metaColumns = listColumns.filter((column) => column !== primaryColumn)
  // The skeleton ghosts (#1967) mirror this exact shape while rows load:
  // cards get their five parts, tables one bar per real column with the
  // primary column long and the actions cell stubbed.
  const wideIndex = listColumns.indexOf(primaryColumn)
  const ghosts = (count: number) =>
    layout === 'cards' ? (
      <SkeletonCards
        count={count}
        icon={Boolean(cardIcon)}
        badges={Boolean(cardBadges)}
        desc={Boolean(cardDesc)}
        metaCols={metaColumns.length}
      />
    ) : (
      <SkeletonRows
        count={count}
        cols={bodyColumnCount}
        wide={wideIndex >= 0 ? [wideIndex] : []}
        stub={anyDetailHref ? [bodyColumnCount - 1] : []}
      />
    )

  useEffect(() => {
    if (selected === null) return
    const onClick = (event: MouseEvent) => {
      const target = event.target as Element
      if (paneRef.current?.contains(target) || listRef.current?.contains(target)) return
      setSelected(null)
    }
    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  }, [selected])

  const open = selected !== null && rows !== null && rows[selected] !== undefined
  const detailPage = open ? detailHref?.(rows[selected]) : undefined
  const onRowClick = (index: number) => (event: React.MouseEvent) => {
    if ((event.target as Element).closest('a, button, details, summary, input, label')) return
    setSelected(selected === index ? null : index)
  }
  return (
    <div className={`col-span-full grid grid-cols-1 items-start gap-6 ${open ? 'min-[1100px]:grid-cols-[minmax(0,11fr)_minmax(340px,9fr)]' : ''}`}>
      <div className="min-w-0 [&>.card]:overflow-x-auto [&_tbody_tr]:cursor-pointer [&_tbody_tr.selected_td]:bg-accent [&_tbody_tr.selected_td:first-child]:rounded-l-lg [&_tbody_tr.selected_td:first-child]:shadow-[inset_2px_0_0_var(--accent)] [&_tbody_tr.selected_td:last-child]:rounded-r-lg" ref={listRef}>
        <Card className="min-w-0 overflow-x-auto">
          {layout === 'cards' ? (
            <CardContent className="p-4">
              <div className="project-grid" id={gridId}>
              {rows === null ? (
                ghosts(pageSize ?? 12)
              ) : rows.length === 0 ? (
                <div className="wide">
                  <EmptyStateBlock state={emptyState ?? DEFAULT_EMPTY} />
                </div>
              ) : (
                rows.map((row, index) => {
                  const href = cardHref?.(row)
                  const icon = cardIcon?.(row)
                  const badges = cardBadges?.(row)
                  const desc = cardDesc?.(row)
                  const titleClassName = primaryColumn?.className
                    ? `min-w-0 flex-1 font-semibold text-card-foreground ${primaryColumn.className}`
                    : 'min-w-0 flex-1 font-semibold text-card-foreground'
                  const content = (
                    <>
                      <div className="flex min-w-0 items-center gap-3">
                        {icon ? <span className="grid size-8 shrink-0 place-items-center rounded-md bg-accent text-accent-foreground [&_svg]:size-4" aria-hidden="true">{icon}</span> : null}
                        <h2 className={titleClassName}>{primaryColumn?.render(row)}</h2>
                        {!href && (
                          <Button variant="ghost" size="icon" type="button" className="shrink-0 rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-expanded={selected === index} aria-label={`Toggle details for ${primaryColumn?.header ?? 'row'} ${index + 1}`} onClick={() => setSelected(selected === index ? null : index)}>
                            {selected === index ? '▾' : '▸'}
                          </Button>
                        )}
                        {badges ? <div className="flex shrink-0 flex-wrap gap-1">{badges}</div> : null}
                      </div>
                      {desc ? <p className="mt-2 line-clamp-2 text-sm text-muted-foreground">{desc}</p> : null}
                      {metaColumns.length > 0 ? (
                        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                          {metaColumns.map((column) => <span key={column.header}>{column.render(row)}</span>)}
                        </div>
                      ) : null}
                    </>
                  )
                  return (
                    href ? <a key={rowKey(row, index)} className="block min-w-0 text-inherit no-underline" href={href}><Card className="min-w-0 p-4 hover:bg-accent/10">{content}</Card></a>
                      : <Card key={rowKey(row, index)} className="min-w-0 cursor-pointer p-4 hover:bg-accent/10" onClick={onRowClick(index)}>{content}</Card>
                  )
                })
              )}
              {loadingMore ? ghosts(4) : null}
              </div>
            </CardContent>
          ) : (
            <Table className="recent data-table data-table--responsive">
              {/* `data-table--responsive` plus a `data-label` on every cell
                  is what drives theme.css's <=720px stacked-card layout.
                  The stylesheet cannot read the <th> text itself, so the
                  markup has to carry the label — the port emitted neither,
                  leaving those rules dead and wide tables overflowing on
                  mobile. Deriving the label from the column header here
                  keeps the two in sync by construction. */}
              <TableHeader>
                <TableRow>
                  {listColumns.map((column) => (
                    <TableHead key={column.header}>{column.header}</TableHead>
                  ))}
                  {anyDetailHref ? <TableHead aria-label="Row actions" /> : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows === null ? (
                  ghosts(pageSize ?? 12)
                ) : rows.length === 0 ? (
                  <TableRow className="hp-table-state">
                    <TableCell colSpan={bodyColumnCount}>
                      <EmptyStateBlock state={emptyState ?? DEFAULT_EMPTY} />
                    </TableCell>
                  </TableRow>
                ) : (
                  rows.map((row, index) => {
                    // #1868: the full-detail link used to live only inside
                    // the inspector pane, so reaching a row's own page
                    // meant opening the pane first and finding a link in
                    // it. It belongs on the row: that is where the
                    // operator already is, and it is the action they came
                    // for.
                    const rowDetail = detailHref?.(row)
                    return (
                      <TableRow key={rowKey(row, index)} className={selected === index ? 'selected' : undefined} onClick={onRowClick(index)}>
                        {listColumns.map((column) => (
                          <TableCell key={column.header} className={column.className} data-label={column.header}>
                            {column.render(row)}
                          </TableCell>
                        ))}
                        {anyDetailHref ? (
                          <TableCell className="hp-row-actions-cell" data-label="">
                            <RowActions
                              actions={[
                                rowDetail
                                  ? { label: 'Open full details', icon: RowIcons.detail, href: rowDetail }
                                  : null,
                              ]}
                            />
                          </TableCell>
                        ) : null}
                      </TableRow>
                    )
                  })
                )}
                {loadingMore ? ghosts(5) : null}
              </TableBody>
            </Table>
          )}
          {rows !== null && onViewMore && total !== undefined && rows.length < total ? (
            <div className="flex items-center justify-center gap-4 pt-4 pb-1 [&>span:first-child]:text-xs [&>span:first-child]:text-muted-foreground" aria-live="polite">
              <span>
                {rows.length.toLocaleString('en-US')} of {total.toLocaleString('en-US')} entries
              </span>
              <Button variant="secondary" size="sm" type="button" onClick={onViewMore} disabled={loadingMore}>
                View more
              </Button>
            </div>
          ) : null}
        </Card>
      </div>
      <div className={open ? 'sticky top-3.5 min-w-0' : 'hidden'} ref={paneRef}>
        {open ? (
          <Card className="hp-md__rowcard min-w-0">
            <Button variant="ghost" size="icon" className="hp-md__close" type="button" aria-label="Close details" title="Close details" onClick={() => setSelected(null)}>
              ×
            </Button>
            <CardHeader><h2 className="font-semibold leading-none tracking-tight">{inspectorTitle}</h2></CardHeader>
            <CardContent>
              {detailPage ? (
                <Button variant="secondary" size="sm" asChild className="hp-flow">
                  <Link to={detailPage}>
                    Open full details →
                  </Link>
                </Button>
              ) : null}
              {inspectorExtra ? <div className="mt-4">{inspectorExtra(rows[selected])}</div> : null}
              <dl>
                {columns.map((column) => (
                  <FieldPair key={column.header} label={column.header} value={column.render(rows[selected])} />
                ))}
              </dl>
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  )
}

function FieldPair({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  )
}
