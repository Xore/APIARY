// Shared Investigate primitives: page header, and the generic
// master-detail table — full-width list, click-open "Row details"
// inspector (outside-click + × close), skeleton-first first paint.
// Mirrors the legacy generic inspector's semantics 1:1.
import { useEffect, useRef, useState } from 'react'
import { RowActions, RowIcons } from './RowActions'

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
      <header className="overview-header">
        <div>
          <div className="label-section">{label}</div>
          <h1>{title}</h1>
          <p className="subtitle">{subtitle}</p>
        </div>
      </header>
      {chips ? <div className="filters">{chips}</div> : null}
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
   * the card title (`.project-card__title`) instead of a meta field.
   * Defaults to the first non-detail column when none is marked. */
  primary?: boolean
}

/** A result surface with nothing to show. Mirrors the legacy `.empty-state`
 * block — a calm serif sentence, a muted hint, and at most one
 * surface-pill action. theme.css has carried these rules the whole time;
 * the port simply stopped emitting the markup. */
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
    <div className="empty-state">
      <div>
        {icon ? (
          <div className="empty-state__icon" aria-hidden="true">
            {icon}
          </div>
        ) : null}
        <div className="empty-state__title">{state.title}</div>
        {state.hint ? <p className="empty-state__hint">{state.hint}</p> : null}
        {state.action ? (
          <a className="empty-state__action" href={state.action.href}>
            {state.action.icon}
            {state.action.label}
          </a>
        ) : null}
      </div>
    </div>
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
        <tr key={`skel-${i}`} aria-hidden="true">
          {Array.from({ length: cols }, (_, col) => {
            const width = stub.includes(col) ? 24 : wide.includes(col) ? '72%' : '42%'
            return (
              <td key={col}>
                <span className="skeleton-line" style={{ display: 'block', width }} />
              </td>
            )
          })}
        </tr>
      ))}
    </>
  )
}

// Shape-true card ghosts (#1967): the five parts a hydrated .project-card
// carries (icon slot, title, badge pill, two-line desc, meta row), each as
// its real shell with a skeleton fill inside -- so mid-load the grid reads
// as the result cards it becomes, and swap-in shifts text instead of box
// positions. Every part after `count` is opt-in so a surface mirrors only
// what its loaded cards actually render; theme.css still styles all five
// shells whether populated or ghosted.
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
        <div key={`skel-${i}`} className="project-card" aria-hidden="true">
          <div className="project-card__header">
            {icon ? (
              // The real slot paints the accent chip; the ghost fills only
              // where the svg will land.
              <span className="project-card__icon">
                <span className="skeleton-line" style={{ display: 'block', width: 16, height: 16 }} />
              </span>
            ) : null}
            <span className="project-card__title">
              <span className="skeleton-line" style={{ display: 'block', width: '68%' }} />
            </span>
            {badges ? (
              <div className="project-card__badges">
                <span className="skeleton-line" style={{ display: 'block', width: 56, height: 18, borderRadius: 999 }} />
              </div>
            ) : null}
          </div>
          {desc ? (
            <p className="project-card__desc">
              {/* Two lines: __desc clamps at two, so the ghost claims the
                  same vertical budget the loaded text will. */}
              <span className="skeleton-line" style={{ display: 'block', width: '88%' }} />
              <span className="skeleton-line" style={{ display: 'block', width: '55%' }} />
            </p>
          ) : null}
          {metaCols > 0 ? (
            <div className="project-card__meta">
              {Array.from({ length: metaCols }, (_, j) => (
                <span key={j}>
                  <span className="skeleton-line" style={{ display: 'block', width: 64 }} />
                </span>
              ))}
            </div>
          ) : null}
        </div>
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
  /** 'cards' renders a `.project-card` grid (theme.css's result-surface
   * pattern — payloads-results/github-analysis-results/etc.) instead of a
   * `.data-table`. Selection, the inspector pane, skeleton-first, and
   * View-more pagination are unchanged either way. */
  layout?: 'table' | 'cards'
  /** `layout="cards"` only: id on the `.project-grid` container — theme.css
   * scopes a few of its `.project-card` refinements (ellipsis, flex-wrap,
   * action-menu alignment) to specific result-surface ids. Omit for a card
   * grid theme.css doesn't name. */
  gridId?: string
  /** `layout="cards"` only: when a row has exactly one detail page to go
   * to (sandbox/ghidra/github-analysis/cape/revdeck/a payload's own
   * analysis page — the legacy Go templates rendered these result grids
   * as `<a class="project-card" href="...">`, not click-to-inspect), the
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
   * port dropped. Every `.project-card` in the Go templates
   * (payload_workbench/sandbox/ghidra/github_analysis/payloads) was five
   * parts: an icon and a badge row flanking the title, a one-line
   * description under it, then the meta row. theme.css still styles all
   * five; only `__title` and `__meta` were being emitted, which is what
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
    <div className={open ? 'hp-md hp-md--active hp-md--open wide' : 'hp-md hp-md--active wide'}>
      <div className="hp-md__list" ref={listRef}>
        <div className="card wide">
          {layout === 'cards' ? (
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
                  const CardTag = href ? 'a' : 'div'
                  const cardProps = href ? { href } : { onClick: onRowClick(index) }
                  return (
                    <CardTag key={rowKey(row, index)} className="project-card" {...cardProps}>
                      <div className="project-card__header">
                        {icon ? (
                          <span className="project-card__icon" aria-hidden="true">
                            {icon}
                          </span>
                        ) : null}
                        <span className={primaryColumn?.className ? `project-card__title ${primaryColumn.className}` : 'project-card__title'}>
                          {primaryColumn?.render(row)}
                        </span>
                        {badges ? <div className="project-card__badges">{badges}</div> : null}
                      </div>
                      {desc ? <p className="project-card__desc">{desc}</p> : null}
                      {metaColumns.length > 0 ? (
                        <div className="project-card__meta">
                          {metaColumns.map((column) => (
                            <span key={column.header}>{column.render(row)}</span>
                          ))}
                        </div>
                      ) : null}
                    </CardTag>
                  )
                })
              )}
              {loadingMore ? ghosts(4) : null}
            </div>
          ) : (
            <table className="recent data-table data-table--responsive">
              {/* `data-table--responsive` plus a `data-label` on every cell
                  is what drives theme.css's <=720px stacked-card layout.
                  The stylesheet cannot read the <th> text itself, so the
                  markup has to carry the label — the port emitted neither,
                  leaving those rules dead and wide tables overflowing on
                  mobile. Deriving the label from the column header here
                  keeps the two in sync by construction. */}
              <thead>
                <tr>
                  {listColumns.map((column) => (
                    <th key={column.header}>{column.header}</th>
                  ))}
                  {anyDetailHref ? <th aria-label="Row actions" /> : null}
                </tr>
              </thead>
              <tbody>
                {rows === null ? (
                  ghosts(pageSize ?? 12)
                ) : rows.length === 0 ? (
                  <tr className="hp-table-state">
                    <td colSpan={bodyColumnCount}>
                      <EmptyStateBlock state={emptyState ?? DEFAULT_EMPTY} />
                    </td>
                  </tr>
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
                      <tr key={rowKey(row, index)} className={selected === index ? 'selected' : undefined} onClick={onRowClick(index)}>
                        {listColumns.map((column) => (
                          <td key={column.header} className={column.className} data-label={column.header}>
                            {column.render(row)}
                          </td>
                        ))}
                        {anyDetailHref ? (
                          <td className="hp-row-actions-cell" data-label="">
                            <RowActions
                              actions={[
                                rowDetail
                                  ? { label: 'Open full details', icon: RowIcons.detail, href: rowDetail }
                                  : null,
                              ]}
                            />
                          </td>
                        ) : null}
                      </tr>
                    )
                  })
                )}
                {loadingMore ? ghosts(5) : null}
              </tbody>
            </table>
          )}
          {rows !== null && onViewMore && total !== undefined && rows.length < total ? (
            <div className="hp-lazy-controls" aria-live="polite">
              <span>
                {rows.length.toLocaleString('en-US')} of {total.toLocaleString('en-US')} entries
              </span>
              <button className="btn btn-secondary btn-sm" type="button" onClick={onViewMore} disabled={loadingMore}>
                View more
              </button>
            </div>
          ) : null}
        </div>
      </div>
      <div className="hp-md__pane" ref={paneRef}>
        {open ? (
          <div className="card hp-md__rowcard">
            <button className="hp-md__close" type="button" aria-label="Close details" title="Close details" onClick={() => setSelected(null)}>
              ×
            </button>
            <h2>{inspectorTitle}</h2>
            {detailPage ? (
              <a className="btn btn-sm btn-secondary hp-flow" href={detailPage}>
                Open full details →
              </a>
            ) : null}
            {inspectorExtra ? <div className="hp-md__extra">{inspectorExtra(rows[selected])}</div> : null}
            <dl>
              {columns.map((column) => (
                <FieldPair key={column.header} label={column.header} value={column.render(rows[selected])} />
              ))}
            </dl>
          </div>
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
