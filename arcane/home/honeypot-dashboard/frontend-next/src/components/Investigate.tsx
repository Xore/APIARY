// Shared Investigate primitives: page header, and the generic
// master-detail table — full-width list, click-open "Row details"
// inspector (outside-click + × close), skeleton-first first paint.
// Mirrors the legacy generic inspector's semantics 1:1.
import { useEffect, useRef, useState } from 'react'

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

export function SkeletonRows({ count, cols }: { count: number; cols: number }) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <tr key={`skel-${i}`} className="hp-skel-batch" aria-hidden="true">
          <td colSpan={cols}>
            <span className="skeleton-line" />
          </td>
        </tr>
      ))}
    </>
  )
}

export function SkeletonCards({ count }: { count: number }) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <div key={`skel-${i}`} className="project-card" aria-hidden="true">
          <span className="skeleton-line" />
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
}) {
  const [selected, setSelected] = useState<number | null>(null)
  const paneRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const listColumns = columns.filter((column) => !column.detail)
  const primaryColumn = columns.find((column) => column.primary) ?? listColumns[0]
  const metaColumns = listColumns.filter((column) => column !== primaryColumn)

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
                <SkeletonCards count={12} />
              ) : (
                rows.map((row, index) => {
                  const href = cardHref?.(row)
                  const CardTag = href ? 'a' : 'div'
                  const cardProps = href ? { href } : { onClick: onRowClick(index) }
                  return (
                    <CardTag key={rowKey(row, index)} className="project-card" {...cardProps}>
                      <div className="project-card__header">
                        <span className="project-card__title">{primaryColumn?.render(row)}</span>
                      </div>
                      {metaColumns.length > 0 ? (
                        <div className="project-card__meta tw:flex-wrap">
                          {metaColumns.map((column) => (
                            <span key={column.header}>{column.render(row)}</span>
                          ))}
                        </div>
                      ) : null}
                    </CardTag>
                  )
                })
              )}
              {loadingMore ? <SkeletonCards count={4} /> : null}
            </div>
          ) : (
            <table className="recent data-table">
              <thead>
                <tr>
                  {listColumns.map((column) => (
                    <th key={column.header}>{column.header}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows === null ? (
                  <SkeletonRows count={12} cols={listColumns.length} />
                ) : (
                  rows.map((row, index) => (
                    <tr key={rowKey(row, index)} className={selected === index ? 'selected' : undefined} onClick={onRowClick(index)}>
                      {listColumns.map((column) => (
                        <td key={column.header} className={column.className}>
                          {column.render(row)}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
                {loadingMore ? <SkeletonRows count={5} cols={listColumns.length} /> : null}
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
