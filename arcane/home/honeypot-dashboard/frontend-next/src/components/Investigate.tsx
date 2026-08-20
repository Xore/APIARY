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

export function MasterDetailTable<Row>({
  rows,
  columns,
  rowKey,
  total,
  onViewMore,
  loadingMore,
  inspectorTitle = 'Row details',
  inspectorExtra,
}: {
  rows: Row[] | null
  columns: Column<Row>[]
  rowKey: (row: Row, index: number) => string
  total?: number
  onViewMore?: () => void
  loadingMore?: boolean
  inspectorTitle?: string
  inspectorExtra?: (row: Row) => React.ReactNode
}) {
  const [selected, setSelected] = useState<number | null>(null)
  const paneRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const listColumns = columns.filter((column) => !column.detail)

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
  return (
    <div className={open ? 'hp-md hp-md--active hp-md--open wide' : 'hp-md hp-md--active wide'}>
      <div className="hp-md__list" ref={listRef}>
        <div className="card wide">
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
                  <tr
                    key={rowKey(row, index)}
                    className={selected === index ? 'selected' : undefined}
                    onClick={(event) => {
                      if ((event.target as Element).closest('a, button, details, summary, input, label')) return
                      setSelected(selected === index ? null : index)
                    }}
                  >
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
