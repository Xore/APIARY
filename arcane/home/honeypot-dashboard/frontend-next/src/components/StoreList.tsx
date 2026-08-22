// StoreListPage — one component behind every store-shaped page: fetches a
// /api/v1/store/{name} page through a server function, renders the shared
// master-detail kit with View-more + skeleton-first. Column definitions
// are the only per-page code.
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from './Investigate'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'

export type StoreRow = JsonRecord
export type StorePage<Row = StoreRow> = { total: number; rows: Row[] }

export function StoreListPage<Row = StoreRow>({
  fetchPage,
  label,
  title,
  subtitle,
  columns,
  rowKey,
  inspectorTitle,
  chipNoun,
  inspectorExtra,
  beforeTable,
  extraChips,
  layout,
  gridId,
  cardHref,
}: {
  fetchPage: (input: { data: { offset: number } }) => Promise<StorePage<Row> | null>
  label: string
  title: string
  subtitle: string
  columns: Column<Row>[]
  rowKey: (row: Row, index: number) => string
  inspectorTitle?: string
  chipNoun: string
  inspectorExtra?: (row: Row) => React.ReactNode
  /** Rendered between the header and the table — KPI tile rows,
   * aggregation cards, filter bars (#1653 fidelity restorations). */
  beforeTable?: React.ReactNode
  /** Extra chips next to the running-total chip. */
  extraChips?: React.ReactNode
  /** 'cards' renders a .project-card grid (theme.css's result-surface
   * pattern) instead of the default data-table. */
  layout?: 'table' | 'cards'
  /** `layout="cards"` only: id on the `.project-grid` container. */
  gridId?: string
  /** `layout="cards"` only: makes the whole card a link to a row's detail
   * page instead of opening the inspector. See MasterDetailTable's own
   * doc comment. */
  cardHref?: (row: Row) => string | undefined
}) {
  const [rows, setRows] = useState<Row[] | null>(null)
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
    // eslint-disable-next-line react-hooks/exhaustive-deps -- stable server fn
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
  }, [rows, loadingMore, fetchPage])

  return (
    <>
      <InvestigateHeader
        label={label}
        title={title}
        subtitle={subtitle}
        chips={
          <>
            <span className="chip">{total.toLocaleString('en-US')} {chipNoun}</span>
            {extraChips}
          </>
        }
      />
      {beforeTable}
      <MasterDetailTable
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle={inspectorTitle}
        inspectorExtra={inspectorExtra}
        layout={layout}
        gridId={gridId}
        cardHref={cardHref}
      />
    </>
  )
}

export function str(row: StoreRow, key: string): string {
  const value = row[key]
  return value === null || value === undefined ? '' : String(value)
}

export function num(row: StoreRow, key: string): number {
  const value = row[key]
  return typeof value === 'number' ? value : 0
}

export function when(iso: string): string {
  return formatTimestamp(iso)
}

// The promoted top-level file.hash.sha256 es_importer.rs writes onto every
// cape/github-analysis document alongside its wrapped source payload.
export function sha256Of(row: StoreRow): string {
  const file = row.file as StoreRow | undefined
  const hash = file?.hash as StoreRow | undefined
  return typeof hash?.sha256 === 'string' ? hash.sha256 : ''
}
