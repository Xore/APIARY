// StoreListPage — one component behind every store-shaped page: fetches a
// /api/v1/store/{name} page through a server function, renders the shared
// master-detail kit with View-more + skeleton-first. Column definitions
// are the only per-page code.
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from './Investigate'

export type StoreRow = Record<string, unknown>
export type StorePage = { total: number; rows: StoreRow[] }

export function StoreListPage({
  fetchPage,
  label,
  title,
  subtitle,
  columns,
  rowKey,
  inspectorTitle,
  chipNoun,
  inspectorExtra,
}: {
  fetchPage: (input: { data: { offset: number } }) => Promise<StorePage | null>
  label: string
  title: string
  subtitle: string
  columns: Column<StoreRow>[]
  rowKey: (row: StoreRow, index: number) => string
  inspectorTitle?: string
  chipNoun: string
  inspectorExtra?: (row: StoreRow) => React.ReactNode
}) {
  const [rows, setRows] = useState<StoreRow[] | null>(null)
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
        chips={<span className="chip">{total.toLocaleString('en-US')} {chipNoun}</span>}
      />
      <MasterDetailTable
        rows={rows}
        columns={columns}
        rowKey={rowKey}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle={inspectorTitle}
        inspectorExtra={inspectorExtra}
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
  return iso.replace('T', ' ').slice(0, 19)
}
