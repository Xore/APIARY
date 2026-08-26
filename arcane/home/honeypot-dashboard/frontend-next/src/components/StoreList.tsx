// StoreListPage — one component behind every store-shaped page: fetches a
// /api/v1/store/{name} page through a server function, renders the shared
// master-detail kit with View-more + skeleton-first. Column definitions
// are the only per-page code.
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column, type EmptyState } from './Investigate'
import { ErrorStateBlock } from './ErrorState'
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
  detailHref,
  cardIcon,
  cardBadges,
  cardDesc,
  emptyReplacement,
  emptyState,
  pageSize,
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
  /** Rendered *instead of* the whole table once the first page has loaded
   * and came back with zero rows — a template gallery / call-to-action
   * rather than a bare empty table (#1575's empty-state pattern). Only
   * for surfaces that have something better to offer than a sentence;
   * everything else wants `emptyState` below. */
  emptyReplacement?: React.ReactNode
  /** The in-table "nothing matched" sentence. See MasterDetailTable. */
  emptyState?: EmptyState
  /** The fetch page size, forwarded so the first-load ghosts preview one
   * full page instead of a hardcoded dozen (#1967). All store surfaces
   * page at 25 today, so callers pass what their server fn requests. */
  pageSize?: number
  /** `layout="cards"` only: the icon, badge row and description the legacy
   * result cards carried. See MasterDetailTable's own doc comment. */
  /** Adds an "Open full details" action to the row inspector. See
   * MasterDetailTable's own doc comment. */
  detailHref?: (row: Row) => string | undefined
  cardIcon?: (row: Row) => React.ReactNode
  cardBadges?: (row: Row) => React.ReactNode
  cardDesc?: (row: Row) => React.ReactNode
}) {
  const [rows, setRows] = useState<Row[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  // #2178: a failed View-more page used to vanish -- rows just stayed short
  // while the header still promised the full total. Named below the table.
  const [moreFailed, setMoreFailed] = useState(false)
  // #1966: the server function collapses every failure mode to a null page,
  // so a first fetch that resolves null while rows is still null can only be
  // a failure -- a success always calls setRows. That used to leave the
  // opening skeleton up forever; now it names itself and offers a retry.
  const [failed, setFailed] = useState(false)
  // Bumping this re-runs the first-page effect without changing anything else.
  const [attempt, setAttempt] = useState(0)
  const retryFirstPage = useCallback(() => {
    setFailed(false)
    setAttempt((n) => n + 1)
  }, [])

  useEffect(() => {
    let cancelled = false
    fetchPage({ data: { offset: 0 } }).then((page) => {
      if (cancelled) return
      if (!page) {
        setFailed(true)
        return
      }
      setRows(page.rows)
      setTotal(page.total)
    }).catch(() => {
      if (!cancelled) setFailed(true)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- stable server fn
  }, [attempt])

  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    setMoreFailed(false)
    try {
      const page = await fetchPage({ data: { offset: rows.length } })
      // #2178: a null page here is a failed read, not the end of the list.
      if (page) {
        setRows((current) => [...(current ?? []), ...page.rows])
      } else {
        setMoreFailed(true)
      }
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
      {failed && rows === null ? (
        <ErrorStateBlock
          title="This list failed to load"
          hint="The backend request failed — the service may be down or shedding load. Nothing here is cached."
          onRetry={retryFirstPage}
        />
      ) : (
        <>
          {beforeTable}
          {emptyReplacement && rows !== null && rows.length === 0 ? (
            emptyReplacement
          ) : (
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
              detailHref={detailHref}
              cardIcon={cardIcon}
              cardBadges={cardBadges}
              cardDesc={cardDesc}
              emptyState={emptyState}
              pageSize={pageSize}
            />
          )}
          {moreFailed ? (
            /* #2178: the click succeeded from the UI's point of view while
               the read behind it failed -- say so instead of a no-op. */
            <p className="note" role="alert">
              Loading more {chipNoun} failed — <button className="copy" type="button" onClick={() => void viewMore()}>retry</button>
            </p>
          ) : null}
        </>
      )}
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
