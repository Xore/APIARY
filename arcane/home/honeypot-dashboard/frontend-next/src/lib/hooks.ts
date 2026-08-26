import { useCallback, useEffect, useState } from 'react'

// Resolves a promise into state, returning undefined until it settles and
// ignoring a result that arrives after the component has moved on to a new
// promise (e.g. a route param changed mid-flight).
export function useResolved<T>(promise: Promise<T>): T | undefined {
  const [value, setValue] = useState<T | undefined>(undefined)
  useEffect(() => {
    let cancelled = false
    setValue(undefined)
    promise.then((result) => {
      if (!cancelled) setValue(result)
    })
    return () => {
      cancelled = true
    }
  }, [promise])
  return value
}

// Shared "resolve a loader promise into rows/total, then view-more via an
// offset-based re-fetch" page state behind ips.tsx/commands.tsx/
// attackers.tsx/alerts.tsx. Callers with a differently-shaped page object
// (e.g. ips.tsx's SourcesPage.total_unique) adapt it to {total, rows}
// before passing it in.
export function usePaginatedList<T>(
  first: Promise<{ total: number; rows: T[] } | null>,
  fetchMore: (offset: number) => Promise<{ total: number; rows: T[] } | null>,
) {
  const [rows, setRows] = useState<T[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  // #2178: the first page resolves null for every failure mode once
  // serviceJSON collapses statuses -- indistinguishable from "never
  // settled", so every consumer of this hook sat in its opening ghosts
  // forever. failed names that case so pages can render an error block;
  // retry() bumps attempt to re-fetch page zero.
  const [failed, setFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    setRows(null)
    setTotal(0)
    setFailed(false)
    // attempt === 0 honours the streamed loader promise it was handed; a
    // retry cannot re-run that stream, so it re-fetches page zero through
    // the ordinary paging fn instead.
    ;(attempt === 0 ? first : fetchMore(0))
      .then((page) => {
        if (cancelled) return
        if (!page) {
          setFailed(true)
          return
        }
        setRows(page.rows)
        setTotal(page.total)
      })
      .catch(() => {
        if (!cancelled) setFailed(true)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned first/fetchMore pair
  }, [first, attempt])

  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchMore(rows.length)
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore, fetchMore])

  return { rows, setRows, total, setTotal, loadingMore, viewMore, failed, retry }
}
