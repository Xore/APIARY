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

  useEffect(() => {
    let cancelled = false
    first.then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
    })
    return () => {
      cancelled = true
    }
  }, [first])

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

  return { rows, setRows, total, setTotal, loadingMore, viewMore }
}
