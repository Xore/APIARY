import { useCallback, useEffect, useState } from 'react'

// The three states a data load can actually be in (#1966). Before this the
// hook could only say null-or-value, so a failed fetch and a slow fetch
// rendered identically -- an endless skeleton -- and a rejection wasn't
// even caught; it was an unhandled promise rejection while the UI kept
// promising data.
export type ServerQuery<T> =
  | { status: 'loading'; data: null }
  | { status: 'error'; data: null }
  | { status: 'ready'; data: T }

/** Re-invokes a TanStack Start server function whenever `deps` changes,
 * resetting to loading while the new fetch is in flight and ignoring a
 * result that resolves after the component has moved on to newer deps.
 *
 * A resolved `null` is treated as the failure it almost always is (#1966):
 * server functions built on serviceJSON collapse every error mode to null,
 * so by the time a null arrives here there is no meaningful difference
 * between "the endpoint had nothing" and "the backend is down" -- and the
 * former belongs in a server function's own empty state, not in a skeleton
 * that never resolves. Endpoints whose empty answer is genuinely null
 * should wrap their payload (e.g. `{ rows: [] }`) so emptiness stays
 * distinguishable from failure. Rejections map to the same error state;
 * before #1966 they were simply unhandled.
 *
 * `retry` re-runs the last fetch with unchanged deps -- the mechanism
 * behind every Retry button this state feeds. */
export function useServerQuery<T, D>(
  fetchFn: (opts: { data: D }) => Promise<T | null>,
  data: D,
  deps: unknown[],
): ServerQuery<T> & { retry: () => void } {
  const [state, setState] = useState<ServerQuery<T>>({ status: 'loading', data: null })
  // Bumping the nonce re-runs the effect without touching deps.
  const [attempt, setAttempt] = useState(0)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    setState({ status: 'loading', data: null })
    fetchFn({ data })
      .then((value) => {
        if (cancelled) return
        if (value === null || value === undefined) setState({ status: 'error', data: null })
        else setState({ status: 'ready', data: value })
      })
      .catch(() => {
        if (!cancelled) setState({ status: 'error', data: null })
      })
    return () => {
      cancelled = true
    }
    // Deps are caller-owned, as documented; `attempt` rides along so retry()
    // re-runs the same fetch. React compares dep arrays element-wise, so the
    // fresh array literal here costs nothing.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned dep list
  }, [...deps, attempt])

  return { ...state, retry }
}
