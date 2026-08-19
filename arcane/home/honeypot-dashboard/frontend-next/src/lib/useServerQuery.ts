import { useEffect, useState } from 'react'

// Re-invokes a TanStack Start server function whenever `deps` changes,
// resetting to null while the new fetch is in flight and ignoring a
// result that resolves after the component has moved on to newer deps.
export function useServerQuery<T, D>(fetchFn: (opts: { data: D }) => Promise<T>, data: D, deps: unknown[]): T | null {
  const [result, setResult] = useState<T | null>(null)

  useEffect(() => {
    let cancelled = false
    setResult(null)
    fetchFn({ data }).then((value) => {
      if (!cancelled) setResult(value)
    })
    return () => {
      cancelled = true
    }
  }, deps)

  return result
}
