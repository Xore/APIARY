import { useEffect, useState } from 'react'

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
