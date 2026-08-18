// The investigate command palette — the "/" search over IPs, sessions,
// hashes, credentials, commands and signatures. Opens on "/" (outside
// inputs) or via openCommandPalette(); grouped live results come from
// the Rust tier's /api/v1/search through a server function.
import { useNavigate } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'

type Hit = { label: string; count: number; url: string }
type Group = { title: string; hits: Hit[] }
type SearchResult = { query: string; redirect: string | null; groups: Group[]; total: number }

const searchFn = createServerFn({ method: 'GET' })
  .inputValidator((input: { q: string }) => input)
  .handler(async ({ data }): Promise<SearchResult | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<SearchResult>(`/api/v1/search?q=${encodeURIComponent(data.q)}`)
  })

export function openCommandPalette() {
  window.dispatchEvent(new CustomEvent('hp:palette'))
}

export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<SearchResult | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const requestRef = useRef(0)
  const navigate = useNavigate()

  useEffect(() => {
    const onOpen = () => setOpen(true)
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as Element
      if (event.key === '/' && !target.closest('input, textarea, select, [contenteditable]')) {
        event.preventDefault()
        setOpen(true)
      }
      if (event.key === 'Escape') setOpen(false)
    }
    window.addEventListener('hp:palette', onOpen)
    document.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('hp:palette', onOpen)
      document.removeEventListener('keydown', onKey)
    }
  }, [])

  useEffect(() => {
    if (open) inputRef.current?.focus()
    else {
      setQuery('')
      setResult(null)
    }
  }, [open])

  useEffect(() => {
    const trimmed = query.trim()
    if (!trimmed) {
      setResult(null)
      return
    }
    const request = ++requestRef.current
    const timer = setTimeout(() => {
      searchFn({ data: { q: trimmed } }).then((response) => {
        if (requestRef.current === request) setResult(response)
      })
    }, 200)
    return () => clearTimeout(timer)
  }, [query])

  const go = useCallback(
    (url: string) => {
      setOpen(false)
      if (url.startsWith('/')) void navigate({ to: url })
    },
    [navigate],
  )

  if (!open) return null
  return (
    <div
      className="hp-palette-overlay"
      style={{ position: 'fixed', inset: 0, zIndex: 90, background: 'color-mix(in srgb, var(--bg) 55%, transparent)', display: 'grid', justifyItems: 'center', alignItems: 'start', paddingTop: '12vh' }}
      onClick={(event) => {
        if (event.target === event.currentTarget) setOpen(false)
      }}
    >
      <div className="card" role="dialog" aria-label="Investigate search" style={{ width: 'min(640px, 92vw)', maxHeight: '70vh', overflow: 'auto' }}>
        <form
          onSubmit={(event) => {
            event.preventDefault()
            if (result?.redirect) go(result.redirect)
            else if (result?.groups[0]?.hits[0]) go(result.groups[0].hits[0].url)
          }}
        >
          <input
            ref={inputRef}
            className="input"
            style={{ width: '100%' }}
            type="search"
            placeholder="Investigate anything — IP, session, hash, credential, country…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            aria-label="Search query"
          />
        </form>
        {result === null && query.trim() ? <p className="note">Searching…</p> : null}
        {result && result.total === 0 ? <p className="empty">No matches in the current window.</p> : null}
        {result?.redirect ? (
          <button className="btn btn-secondary btn-sm" type="button" onClick={() => go(result.redirect!)} style={{ marginTop: 8 }}>
            Open exact match ↵
          </button>
        ) : null}
        {result?.groups.map((group) => (
          <div key={group.title}>
            <div className="label-section" style={{ marginTop: 12 }}>{group.title}</div>
            {group.hits.map((hit) => (
              <button
                key={`${group.title}-${hit.label}`}
                type="button"
                className="hp-palette-hit"
                style={{ display: 'flex', width: '100%', justifyContent: 'space-between', gap: 12, padding: '6px 8px', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-primary)', textAlign: 'left' }}
                onClick={() => go(hit.url)}
              >
                <code style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{hit.label}</code>
                <span className="badge badge--muted">{hit.count.toLocaleString('en-US')}</span>
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}
