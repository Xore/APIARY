// The investigate command palette — the "/" search over IPs, sessions,
// hashes, credentials, commands and signatures. Ports the Go shell's
// #hp-command-palette (partials/dashboard.html:181-191 + hp-app.js's
// palette block) on the theme's own modal contract — .modal-backdrop +
// .modal--palette, .command-palette__field (textarea: Enter submits,
// Shift+Enter adds a line, auto-grown to 120px), .command-palette__results
// listbox with ArrowUp/Down row cycling (the active row trades its group
// label for an "Enter" hint), focus restored to the opener on close.
// Grouped live results come from the Rust tier's /api/v1/search.
import { useNavigate } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'

type Hit = { label: string; count: number; url: string }
type Group = { title: string; hits: Hit[] }
type SearchResult = { query: string; redirect: string | null; groups: Group[]; total: number }
type Row = { title: string; group: string; url: string }

const searchFn = createServerFn({ method: 'GET' })
  .validator((input: { q: string }) => input)
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
  // #2178: a failed lookup collapsed into the same null as "not searched
  // yet", and the bottom line then presented ordinary guidance while the
  // backend was down. searchFailed names that state instead.
  const [searchFailed, setSearchFailed] = useState(false)
  const [activeRow, setActiveRow] = useState(-1)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const restoreFocusRef = useRef<Element | null>(null)
  const requestRef = useRef(0)
  const navigate = useNavigate()

  const close = useCallback(() => {
    setOpen(false)
    if (restoreFocusRef.current instanceof HTMLElement && restoreFocusRef.current.isConnected) {
      restoreFocusRef.current.focus()
    }
  }, [])

  useEffect(() => {
    const onOpen = () => {
      restoreFocusRef.current = document.activeElement
      setOpen(true)
    }
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as Element
      if (event.key === '/' && !target.closest('input, textarea, select, [contenteditable]')) {
        event.preventDefault()
        restoreFocusRef.current = document.activeElement
        setOpen(true)
      }
    }
    window.addEventListener('hp:palette', onOpen)
    document.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('hp:palette', onOpen)
      document.removeEventListener('keydown', onKey)
    }
  }, [])

  // Escape closes — bound only while open so the page underneath keeps
  // its own Escape semantics otherwise.
  useEffect(() => {
    if (!open) return
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        close()
      }
    }
    document.addEventListener('keydown', onEscape)
    return () => document.removeEventListener('keydown', onEscape)
  }, [open, close])

  useEffect(() => {
    if (open) inputRef.current?.focus()
    else {
      setQuery('')
      setResult(null)
      setSearchFailed(false)
      setActiveRow(-1)
    }
  }, [open])

  useEffect(() => {
    const trimmed = query.trim()
    if (!trimmed) {
      setResult(null)
      setSearchFailed(false)
      setActiveRow(-1)
      return
    }
    const request = ++requestRef.current
    const timer = setTimeout(() => {
      searchFn({ data: { q: trimmed } })
        .then((response) => {
          if (requestRef.current !== request) return
          // #2178: serviceJSON collapses every failure mode to null; flag it
          // rather than letting it read as guidance for an empty palette.
          setSearchFailed(response === null)
          setResult(response)
          setActiveRow(response && response.total > 0 ? 0 : -1)
        })
        .catch(() => {
          if (requestRef.current === request) {
            setSearchFailed(true)
            setResult(null)
            setActiveRow(-1)
          }
        })
    }, 200)
    return () => clearTimeout(timer)
  }, [query])

  const go = useCallback(
    (url: string) => {
      setOpen(false)
      if (!url.startsWith('/')) return
      const [path, queryString] = url.split('?')
      void navigate({
        to: path,
        search: queryString ? Object.fromEntries(new URLSearchParams(queryString)) : undefined,
      })
    },
    [navigate],
  )

  const rows: Row[] =
    result?.groups.flatMap((group) =>
      group.hits.map((hit) => ({ title: hit.label, group: group.title, url: hit.url })),
    ) ?? []

  const submit = () => {
    if (activeRow >= 0 && rows[activeRow]) {
      go(rows[activeRow].url)
      return
    }
    if (result?.redirect) go(result.redirect)
    else if (query.trim()) go(`/search?q=${encodeURIComponent(query.trim())}`)
  }

  const onFieldKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'ArrowDown' && rows.length) {
      event.preventDefault()
      setActiveRow((row) => Math.min(row + 1, rows.length - 1))
      return
    }
    if (event.key === 'ArrowUp' && rows.length) {
      event.preventDefault()
      setActiveRow((row) => Math.max(row - 1, -1))
      return
    }
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      submit()
    }
  }

  // Auto-grow the textarea to 120px, same as hp-app.js resizeSearch.
  const resize = () => {
    const field = inputRef.current
    if (!field) return
    field.style.height = 'auto'
    field.style.height = `${Math.min(120, field.scrollHeight)}px`
  }

  if (!open) return null
  return (
    <>
      <div className="modal-backdrop open" aria-hidden="true" onClick={close} />
      <section className="modal modal--palette open" role="dialog" aria-modal="true" aria-label="Investigate an indicator">
        <form
          className="command-palette__field"
          role="search"
          onSubmit={(event) => {
            event.preventDefault()
            submit()
          }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <textarea
            ref={inputRef}
            rows={1}
            placeholder="Investigate an IP, ASN, payload hash, session, HTTP path or free text…"
            aria-label="Investigate an indicator"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value)
              resize()
            }}
            onKeyDown={onFieldKeyDown}
          />
          <button className="modal__close" type="button" aria-label="Close" onClick={close}>
            ✕
          </button>
        </form>
        {rows.length > 0 ? (
          <div className="command-palette__results" role="listbox" aria-label="Search results">
            {rows.map((row, index) => {
              const active = index === activeRow
              return (
                <button
                  key={`${row.group}:${row.title}:${index}`}
                  type="button"
                  className={active ? 'command-palette__row active' : 'command-palette__row'}
                  role="option"
                  aria-selected={active}
                  onClick={() => go(row.url)}
                  onMouseEnter={() => setActiveRow(index)}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <polyline points="16 18 22 12 16 6" />
                    <polyline points="8 6 2 12 8 18" />
                  </svg>
                  <span className="command-palette__row-title">{row.title}</span>
                  <span className="command-palette__row-meta">{active ? 'Enter' : row.group}</span>
                </button>
              )
            })}
          </div>
        ) : (
          <p className="command-palette__empty">
            {searchFailed
              ? 'The search request failed — the backend may be down or shedding load. Enter still opens a full /search for this query.'
              : result && result.total === 0
                ? 'No matches in the current window.'
                : 'Press Enter to open an investigation for this query.'}
          </p>
        )}
      </section>
    </>
  )
}
