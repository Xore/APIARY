// Sidebar view-tabs (design pick 7D) — the React port of hp-app.js's
// sidebar view-tabs IIFE (hp-app.js:1990-2066). A page's MAIN view tablist
// relocates into the sidebar rail, nesting directly under the active nav
// item, so switching a page's views reads the same as switching pages.
// Component-level tablists (row inspectors, detail sub-tabs — the Go
// tier's data-hp-tabs-inline class of tabs) never use this module.
//
// Mechanism: a useSyncExternalStore registry. A page calls
// useSidebarViewTabs({tabs, active, onSelect, ...}) — the hook registers
// the config on mount (and keeps it fresh on every render) and
// unregisters on unmount/navigation. Sidebar.tsx renders
// <SidebarViewTabs /> below the active nav item: the ".hp-views-label"
// 'Views' label plus a .tabs[data-hp-sidebar-tabs] tablist (theme.css's
// .app-sidebar .tabs vocabulary, theme.css:3269-3288).
//
// #1576 semantics preserved: below 520px the sidebar itself goes
// off-canvas (theme.css's own breakpoint), so relocating the tabs there
// would hide them behind the hamburger drawer. At that width the hook
// renders the tablist INLINE in the content flow instead, and the rail
// stays empty — never both. The inline strip also renders pre-hydration,
// matching the Go tier's no-JS fallback (server HTML keeps the stock
// horizontal tabs; JS moves them into the rail).
import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'

export type ViewTabDef = { id: string; label: string }

export type ViewTabsConfig = {
  /** Accessible name for the tablist. */
  label: string
  tabs: readonly ViewTabDef[]
  active: string
  onSelect: (id: string) => void
  /** Prefix for tab/panel element ids — must match the page's TabPanel ids. */
  idPrefix: string
}

type Registration = { config: ViewTabsConfig; owner: object }

// ── Registry ─────────────────────────────────────────────────────────────
let registration: Registration | null = null
const listeners = new Set<() => void>()

function emit() {
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

const getSnapshot = () => registration
const getServerSnapshot = () => null

function useRegistration(): Registration | null {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot)
}

// ── 520px breakpoint (theme.css's off-canvas sidebar threshold) ─────────
let narrowQuery: MediaQueryList | null = null
function getNarrowQuery(): MediaQueryList {
  narrowQuery ??= window.matchMedia('(max-width: 520px)')
  return narrowQuery
}

function subscribeNarrow(listener: () => void) {
  const query = getNarrowQuery()
  query.addEventListener('change', listener)
  return () => query.removeEventListener('change', listener)
}

export function useNarrowViewport(): boolean {
  return useSyncExternalStore(subscribeNarrow, () => getNarrowQuery().matches, () => false)
}

// ── Tablist renderer ─────────────────────────────────────────────────────
// The .tabs/.tab markup shape the Go pages render (numbered <span>NN</span>
// pills), with the full tablist keyboard semantics from Tabs.tsx's
// onKeyDown pattern (hp-app.js:1131-1148's roving tabIndex + arrow cycler).
function ViewTabList({ config, sidebar }: { config: ViewTabsConfig; sidebar?: boolean }) {
  const listRef = useRef<HTMLDivElement>(null)
  const { tabs, active, onSelect, idPrefix } = config

  const focusAndSelect = (index: number) => {
    const tab = tabs[(index + tabs.length) % tabs.length]
    onSelect(tab.id)
    listRef.current
      ?.querySelector<HTMLButtonElement>(`#${CSS.escape(`${idPrefix}-${tab.id}`)}`)
      ?.focus()
  }

  const onKeyDown = (event: React.KeyboardEvent, index: number) => {
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        event.preventDefault()
        focusAndSelect(index + 1)
        break
      case 'ArrowLeft':
      case 'ArrowUp':
        event.preventDefault()
        focusAndSelect(index - 1)
        break
      case 'Home':
        event.preventDefault()
        focusAndSelect(0)
        break
      case 'End':
        event.preventDefault()
        focusAndSelect(tabs.length - 1)
        break
    }
  }

  return (
    <div
      ref={listRef}
      className="tabs"
      role="tablist"
      aria-label={config.label}
      {...(sidebar ? { 'data-hp-sidebar-tabs': '1' } : null)}
    >
      {tabs.map((tab, index) => {
        const selected = tab.id === active
        return (
          <button
            key={tab.id}
            id={`${idPrefix}-${tab.id}`}
            className={selected ? 'tab active' : 'tab'}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel-${tab.id}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onSelect(tab.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
          >
            <span>{String(index + 1).padStart(2, '0')}</span>
            {tab.label}
          </button>
        )
      })}
    </div>
  )
}

// ── Page-side hook ───────────────────────────────────────────────────────
/** Register a page's main view tabs for sidebar relocation. Returns the
 * inline tab strip to render in the content flow — non-null only below
 * 520px (off-canvas sidebar, #1576) or pre-hydration (the no-JS
 * fallback); otherwise the tabs live in the sidebar rail and this
 * returns null. Render the result exactly where the inline strip
 * belongs. */
export function useSidebarViewTabs({
  label,
  tabs,
  active,
  onSelect,
  idPrefix = 'view',
}: {
  label: string
  tabs: readonly ViewTabDef[]
  active: string
  onSelect: (id: string) => void
  idPrefix?: string
}): ReactNode {
  const owner = useRef<object | null>(null)
  owner.current ??= {}
  const narrow = useNarrowViewport()
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])

  const inline = narrow || !mounted
  const config: ViewTabsConfig = { label, tabs, active, onSelect, idPrefix }

  // Re-register on every commit so the rail always reflects the freshest
  // active/onSelect. Shrinking below 520px sweeps this page's rail out of
  // the sidebar (never inline + rail at once — hp-app.js:2035).
  useEffect(() => {
    const token = owner.current as object
    if (inline) {
      if (registration?.owner === token) {
        registration = null
        emit()
      }
      return
    }
    registration = { config, owner: token }
    emit()
  })

  // Navigation/unmount clears only this page's own registration — a new
  // page may already have replaced it (its effect can run first).
  useEffect(() => {
    const token = owner.current as object
    return () => {
      if (registration?.owner === token) {
        registration = null
        emit()
      }
    }
  }, [])

  return inline ? <ViewTabList config={config} /> : null
}

// ── Sidebar-side renderer ────────────────────────────────────────────────
/** The relocated rail: 'Views' label + tablist, rendered by Sidebar.tsx
 * directly below the active nav item. Null when no page registered tabs
 * or the viewport is narrow (the page renders them inline instead). */
export function SidebarViewTabs() {
  const entry = useRegistration()
  const narrow = useNarrowViewport()
  const ref = useRef<HTMLDivElement>(null)
  const pageLabel = entry?.config.label

  // Keep the rail where the operator actually is: scroll the active item's
  // nested view tabs into view on every page change (hp-app.js's reveal()).
  useEffect(() => {
    if (pageLabel) ref.current?.scrollIntoView({ block: 'nearest' })
  }, [pageLabel])

  if (!entry || narrow) return null
  return (
    <div ref={ref}>
      <div className="sidebar__section-label hp-views-label">Views</div>
      <ViewTabList config={entry.config} sidebar />
    </div>
  )
}
