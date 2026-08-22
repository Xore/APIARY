// Accessible tab strip — the port of hp-app.js's dashboard-tab handling
// (activateDashboardTab's roving tabIndex + the Arrow/Home/End keydown
// cycler at hp-app.js:1131-1148) as a reusable component, so every page
// that lost its tablist in the port gets the full semantics back:
// aria-controls/id linkage, roving focus, arrow-key cycling. Markup
// speaks theme.css's .segmented vocabulary by default; pass className to
// use a page's own tab-strip class instead.
import { useRef } from 'react'

export type TabDef = { id: string; label: React.ReactNode }

export function Tabs({
  tabs,
  active,
  onSelect,
  label,
  className = 'segmented',
  idPrefix = 'tab',
}: {
  tabs: TabDef[]
  active: string
  onSelect: (id: string) => void
  /** Accessible name for the tablist. */
  label: string
  className?: string
  /** Prefix for tab/panel element ids — must match TabPanel's. */
  idPrefix?: string
}) {
  const listRef = useRef<HTMLDivElement>(null)

  const focusAndSelect = (index: number) => {
    const tab = tabs[(index + tabs.length) % tabs.length]
    onSelect(tab.id)
    listRef.current
      ?.querySelector<HTMLButtonElement>(`#${idPrefix}-${CSS.escape(tab.id)}`)
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
    <div ref={listRef} className={className} role="tablist" aria-label={label}>
      {tabs.map((tab, index) => {
        const selected = tab.id === active
        return (
          <button
            key={tab.id}
            id={`${idPrefix}-${tab.id}`}
            // theme.css's segmented active state is `button.active`
            // (theme.css:1354), not is-active.
            className={selected ? 'active' : undefined}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel-${tab.id}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onSelect(tab.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
          >
            {tab.label}
          </button>
        )
      })}
    </div>
  )
}

export function TabPanel({
  id,
  active,
  idPrefix = 'tab',
  children,
  className,
}: {
  id: string
  active: string
  idPrefix?: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <div
      id={`${idPrefix}-panel-${id}`}
      role="tabpanel"
      aria-labelledby={`${idPrefix}-${id}`}
      hidden={id !== active}
      className={className}
    >
      {children}
    </div>
  )
}
