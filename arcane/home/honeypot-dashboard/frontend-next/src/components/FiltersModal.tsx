// A single "Filters" button + settings-style popup, reused across every
// list page that has more than one or two narrowing fields (#1682) —
// events.tsx and ml-anomalies.tsx today. Replaces an inline row of
// selects/inputs (which pushed every list page's toolbar wider as more
// fields got added, and applied each field's change immediately, one
// navigation per keystroke on a select) with one button, a field count
// badge, and a form that batches every change into a single "Apply" —
// same focus-trap/backdrop/Escape contract as the report-PDF viewers
// (payload-analysis.$hash.tsx's PayloadReportViewer, github-analysis's
// ReportViewer, reports.tsx's ReportViewerModal), factored out here since
// this is now the fourth call site for the identical modal chrome.
import { useEffect, useRef } from 'react'

export function FiltersButton({
  activeCount,
  onClick,
}: {
  /** Number of fields currently narrowing the list — 0 renders a plain
   * "Filters" chip, >0 shows the count so the operator can see at a
   * glance that the list isn't showing everything. */
  activeCount: number
  onClick: () => void
}) {
  return (
    <button className={activeCount > 0 ? 'chip is-active' : 'chip'} type="button" onClick={onClick}>
      Filters{activeCount > 0 ? ` (${activeCount})` : ''}
    </button>
  )
}

export function FiltersModal({
  title = 'Filters',
  onClose,
  onApply,
  onClear,
  clearDisabled,
  children,
}: {
  title?: string
  onClose: () => void
  /** Commits every field's draft value in one navigation. Fields are
   * uncontrolled (defaultValue from current search state) — read them
   * off `event.currentTarget` via FormData, same pattern the rest of
   * this codebase already uses for its search/blur-committed inputs. */
  onApply: (event: React.FormEvent<HTMLFormElement>) => void
  /** Resets every field to its default (no scope) in one navigation. */
  onClear: () => void
  clearDisabled?: boolean
  children: React.ReactNode
}) {
  const closeRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLElement>(null)

  useEffect(() => {
    const previous = document.activeElement
    closeRef.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key !== 'Tab' || !panelRef.current) return
      const focusables = panelRef.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled])',
      )
      if (!focusables.length) return
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus()
    }
  }, [onClose])

  return (
    <>
      <div className="modal-backdrop open" aria-hidden="true" onClick={onClose} />
      <section
        className="modal open"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={panelRef}
        style={{ width: 'min(560px, calc(100vw - 40px))', height: 'auto', maxHeight: 'min(680px, calc(100dvh - 40px))', overflowY: 'auto' }}
      >
        <div className="modal__header">
          <h2>{title}</h2>
          <button className="modal__close" type="button" aria-label="Close filters" onClick={onClose} ref={closeRef}>
            ✕
          </button>
        </div>
        <form
          className="settings-grid"
          onSubmit={(event) => {
            event.preventDefault()
            onApply(event)
          }}
        >
          {children}
          <div className="hp-row hp-flow--tight">
            <button className="btn btn-primary" type="submit">
              Apply filters
            </button>
            <button className="btn btn-secondary" type="button" disabled={clearDisabled} onClick={onClear}>
              Clear all
            </button>
          </div>
        </form>
      </section>
    </>
  )
}
