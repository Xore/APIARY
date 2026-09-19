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
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogTitle } from './ui/dialog'

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
    <Button variant={activeCount > 0 ? 'default' : 'outline'} size="sm" className={activeCount > 0 ? 'chip is-active' : 'chip'} type="button" onClick={onClick}>
      Filters{activeCount > 0 ? ` (${activeCount})` : ''}
    </Button>
  )
}

export function FiltersModal({
  title = 'Filters',
  open,
  onClose,
  onApply,
  onClear,
  clearDisabled,
  children,
}: {
  title?: string
  open: boolean
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

  useEffect(() => {
    if (open) closeRef.current?.focus()
  }, [open])

  return (
    <Dialog open={open} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogTitle>{title}</DialogTitle>
        <form
          className="settings-grid"
          onSubmit={(event) => {
            event.preventDefault()
            onApply(event)
          }}
        >
          {children}
          <div className="hp-row hp-flow--tight">
            <Button variant="default" size="default" type="submit">
              Apply filters
            </Button>
            <Button variant="secondary" size="default" type="button" disabled={clearDisabled} onClick={onClear}>
              Clear all
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
