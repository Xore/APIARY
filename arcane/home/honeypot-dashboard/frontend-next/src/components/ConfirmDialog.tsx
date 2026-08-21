// Consequential-action confirmation dialog — the port of hp-modals.js's
// HoneypotModals.confirm (the one confirm surface the Go dashboard used
// for sandbox detonation, bulk alert acknowledgment, CSV export scope and
// every settings mutation). Same theme.css markup contract
// (.edit-dialog-backdrop / .edit-dialog / .danger-dialog__warning,
// partials/dashboard.html:192-202) and the same behavioral contract:
//  - onConfirm may be async; while it runs the confirm button reads
//    "Working…" and the dialog refuses to dismiss;
//  - a rejected onConfirm keeps the dialog open with "Try again" and
//    announces the error in the flash region;
//  - a resolved string is announced as the success message;
//  - Escape and backdrop click cancel (only while not running), Enter
//    confirms, focus is trapped inside and restored to the trigger.
import { useCallback, useEffect, useRef, useState } from 'react'
import { flash } from '../lib/flash'

export type ConfirmOptions = {
  title: string
  description?: string
  /** Consequence line, visually distinct from the description. */
  warning?: string
  confirmLabel?: string
  /** danger: false renders the confirm as btn-primary (e.g. CSV export). */
  danger?: boolean
  /** Runs on confirm; a resolved string is flashed as the outcome. */
  onConfirm: () => void | string | Promise<void | string>
}

const CONFIRM_EVENT = 'hp:confirm'

/** Open the shared confirmation dialog. Call from anywhere; the host is
 * mounted once in AppShell. */
export function confirmAction(options: ConfirmOptions) {
  if (typeof window === 'undefined') return
  window.dispatchEvent(new CustomEvent<ConfirmOptions>(CONFIRM_EVENT, { detail: options }))
}

export function ConfirmHost() {
  const [options, setOptions] = useState<ConfirmOptions | null>(null)
  const [running, setRunning] = useState(false)
  const [failed, setFailed] = useState(false)
  const panelRef = useRef<HTMLElement>(null)
  const confirmRef = useRef<HTMLButtonElement>(null)
  const triggerRef = useRef<Element | null>(null)

  const close = useCallback((restoreFocus = true) => {
    setOptions(null)
    setRunning(false)
    setFailed(false)
    if (restoreFocus && triggerRef.current instanceof HTMLElement && triggerRef.current.isConnected) {
      triggerRef.current.focus()
    }
  }, [])

  useEffect(() => {
    const onOpen = (event: Event) => {
      triggerRef.current = document.activeElement
      setFailed(false)
      setRunning(false)
      setOptions((event as CustomEvent<ConfirmOptions>).detail)
    }
    window.addEventListener(CONFIRM_EVENT, onOpen)
    return () => window.removeEventListener(CONFIRM_EVENT, onOpen)
  }, [])

  // Initial focus on the confirm button, matching hp-modals.js's
  // focus-trap initialFocus.
  useEffect(() => {
    if (options) confirmRef.current?.focus()
  }, [options])

  const runConfirm = useCallback(async () => {
    if (!options || running) return
    setRunning(true)
    try {
      const message = await options.onConfirm()
      close(false)
      if (typeof message === 'string' && message) flash(message)
    } catch (error) {
      setRunning(false)
      setFailed(true)
      flash(error instanceof Error ? error.message : String(error), { error: true })
      confirmRef.current?.focus()
    }
  }, [options, running, close])

  // Keyboard contract: Escape cancels (deepest-layer only — stop the event
  // so a page-level Escape handler doesn't also fire), Enter confirms,
  // Tab cycles inside the dialog (hand-rolled trap; the Go tier vendored
  // focus-trap, but two buttons don't warrant the dependency).
  useEffect(() => {
    if (!options) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !running) {
        event.preventDefault()
        event.stopImmediatePropagation()
        close()
        return
      }
      if (event.key === 'Enter' && !(event.target instanceof HTMLTextAreaElement)) {
        const target = event.target as HTMLElement
        if (target.dataset.hpModalCancel === undefined) {
          event.preventDefault()
          void runConfirm()
        }
        return
      }
      if (event.key === 'Tab' && panelRef.current) {
        const focusable = Array.from(
          panelRef.current.querySelectorAll<HTMLElement>('button:not([disabled])'),
        )
        if (focusable.length === 0) return
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault()
          last.focus()
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault()
          first.focus()
        } else if (!panelRef.current.contains(document.activeElement)) {
          event.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
  }, [options, running, close, runConfirm])

  if (!options) return null
  return (
    <div
      className="edit-dialog-backdrop open"
      id="hp-confirm-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget && !running) close()
      }}
    >
      <section
        ref={panelRef}
        className="edit-dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="hp-confirm-title"
        aria-describedby="hp-confirm-description"
      >
        <h2 className="edit-dialog__title" id="hp-confirm-title">
          {options.title}
        </h2>
        <p className="edit-dialog__desc" id="hp-confirm-description">
          {options.description ?? ''}
        </p>
        {options.warning ? <div className="danger-dialog__warning">{options.warning}</div> : null}
        <div className="edit-dialog__actions">
          <button className="btn btn-secondary" data-hp-modal-cancel="" type="button" onClick={() => close()} disabled={running}>
            Cancel
          </button>
          <button
            ref={confirmRef}
            className={options.danger === false ? 'btn btn-primary' : 'btn btn-danger'}
            type="button"
            onClick={() => void runConfirm()}
            disabled={running}
          >
            {running ? 'Working…' : failed ? 'Try again' : options.confirmLabel ?? 'Confirm'}
          </button>
        </div>
      </section>
    </div>
  )
}
