// Global status flash — the port of the Go shell's #hp-flash toast
// (partials/dashboard.html:173, driven by hp-modals.js announce() and
// hp-app.js flashCopied()). One fixed live region for transient outcome
// messages: confirm-dialog results, copy-to-clipboard confirmation, live
// "new events" notices. Same theme.css classes (.toast.hp-modal-status,
// .open, data-state) so the visual contract is untouched.
import { useEffect, useState } from 'react'

type FlashMessage = { text: string; error: boolean; duration: number }

const FLASH_EVENT = 'hp:flash'

/** Show a transient status message in the shell's flash region.
 * Errors persist longer by default, mirroring hp-modals.js (5s) vs the
 * short 1.6s copy-confirmation flash (pass duration for that case). */
export function flash(text: string, options?: { error?: boolean; duration?: number }) {
  if (typeof window === 'undefined') return
  window.dispatchEvent(
    new CustomEvent<FlashMessage>(FLASH_EVENT, {
      detail: { text, error: options?.error ?? false, duration: options?.duration ?? 5000 },
    }),
  )
}

/** Copy text to the clipboard with visible confirmation — the port of
 * hp-app.js flashCopied(): success and the (previously swallowed)
 * failure case both surface in the flash region. */
export function copyWithFlash(value: string, label?: string) {
  const shown = label ?? (value.length > 60 ? `${value.slice(0, 57)}…` : value)
  navigator.clipboard
    ?.writeText(value)
    .then(() => flash(`Copied ${shown}`, { duration: 1600 }))
    .catch(() => flash('Copy failed — clipboard unavailable', { error: true }))
}

/** Mounted once in AppShell. Renders the single flash live region. */
export function FlashHost() {
  const [message, setMessage] = useState<FlashMessage | null>(null)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined
    const onFlash = (event: Event) => {
      const detail = (event as CustomEvent<FlashMessage>).detail
      setMessage(detail)
      setOpen(true)
      if (timer) clearTimeout(timer)
      timer = setTimeout(() => setOpen(false), detail.duration)
    }
    window.addEventListener(FLASH_EVENT, onFlash)
    return () => {
      window.removeEventListener(FLASH_EVENT, onFlash)
      if (timer) clearTimeout(timer)
    }
  }, [])

  return (
    <div
      id="hp-flash"
      className={open ? 'toast hp-modal-status open' : 'toast hp-modal-status'}
      role="status"
      aria-live="polite"
      data-state={message?.error ? 'error' : 'success'}
    >
      {message?.text ?? ''}
    </div>
  )
}
