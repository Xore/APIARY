// Settings-as-modal from anywhere (#1653) — the port of
// hp-settings.js:23-38,128-174: the topbar avatar and the sidebar account
// menu's "Dashboard settings" item open the full settings surface as the
// theme's centered modal (per Xore; dashboard.html's
// data-hp-account-dashboard-settings contract) instead of navigating, with
// the plain /settings href kept as the no-JS / middle-click fallback. The
// surface itself lives in routes/settings.tsx (SettingsSurface); this
// component supplies the overlay chrome the Go fragment carried:
// .modal-backdrop, focus moved in on open and restored on close,
// Escape/backdrop dismiss, and a Tab focus trap (settings_modal.html:6-8 +
// hp-settings.js's focus-trap). Mounted by AppShell only while open, so
// mount/unmount is the open/close lifecycle.
import { useEffect, useRef, useState } from 'react'
import { fetchSettingsData, SettingsSurface, type SettingsData } from '../routes/settings'
import type { User } from '../lib/auth'

export function SettingsModal({ user, onClose }: { user?: User | null; onClose: () => void }) {
  const rootRef = useRef<HTMLDivElement>(null)
  const restoreRef = useRef<Element | null>(null)
  // The modal always opens on Account, like the Go modal (no ?pane= deep
  // link in overlay mode); pane switches are local state, never navigation.
  const [pane, setPane] = useState<string | undefined>(undefined)
  // One fetch per open — the component mounts when the modal opens.
  const [data] = useState<SettingsData>(() => fetchSettingsData())

  // Focus moves into the dialog on open (the close button — the first
  // focusable, matching the Go focus-trap's default initial focus) and
  // returns to the trigger on close.
  useEffect(() => {
    restoreRef.current = document.activeElement
    rootRef.current?.querySelector<HTMLElement>('.modal__close')?.focus()
    return () => {
      const trigger = restoreRef.current
      if (trigger instanceof HTMLElement && trigger.isConnected) trigger.focus()
    }
  }, [])

  // Keyboard contract (hp-settings.js:177-186): while the nested confirm
  // dialog is open it owns Escape and Tab — its capture-phase handler
  // stopImmediatePropagation's Escape before this bubble-phase listener
  // runs, and the host check below covers Tab. Otherwise Escape closes the
  // modal and Tab cycles inside it (hand-rolled trap, same pattern as
  // ConfirmDialog.tsx). The settings search input clears itself on Escape
  // and stops propagation, so a first Escape there never closes the modal.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (document.getElementById('hp-confirm-backdrop')) return
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key === 'Tab' && rootRef.current) {
        const focusable = Array.from(
          rootRef.current.querySelectorAll<HTMLElement>(
            'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
          ),
        ).filter((element) => !element.closest('[hidden]'))
        if (focusable.length === 0) return
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault()
          last.focus()
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault()
          first.focus()
        } else if (!rootRef.current.contains(document.activeElement)) {
          event.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div ref={rootRef}>
      <div className="modal-backdrop open" onClick={onClose} />
      <SettingsSurface data={data} user={user ?? null} pane={pane} onPaneChange={setPane} onClose={onClose} />
    </div>
  )
}
