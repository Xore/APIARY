// The settings overlay reuses the page's pane state. Dialog owns focus,
// Escape, backdrop dismissal and focus restoration.
import { useRef, useState } from 'react'
import { Dialog, DialogContent, DialogTitle } from './ui/dialog'
import { fetchSettingsData, SettingsSurface, type SettingsData } from '../routes/settings'
import type { User } from '../lib/auth'

export function SettingsModal({ user, onClose }: { user?: User | null; onClose: () => void }) {
  const triggerRef = useRef<Element | null>(typeof document === 'undefined' ? null : document.activeElement)
  // The modal always opens on Account, like the Go modal (no ?pane= deep
  // link in overlay mode); pane switches are local state, never navigation.
  const [pane, setPane] = useState<string | undefined>(undefined)
  // One fetch per open — the component mounts when the modal opens.
  const [data] = useState<SettingsData>(() => fetchSettingsData())

  return (
    <Dialog open onOpenChange={(open) => { if (!open && !document.getElementById('hp-confirm-backdrop')) onClose() }}>
      <DialogContent
        onEscapeKeyDown={(event) => { if (document.getElementById('hp-confirm-backdrop')) event.preventDefault() }}
        onCloseAutoFocus={(event) => {
          event.preventDefault()
          const trigger = triggerRef.current instanceof HTMLElement && triggerRef.current.isConnected
            ? triggerRef.current
            : document.querySelector<HTMLElement>('[aria-label="Toolbar actions"]')
          trigger?.focus()
        }}
      >
        <DialogTitle className="sr-only">Settings</DialogTitle>
        <SettingsSurface data={data} user={user ?? null} pane={pane} onPaneChange={setPane} onClose={onClose} />
      </DialogContent>
    </Dialog>
  )
}
