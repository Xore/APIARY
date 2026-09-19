// The app shell: topbar pill + shadcn sidebar/inset layout, document-title
// sync on navigation (also the screen reader's SPA navigation cue),
// recent-investigation recording, and the shared flash + confirm-dialog
// hosts every page's actions announce through.
import { useEffect, useState } from 'react'
import { useRouterState } from '@tanstack/react-router'
import { Sidebar } from './Sidebar'
import { SidebarInset, SidebarProvider } from './ui/sidebar'
import { Topbar } from './Topbar'
import { CommandPalette } from './CommandPalette'
import { ConfirmHost } from './ConfirmDialog'
import { SettingsModal } from './SettingsModal'
import { LiveToasts } from './LiveToasts'
import { ProblemReportButton } from './ProblemReportButton'
import { FlashHost } from '../lib/flash'
import { usePredictivePrefetch } from '../lib/prefetch'
import { pageFor } from '../lib/nav'
import { recordRecentFromLocation } from '../lib/recent'
import type { BannerView } from '../lib/banner'
import type { User } from '../lib/auth'

export function AppShell({
  banner,
  showProblemReportButton,
  user,
  appName,
  children,
}: {
  banner?: BannerView | null
  showProblemReportButton?: boolean
  user?: User | null
  /** Operator-editable brand (settings → Application name). */
  appName?: string
  children: React.ReactNode
}) {
  usePredictivePrefetch()
  const location = useRouterState({ select: (s) => s.location })
  // Settings-as-modal from anywhere (hp-settings.js:23-38, per Xore): the
  // topbar avatar and account-menu item open the centered settings modal
  // instead of navigating; on /settings itself the openers stay plain
  // links (the page is already the settings surface).
  const [settingsOpen, setSettingsOpen] = useState(false)
  const onSettingsRoute = location.pathname === '/settings'
  const openSettings = onSettingsRoute ? undefined : () => setSettingsOpen(true)

  // Navigation side effects: sync the tab title (WCAG 2.4.2 — the title
  // change is the SPA-navigation cue for screen readers) and record entity
  // pages into the sidebar's Recent list.
  useEffect(() => {
    // Navigating underneath the settings overlay (command palette, browser
    // back) dismisses it — the destination page is what the user asked for.
    setSettingsOpen(false)
    document.title = `${appName || 'APIARY'} — ${pageFor(location.pathname)}`
    recordRecentFromLocation(location.pathname, location.searchStr)
  }, [location.pathname, location.searchStr, appName])

  return (
    <SidebarProvider
      style={{
        '--sidebar-width': '16rem',
        '--sidebar-width-icon': '3rem',
        '--header-height': 'calc(var(--spacing) * 14)',
      } as React.CSSProperties}
    >
      <a
        href="#main"
        className="skip-link sr-only"
        onFocus={(event) => {
          Object.assign(event.currentTarget.style, {
            position: 'fixed',
            top: '8px',
            left: '8px',
            width: 'auto',
            height: 'auto',
            overflow: 'visible',
            clip: 'auto',
            whiteSpace: 'normal',
            zIndex: 9999,
            background: 'var(--bg-raised, #fff)',
            color: 'var(--text-000, #000)',
            padding: '8px 16px',
            borderRadius: '6px',
            boxShadow: '0 2px 8px rgba(0, 0, 0, 0.3)',
          })
        }}
        onBlur={(event) => {
          event.currentTarget.removeAttribute('style')
        }}
      >
        Skip to main content
      </a>
      <CommandPalette />
      <ProblemReportButton enabled={showProblemReportButton ?? false} />
      <ConfirmHost />
      <FlashHost />
      <LiveToasts />
      <Sidebar user={user} onOpenSettings={openSettings} />
      <SidebarInset id="main" className="app-main min-h-0">
        <Topbar banner={banner} user={user} onOpenSettings={openSettings} />
        <div className="app-content app-content--wide" data-hp-page-content>
          {children}
        </div>
      </SidebarInset>
      {settingsOpen && !onSettingsRoute ? (
        <SettingsModal user={user} onClose={() => setSettingsOpen(false)} />
      ) : null}
    </SidebarProvider>
  )
}
