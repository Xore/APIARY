// The app shell: topbar pill + sidebar rail + main region, class-compatible
// with theme.css's .app-shell grid. Ports partials/dashboard.html's
// structure and hp-app.js's shell mechanics: sidebar collapse (desktop,
// persisted) / off-canvas drawer + scrim (≤520px), document-title sync on
// navigation (hp-dynamic-nav.js:153 — also the screen reader's SPA
// navigation cue), recent-investigation recording, and the shared flash +
// confirm-dialog hosts every page's actions announce through.
import { useEffect, useState } from 'react'
import { useRouterState } from '@tanstack/react-router'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'
import { CommandPalette } from './CommandPalette'
import { ConfirmHost } from './ConfirmDialog'
import { ProblemReportButton } from './ProblemReportButton'
import { FlashHost } from '../lib/flash'
import { usePredictivePrefetch } from '../lib/prefetch'
import { pageFor } from '../lib/nav'
import { recordRecentFromLocation } from '../lib/recent'
import type { BannerView } from '../lib/banner'
import type { User } from '../lib/auth'

const COLLAPSE_KEY = 'hp-sidebar-collapsed'
const MOBILE_BREAKPOINT = 520

export function AppShell({
  banner,
  showProblemReportButton,
  user,
  children,
}: {
  banner?: BannerView | null
  showProblemReportButton?: boolean
  user?: User | null
  children: React.ReactNode
}) {
  usePredictivePrefetch()
  const location = useRouterState({ select: (s) => s.location })
  // Desktop collapse persists (same key as the Go shell); the mobile
  // drawer is transient and closes on navigation, scrim click or Escape.
  const [collapsed, setCollapsed] = useState(false)
  const [navOpen, setNavOpen] = useState(false)

  useEffect(() => {
    try {
      if (window.innerWidth > MOBILE_BREAKPOINT && localStorage.getItem(COLLAPSE_KEY) === '1') {
        setCollapsed(true)
      }
    } catch {
      /* storage unavailable */
    }
  }, [])

  // One toggle, two meanings — hp-app.js:1213-1224: at mobile widths the
  // button opens the drawer, on desktop it collapses the rail.
  const toggleNav = () => {
    if (window.innerWidth <= MOBILE_BREAKPOINT) {
      setNavOpen((open) => !open)
      return
    }
    setCollapsed((value) => {
      const next = !value
      try {
        localStorage.setItem(COLLAPSE_KEY, next ? '1' : '0')
      } catch {
        /* storage unavailable */
      }
      return next
    })
  }

  // Navigation side effects: close the drawer, sync the tab title (WCAG
  // 2.4.2 — the title change is the SPA-navigation cue for screen
  // readers), record entity pages into the sidebar's Recent list.
  useEffect(() => {
    setNavOpen(false)
    document.title = `APIARY — ${pageFor(location.pathname)}`
    recordRecentFromLocation(location.pathname, location.searchStr)
  }, [location.pathname, location.searchStr])

  useEffect(() => {
    if (!navOpen) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setNavOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [navOpen])

  const shellClass = ['app-shell', collapsed ? 'hp-collapsed' : '', navOpen ? 'hp-nav-open' : '']
    .filter(Boolean)
    .join(' ')

  return (
    <div className={shellClass}>
      <CommandPalette />
      <ProblemReportButton enabled={showProblemReportButton ?? false} />
      <ConfirmHost />
      <FlashHost />
      <Topbar banner={banner} user={user} onToggleNav={toggleNav} />
      <Sidebar user={user} />
      {/* Click-to-dismiss backdrop behind the ≤520px drawer — visible only
          while .hp-nav-open is on the shell (theme.css:2143-2158). */}
      <div className="app-shell__nav-scrim" aria-hidden="true" onClick={() => setNavOpen(false)} />
      <main className="app-main">
        <div className="app-content app-content--wide tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
          {children}
        </div>
      </main>
    </div>
  )
}
