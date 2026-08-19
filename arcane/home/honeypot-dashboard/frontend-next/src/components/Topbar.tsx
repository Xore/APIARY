// Topbar — the 11E floating pill bar: breadcrumb (section / page from the
// router, never diverging from the sidebar), alerts bell, theme cycler,
// LIVE state, account avatar. Ports partials/dashboard.html's topbar.
import { Link, useRouterState } from '@tanstack/react-router'
import { pageFor, sectionFor } from '../lib/nav'
import { cycleTheme, useThemeMode } from '../lib/prefs'
import type { BannerView } from '../lib/banner'

export function Topbar({ banner }: { banner?: BannerView | null }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const mode = useThemeMode()
  const section = sectionFor(pathname)
  const page = pageFor(pathname)
  return (
    <header className="app-toolbar">
      <button className="btn btn-icon btn-ghost" type="button" aria-label="Toggle navigation" title="Toggle navigation">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <line x1="9" y1="3" x2="9" y2="21" />
        </svg>
      </button>
      <Link className="app-toolbar__brand" to="/" aria-label="APIARY home">
        <img className="theme-art--dark" src="/static/apiary-compact-mark-for-dark.png" width="22" height="22" alt="" />
        <img className="theme-art--light" src="/static/apiary-compact-mark-for-light.png" width="22" height="22" alt="" />
      </Link>
      <div className="hp-crumb">
        {section ? (
          <>
            <span>{section}</span>
            <span className="sep">/</span>
          </>
        ) : null}
        <b>{page}</b>
      </div>
      <div className="app-toolbar__search" aria-hidden="true" />
      <div className="hp-toolbar-actions">
        <Link className="btn btn-icon btn-ghost" to="/alerts" title="Open alerts" aria-label="Open alerts">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
            <path d="M13.73 21a2 2 0 0 1-3.46 0" />
          </svg>
        </Link>
        <button
          className="btn btn-icon btn-ghost"
          type="button"
          onClick={cycleTheme}
          aria-label="Switch color theme"
          title={`Theme: ${mode}`}
        >
          {mode === 'system' ? (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="2" y="3" width="20" height="14" rx="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
          ) : mode === 'dark' ? (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="5" />
              <line x1="12" y1="1" x2="12" y2="3" />
              <line x1="12" y1="21" x2="12" y2="23" />
              <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
              <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
              <line x1="1" y1="12" x2="3" y2="12" />
              <line x1="21" y1="12" x2="23" y2="12" />
              <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
              <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
            </svg>
          )}
        </button>
        <button className="hp-live-state" type="button" aria-pressed="false" title="Dashboard refresh is active">
          <span className="status-dot" />
          <span>Live</span>
        </button>
        <a className="avatar hp-toolbar-avatar" href="/settings" title="Account & settings" aria-label="Account and settings">
          ·
        </a>
      </div>
      {banner ? (
        <div className={`alert alert--${banner.severity} app-toolbar__banner`} role="status">
          {banner.text}
        </div>
      ) : null}
    </header>
  )
}
