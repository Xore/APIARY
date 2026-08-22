// Sidebar rail — 12E claude-minimal port of partials/dashboard.html's
// sidebar: search affordance (opens the command palette, same as the "/"
// shortcut), serif brand, grouped nav with raised-pill active items, the
// Recent-investigations list (pick 12B), and the account/session menu
// (hp-account.js's dropdown: settings, log out, role badge). Identity is
// resolved server-side into router context — no /api/whoami fetch here.
import { Fragment, useEffect, useRef, useState } from 'react'
import { Link, useRouterState } from '@tanstack/react-router'
import { NAV_SECTIONS, navHrefFor } from '../lib/nav'
import { hrefForRecent, labelForRecent, useRecentInvestigations } from '../lib/recent'
import { SidebarViewTabs } from '../lib/viewTabs'
import { openCommandPalette } from './CommandPalette'
import type { User } from '../lib/auth'

function NavIcon({ path }: { path: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      dangerouslySetInnerHTML={{ __html: path }}
    />
  )
}

function AccountMenu({ user }: { user?: User | null }) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  // Click-away and Escape close, matching hp-account.js — Escape also
  // returns focus to the trigger.
  useEffect(() => {
    if (!open) return
    const onClick = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        setOpen(false)
        triggerRef.current?.focus()
      }
    }
    document.addEventListener('click', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('click', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const display = user?.displayName || user?.username || 'Account'
  const initial = display.trim().charAt(0).toUpperCase() || '?'

  return (
    <div className="hp-account" ref={rootRef}>
      <div className="dropdown hp-account-menu" role="menu" aria-label="Account actions" hidden={!open}>
        <Link className="dropdown__item" role="menuitem" to="/settings" onClick={() => setOpen(false)}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
          <span>Dashboard settings</span>
        </Link>
        <div className="dropdown__divider" />
        {/* Log out is a real navigation — the /auth/logout server route
            clears the session cookie and bounces through Keycloak. */}
        <a className="dropdown__item" role="menuitem" href="/auth/logout">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          <span>Log out</span>
        </a>
        {!user ? (
          <span className="dropdown__item hp-account-note">Account service unavailable</span>
        ) : null}
      </div>
      <button
        ref={triggerRef}
        className="sidebar__profile hp-account-trigger"
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account actions"
        onClick={() => setOpen((value) => !value)}
      >
        <span className="avatar" aria-hidden="true">
          {initial}
        </span>
        <div>
          <div className="hp-profile-name">{display}</div>
          {/* Accent badge for admins, muted for users — hp-app.js:1845-1850. */}
          {user ? (
            <span className={user.role === 'admin' ? 'badge badge--accent' : 'badge badge--muted'}>{user.role}</span>
          ) : null}
        </div>
      </button>
    </div>
  )
}

export function Sidebar({ user }: { user?: User | null }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const activeHref = navHrefFor(pathname)
  const recent = useRecentInvestigations()
  // Whether any nav item owns the current path — when none does, the
  // relocated view-tabs rail falls back to the end of the nav body
  // (hp-app.js:2049-2052's side.append fallback).
  const hasActiveItem = NAV_SECTIONS.some((section) => section.items.some((item) => item.to === activeHref))
  return (
    <aside className="app-sidebar" aria-label="Primary navigation">
      <button
        className="hp-sidebar-search"
        type="button"
        aria-label="Search and investigate"
        title="Search and investigate · /"
        onClick={openCommandPalette}
      >
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
      </button>
      <Link to="/" className="hp-brand">
        <span className="hp-brand-mark" aria-hidden="true">
          <img className="theme-art--dark" src="/static/apiary-compact-mark-for-dark.png" width="28" height="28" alt="" />
          <img className="theme-art--light" src="/static/apiary-compact-mark-for-light.png" width="28" height="28" alt="" />
        </span>
        <span className="hp-brand-text">
          <strong>APIARY</strong>
          <small>Defensive operations</small>
        </span>
      </Link>
      <nav className="app-sidebar__body" aria-label="Dashboard sections">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label}>
            <div className="sidebar__section-label">{section.label}</div>
            {section.items.map((item) => {
              // Detail pages highlight their parent entry (hp-app.js's
              // activeHref) so drill-downs never orphan the rail.
              const active = activeHref === item.to
              return (
                <Fragment key={item.to}>
                  <Link
                    to={item.to}
                    className={active ? 'sidebar__item active' : 'sidebar__item'}
                    aria-current={active ? 'page' : undefined}
                  >
                    <NavIcon path={item.icon} />
                    <span>{item.label}</span>
                  </Link>
                  {/* Design pick 7D: the current page's view tabs nest
                      directly under the active nav item, indented like a
                      tree branch (hp-app.js:2044-2051). */}
                  {active ? <SidebarViewTabs /> : null}
                </Fragment>
              )
            })}
          </div>
        ))}
        {!hasActiveItem ? <SidebarViewTabs /> : null}
        {recent.length > 0 ? (
          <>
            <div className="sidebar__section-label hp-views-label">Recent</div>
            <div className="sidebar__recent">
              {recent.map((entry) => {
                const href = hrefForRecent(entry)
                if (!href) return null
                const label = labelForRecent(entry)
                return (
                  <a key={`${entry.kind}:${entry.value}`} href={href} title={label}>
                    {label}
                  </a>
                )
              })}
            </div>
          </>
        ) : null}
      </nav>
      <AccountMenu user={user} />
    </aside>
  )
}
