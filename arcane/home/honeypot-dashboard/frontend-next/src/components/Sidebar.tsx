// Sidebar rail — 12E claude-minimal port of partials/dashboard.html's
// sidebar: search affordance, serif brand, grouped nav with raised-pill
// active items. Router-native active state replaces hp-app.js's
// syncActiveNav.
import { Link, useRouterState } from '@tanstack/react-router'
import { NAV_SECTIONS } from '../lib/nav'

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

export function Sidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  return (
    <aside className="app-sidebar" aria-label="Primary navigation">
      <button
        className="hp-sidebar-search"
        type="button"
        aria-label="Search and investigate"
        title="Search and investigate · /"
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
              const active = pathname === item.to
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={active ? 'sidebar__item active' : 'sidebar__item'}
                  aria-current={active ? 'page' : undefined}
                >
                  <NavIcon path={item.icon} />
                  <span>{item.label}</span>
                </Link>
              )
            })}
          </div>
        ))}
      </nav>
      <button
        className="sidebar__profile hp-account-trigger"
        type="button"
        aria-haspopup="menu"
        aria-expanded="false"
        aria-label="Account actions"
      >
        <span className="avatar" aria-hidden="true">
          ·
        </span>
        <div>
          <div className="hp-profile-name">…</div>
        </div>
      </button>
    </aside>
  )
}
