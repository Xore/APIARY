// Sidebar rail — 12E claude-minimal port of partials/dashboard.html's
// sidebar: search affordance (opens the command palette, same as the "/"
// shortcut), serif brand, grouped nav with raised-pill active items, the
// Recent-investigations list (pick 12B), and the account/session menu
// (hp-account.js's dropdown: settings, log out, role badge). Identity is
// resolved server-side into router context — no /api/whoami fetch here.
import { Fragment } from 'react'
import { Link, useRouterState } from '@tanstack/react-router'
import { NAV_SECTIONS, navHrefFor } from '../lib/nav'
import { labelForRecent, linkForRecent, useRecentInvestigations } from '../lib/recent'
import { SidebarViewTabs } from '../lib/viewTabs'
import { openCommandPalette } from './CommandPalette'
import type { User } from '../lib/auth'
import { Sidebar as ShadcnSidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuItem } from './ui/sidebar'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from './ui/dropdown-menu'
import { Avatar, AvatarFallback } from './ui/avatar'
import { Badge } from './ui/badge'
import { Button } from './ui/button'

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

function AccountMenu({ user, onOpenSettings }: { user?: User | null; onOpenSettings?: () => void }) {
  const display = user?.displayName || user?.username || 'Account'
  const initial = display.trim().charAt(0).toUpperCase() || '?'

  return (
    <DropdownMenu>
      <DropdownMenuContent align="start" aria-label="Account actions">
        {/* Opens the centered settings modal when JS-driven opening is
            available (hp-settings.js:23-27's
            data-hp-account-dashboard-settings, per Xore); the /settings
            href stays as the no-JS / modified-click fallback, and on the
            /settings route itself this is a plain link. */}
        <DropdownMenuItem asChild><Link
          to="/settings"
          onClick={(event) => {
            if (!onOpenSettings || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
            event.preventDefault()
            onOpenSettings()
          }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
          <span>Dashboard settings</span>
        </Link></DropdownMenuItem>
        <DropdownMenuSeparator />
        {/* Log out is a real navigation — the /auth/logout server route
            clears the session cookie and bounces through Keycloak. */}
        <Button asChild><Link to="/auth/logout" reloadDocument>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          <span>Log out</span>
        </Link></Button>
        {!user ? (
          <DropdownMenuItem disabled>Account service unavailable</DropdownMenuItem>
        ) : null}
      </DropdownMenuContent>
      <DropdownMenuTrigger asChild><Button
        variant="ghost"
        size="default"
        className="sidebar__profile hp-account-trigger"
        type="button"
        aria-label="Account actions"
      >
        <Avatar aria-hidden="true"><AvatarFallback>{initial}</AvatarFallback></Avatar>
        <div>
          <div className="text-[13px] text-foreground">{display}</div>
          {/* Accent badge for admins, muted for users — hp-app.js:1845-1850. */}
          {user ? (
            <Badge variant={user.role === 'admin' ? 'default' : 'secondary'}>{user.role}</Badge>
          ) : null}
        </div>
      </Button></DropdownMenuTrigger>
    </DropdownMenu>
  )
}

export function Sidebar({ user, onOpenSettings }: { user?: User | null; onOpenSettings?: () => void }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const activeHref = navHrefFor(pathname)
  const recent = useRecentInvestigations()
  // Whether any nav item owns the current path — when none does, the
  // relocated view-tabs rail falls back to the end of the nav body
  // (hp-app.js:2049-2052's side.append fallback).
  const hasActiveItem = NAV_SECTIONS.some((section) => section.items.some((item) => item.to === activeHref))
  return (
    <ShadcnSidebar collapsible="icon" className="!bg-transparent"><aside className="app-sidebar h-full w-full" aria-label="Primary navigation">
      <Button
        variant="ghost"
        size="icon"
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
      </Button>
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
      <SidebarContent className="app-sidebar__body !block"><nav aria-label="Dashboard sections">
        {NAV_SECTIONS.map((section) => (
          <SidebarGroup key={section.label} className="!p-0">
            <SidebarGroupLabel className="sidebar__section-label !h-auto">{section.label}</SidebarGroupLabel>
            <SidebarMenu>
            {section.items.map((item) => {
              // Detail pages highlight their parent entry (hp-app.js's
              // activeHref) so drill-downs never orphan the rail.
              const active = activeHref === item.to
              return (
                <SidebarMenuItem key={item.to}><Fragment>
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
                </Fragment></SidebarMenuItem>
              )
            })}
            </SidebarMenu>
          </SidebarGroup>
        ))}
        {!hasActiveItem ? <SidebarViewTabs /> : null}
        {recent.length > 0 ? (
          <>
            <div className="sidebar__section-label">Recent</div>
            <div className="sidebar__recent">
              {recent.map((entry) => {
                const link = linkForRecent(entry)
                if (!link) return null
                const label = labelForRecent(entry)
                return (
                  <Link key={`${entry.kind}:${entry.value}`} to={link.to} params={link.params} search={link.search} title={label}>
                    {label}
                  </Link>
                )
              })}
            </div>
          </>
        ) : null}
      </nav></SidebarContent>
      <SidebarFooter>
        <AccountMenu user={user} onOpenSettings={onOpenSettings} />
      </SidebarFooter>
    </aside></ShadcnSidebar>
  )
}
