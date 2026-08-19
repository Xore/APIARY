// The sidebar's information architecture, ported 1:1 from
// partials/dashboard.html (sections, order, labels, routes). Icons are the
// same feather-style paths the templates inline; kept as raw path data so
// components stay terse.
export type NavItem = {
  label: string
  to: string
  icon: string // svg inner markup (feather-style, stroke-based)
}

export type NavSection = {
  label: string
  items: NavItem[]
}

export const NAV_SECTIONS: NavSection[] = [
  {
    label: 'Monitor',
    items: [
      { label: 'Overview', to: '/', icon: '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>' },
      { label: 'ML anomalies', to: '/ml-anomalies', icon: '<path d="M12 2a4 4 0 0 1 4 4v1a4 4 0 0 1-.4 1.75L18 12l-2.4 3.25A4 4 0 0 1 16 17v1a4 4 0 0 1-8 0v-1a4 4 0 0 1 .4-1.75L6 12l2.4-3.25A4 4 0 0 1 8 7V6a4 4 0 0 1 4-4z"/><circle cx="12" cy="12" r="2"/>' },
      { label: 'LLM analysis', to: '/llm-analysis', icon: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>' },
      { label: 'Agent campaigns', to: '/agent-campaigns', icon: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>' },
      { label: 'Auth-failure events', to: '/auth-events', icon: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>' },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { label: 'Event explorer', to: '/events', icon: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>' },
      { label: 'Attack sources', to: '/ips', icon: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' },
      { label: 'Campaigns', to: '/campaigns', icon: '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>' },
      { label: 'Infrastructure clusters', to: '/clusters', icon: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>' },
      { label: 'Attacker identities', to: '/attackers', icon: '<polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/>' },
      { label: 'Kill-chain analytics', to: '/kill-chain', icon: '<path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/>' },
      { label: 'Executed commands', to: '/commands', icon: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>' },
      { label: 'Sensor detail', to: '/sensors', icon: '<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/>' },
      { label: 'Session recordings', to: '/recordings', icon: '<circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/>' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { label: 'Alerts', to: '/alerts', icon: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>' },
      { label: 'Source & pipeline health', to: '/source-health', icon: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>' },
      { label: 'Event history', to: '/history', icon: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>' },
    ],
  },
  {
    label: 'Reports',
    items: [
      { label: 'Reports studio', to: '/reports', icon: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>' },
    ],
  },
  {
    label: 'Tools',
    items: [
      { label: 'Canarytokens', to: '/canarytokens', icon: '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>' },
      { label: 'Credentials', to: '/credentials', icon: '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/>' },
    ],
  },
  {
    label: 'Evidence',
    items: [
      { label: 'Captured payloads', to: '/payloads', icon: '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/>' },
      { label: 'Analysis results', to: '/payload-workbench/results', icon: '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>' },
    ],
  },
]

/** Section label for a pathname — drives the topbar breadcrumb. */
export function sectionFor(pathname: string): string {
  for (const section of NAV_SECTIONS) {
    if (section.items.some((item) => item.to === pathname)) return section.label
  }
  return ''
}

/** Page label for a pathname. */
export function pageFor(pathname: string): string {
  for (const section of NAV_SECTIONS) {
    const hit = section.items.find((item) => item.to === pathname)
    if (hit) return hit.label
  }
  return 'Dashboard'
}
