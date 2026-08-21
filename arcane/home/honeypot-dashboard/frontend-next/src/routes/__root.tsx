// Root document of the modernization port (#1608). Design contract: the
// markup speaks the exact class vocabulary of Xore/theme's theme.css (the
// same vendored stylesheet the Go dashboard serves), so the port inherits
// the claude-pure element set 1:1 — no visual drift by construction.
import { HeadContent, Scripts, createRootRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { AppShell } from '../components/AppShell'
import { getSessionUser, type User } from '../lib/auth'
import { activeBanner, type BannerView, type BehaviorConfig, type PresentationConfig } from '../lib/banner'

type ShellConfig = { banner: BannerView | null; showProblemReportButton: boolean }

// One /api/v1/config read backs every shell-wide (not per-route) piece of
// chrome: the banner and whether the "Report a problem" button shows at
// all (behavior.show_problem_report_button) — fetched together so neither
// costs its own round trip.
const fetchShellConfig = createServerFn({ method: 'GET' }).handler(async (): Promise<ShellConfig> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const config = await serviceJSON<{
    payload?: {
      presentation?: PresentationConfig
      behavior?: BehaviorConfig & { show_problem_report_button?: boolean }
    }
  }>('/api/v1/config')
  return {
    banner: activeBanner(config?.payload?.presentation, config?.payload?.behavior),
    showProblemReportButton: config?.payload?.behavior?.show_problem_report_button ?? false,
  }
})

export const Route = createRootRoute({
  // BFF-owned auth: every navigation resolves the redis session on the
  // server; unauthenticated requests bounce to the Keycloak flow. The
  // /auth/* server routes stay reachable, and the resolved user rides the
  // router context for the shell (avatar, profile).
  beforeLoad: async ({ location }) => {
    if (location.pathname.startsWith('/auth/')) return {}
    const user = await getSessionUser()
    if (!user) {
      throw redirect({
        href: `/auth/login?return_to=${encodeURIComponent(location.pathname + location.searchStr)}`,
      })
    }
    return { user }
  },
  // Shell-wide chrome (banner, problem-report button) is fetched once here
  // rather than per-route, both because every page shares it and so
  // /auth/* skips the extra backend round-trip pre-login.
  loader: async ({ location }): Promise<ShellConfig> => {
    if (location.pathname.startsWith('/auth/')) return { banner: null, showProblemReportButton: false }
    return fetchShellConfig()
  },
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { name: 'robots', content: 'noindex, nofollow' },
      { title: 'APIARY' },
    ],
    links: [{ rel: 'stylesheet', href: '/static/theme.css' }],
    scripts: [
      {
        // Pre-paint theme + palette boot, byte-compatible with the Go
        // dashboard's bootstrap: same localStorage keys (hp-theme,
        // hp-palette), same data attributes — an operator switching between
        // tiers during the transition keeps their appearance.
        children:
          '(function(){try{var t=localStorage.getItem("hp-theme");if(t==="light"||t==="dark"){document.documentElement.dataset.theme=t;}else if(t){localStorage.removeItem("hp-theme");}var p=localStorage.getItem("hp-palette");if(p&&/^[a-z]{3,16}$/.test(p)&&p!=="claude"){document.documentElement.dataset.hpPalette=p;}else if(p){localStorage.removeItem("hp-palette");}}catch(e){}})();',
      },
    ],
  }),
  shellComponent: RootDocument,
  notFoundComponent: () => (
    <header className="overview-header">
      <div>
        <div className="label-section">404</div>
        <h1>page not found</h1>
        <p className="subtitle">
          Nothing lives at this address. <a className="lnk" href="/">Back to the overview →</a>
        </p>
      </div>
    </header>
  ),
})

function RootDocument({ children }: { children: React.ReactNode }) {
  const { banner, showProblemReportButton } = Route.useLoaderData()
  // beforeLoad already resolved the session user into router context for
  // every non-/auth navigation — thread it to the shell so the sidebar
  // profile widget and topbar avatar show a real identity (#1653).
  const { user } = Route.useRouteContext() as { user?: User | null }
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        <AppShell banner={banner} showProblemReportButton={showProblemReportButton} user={user ?? null}>
          {children}
        </AppShell>
        <Scripts />
      </body>
    </html>
  )
}
