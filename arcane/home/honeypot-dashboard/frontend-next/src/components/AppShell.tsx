// The app shell: topbar pill + sidebar rail + main region, class-compatible
// with theme.css's .app-shell grid. Ports partials/dashboard.html's
// structure; behaviors (active nav, breadcrumb, theme cycling, palette)
// live in typed hooks instead of hp-app.js's delegation.
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'
import { CommandPalette } from './CommandPalette'
import { ProblemReportButton } from './ProblemReportButton'
import { usePredictivePrefetch } from '../lib/prefetch'
import type { BannerView } from '../lib/banner'

export function AppShell({
  children,
  banner,
  showProblemReportButton,
}: {
  children: React.ReactNode
  banner?: BannerView | null
  showProblemReportButton?: boolean
}) {
  usePredictivePrefetch()
  return (
    <div className="app-shell">
      <CommandPalette />
      <ProblemReportButton enabled={showProblemReportButton ?? false} />
      <Topbar banner={banner} />
      <Sidebar />
      <main className="app-main">
        <div
          className="app-content app-content--wide tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8"
          data-hp-page-content
        >
          {children}
        </div>
      </main>
    </div>
  )
}
