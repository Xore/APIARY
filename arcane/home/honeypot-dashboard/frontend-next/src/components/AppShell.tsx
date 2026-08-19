// The app shell: topbar pill + sidebar rail + main region, class-compatible
// with theme.css's .app-shell grid. Ports partials/dashboard.html's
// structure; behaviors (active nav, breadcrumb, theme cycling, palette)
// live in typed hooks instead of hp-app.js's delegation.
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'
import { CommandPalette } from './CommandPalette'
import { usePredictivePrefetch } from '../lib/prefetch'
import type { BannerView } from '../lib/banner'

export function AppShell({ children, banner }: { children: React.ReactNode; banner?: BannerView | null }) {
  usePredictivePrefetch()
  return (
    <div className="app-shell">
      <CommandPalette />
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
