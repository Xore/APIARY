// The app shell: topbar pill + sidebar rail + main region, class-compatible
// with theme.css's .app-shell grid. Ports partials/dashboard.html's
// structure; behaviors (active nav, breadcrumb, theme cycling, palette)
// live in typed hooks instead of hp-app.js's delegation.
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="app-shell">
      <Topbar />
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
