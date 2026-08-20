// Site-wide maintenance/incident banner — port of dashboard/page_presentation.go's
// activeBannerView. Configured banner text within its expiry window, or the
// maintenance-mode fallback when behavior.maintenance_mode is set. Computed
// once in the root route's loader so every page shows the same banner the Go
// shell rendered in its shared topbar partial (dashboard.html:171), not just
// the overview.
//
// Pure compute only, no `.server.ts` suffix on purpose: __root.tsx (which
// calls this from inside a createServerFn handler) is bundled for the
// client too, and the build's import-protection plugin denies importing
// any `**/*.server.*` module from client-bundled code, even one only
// reached through a server-only code path.
export type BannerView = { text: string; severity: string }

export type PresentationConfig = {
  banner_text?: string
  banner_severity?: string
  banner_expires?: string
}

export type BehaviorConfig = {
  maintenance_mode?: boolean
}

export function activeBanner(
  presentation: PresentationConfig | null | undefined,
  behavior: BehaviorConfig | null | undefined,
): BannerView | null {
  const text = (presentation?.banner_text ?? '').trim()
  const severity = presentation?.banner_severity || 'info'
  if (text) {
    const expires = presentation?.banner_expires
    if (expires) {
      const expiry = new Date(expires)
      if (!Number.isNaN(expiry.getTime()) && Date.now() > expiry.getTime()) return null
    }
    return { text, severity }
  }
  if (behavior?.maintenance_mode) {
    return { text: 'Dashboard is in maintenance mode.', severity: 'warning' }
  }
  return null
}
