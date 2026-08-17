// Root document of the modernization port (#1608). Design contract: the
// markup speaks the exact class vocabulary of Xore/theme's theme.css (the
// same vendored stylesheet the Go dashboard serves), so the port inherits
// the claude-pure element set 1:1 — no visual drift by construction.
import { HeadContent, Scripts, createRootRoute } from '@tanstack/react-router'
import { AppShell } from '../components/AppShell'

export const Route = createRootRoute({
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
})

function RootDocument({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        <AppShell>{children}</AppShell>
        <Scripts />
      </body>
    </html>
  )
}
