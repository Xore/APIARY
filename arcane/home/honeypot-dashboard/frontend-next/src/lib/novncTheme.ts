import { cssVar } from './cssVar'

const themeProperties = {
  '--novnc-toolbar-background': ['--card', '#383835'],
  '--novnc-toolbar-foreground': ['--card-foreground', '#e9e6df'],
  '--novnc-border': ['--border', 'rgba(255,255,255,0.14)'],
  '--novnc-button-background': ['--secondary', '#454541'],
  '--novnc-button-foreground': ['--secondary-foreground', '#e9e6df'],
  '--novnc-button-hover-background': ['--shadcn-accent', '#49352c'],
  '--novnc-button-hover-foreground': ['--accent-foreground', '#e9e6df'],
  '--novnc-focus': ['--ring', '#d97757'],
} as const

/** Resolve shadcn tokens into the noVNC host chrome without touching RFB's DOM. */
export function applyNoVncTheme(container: HTMLElement): void {
  container.classList.remove('novnc-shadcn')
  for (const [property, [token, fallback]] of Object.entries(themeProperties)) {
    container.style.setProperty(property, cssVar(token, fallback))
  }
  container.classList.add('novnc-shadcn')
}
