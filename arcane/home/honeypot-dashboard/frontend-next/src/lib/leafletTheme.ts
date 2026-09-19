import type { Map as LeafletMap } from 'leaflet'
import { cssVar } from './cssVar'

const themeProperties = {
  '--leaflet-tile-background': ['--background', '#1f1f1d'],
  '--leaflet-control-background': ['--popover', '#383835'],
  '--leaflet-control-foreground': ['--popover-foreground', '#e9e6df'],
  '--leaflet-control-border': ['--border', 'rgba(255,255,255,0.14)'],
  '--leaflet-control-hover-background': ['--shadcn-accent', '#454541'],
  '--leaflet-control-hover-foreground': ['--accent-foreground', '#e9e6df'],
  '--leaflet-control-focus': ['--ring', '#d97757'],
  '--leaflet-popup-background': ['--popover', '#383835'],
  '--leaflet-popup-foreground': ['--popover-foreground', '#e9e6df'],
  '--leaflet-popup-border': ['--border', 'rgba(255,255,255,0.14)'],
} as const

/** Resolve shadcn tokens into values Leaflet's own DOM can paint. */
export function applyLeafletTheme(map: Pick<LeafletMap, 'getContainer'>): void {
  const container = map.getContainer()
  container.classList.remove('leaflet-shadcn')
  for (const [property, [token, fallback]] of Object.entries(themeProperties)) {
    container.style.setProperty(property, cssVar(token, fallback))
  }
  container.classList.add('leaflet-shadcn')
}
