import type { ITheme } from '@xterm/xterm'
import { cssVar } from './cssVar'

export function xtermTheme(): ITheme {
  const foreground = cssVar('--foreground', '#e9e6df')
  const background = cssVar('--card', '#383835')
  const primary = cssVar('--primary', '#d97757')
  const primaryForeground = cssVar('--primary-foreground', '#ffffff')
  const muted = cssVar('--muted', '#2c2c2a')
  const mutedForeground = cssVar('--muted-foreground', '#a5a9a6')
  const border = cssVar('--border', 'rgba(255,255,255,0.14)')
  const red = cssVar('--destructive', '#dc7774')
  const green = cssVar('--chart-2', '#79c99e')
  const yellow = cssVar('--chart-4', '#deb36a')
  const blue = cssVar('--chart-3', '#78a9d4')
  const magenta = cssVar('--chart-5', '#dc7774')

  return {
    foreground,
    background,
    cursor: primary,
    cursorAccent: primaryForeground,
    selectionBackground: cssVar('--accent', '#49352c'),
    selectionForeground: cssVar('--accent-foreground', foreground),
    selectionInactiveBackground: muted,
    scrollbarSliderBackground: border,
    scrollbarSliderHoverBackground: mutedForeground,
    scrollbarSliderActiveBackground: foreground,
    overviewRulerBorder: border,
    black: cssVar('--background', '#20201f'),
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan: primary,
    white: foreground,
    brightBlack: mutedForeground,
    brightRed: red,
    brightGreen: green,
    brightYellow: yellow,
    brightBlue: blue,
    brightMagenta: magenta,
    brightCyan: primary,
    brightWhite: cssVar('--card-foreground', foreground),
  }
}
