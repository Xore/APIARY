import { expect, test, type Page } from '@playwright/test'

const cases = [
  { palette: 'claude', mode: 'light', width: 1280, height: 800 },
  { palette: 'claude', mode: 'dark', width: 390, height: 844 },
  { palette: 'ocean', mode: 'light', width: 390, height: 844 },
  { palette: 'ocean', mode: 'dark', width: 1280, height: 800 },
] as const

const themeTokens = {
  foreground: '--foreground',
  background: '--card',
  cursor: '--primary',
  cursorAccent: '--primary-foreground',
  selectionBackground: '--accent',
  selectionForeground: '--accent-foreground',
  selectionInactiveBackground: '--muted',
  scrollbarSliderBackground: '--border',
  scrollbarSliderHoverBackground: '--muted-foreground',
  scrollbarSliderActiveBackground: '--foreground',
  overviewRulerBorder: '--border',
  black: '--background',
  red: '--destructive',
  green: '--chart-2',
  yellow: '--chart-4',
  blue: '--chart-3',
  magenta: '--chart-5',
  cyan: '--primary',
  white: '--foreground',
  brightBlack: '--muted-foreground',
  brightRed: '--destructive',
  brightGreen: '--chart-2',
  brightYellow: '--chart-4',
  brightBlue: '--chart-3',
  brightMagenta: '--chart-5',
  brightCyan: '--primary',
  brightWhite: '--card-foreground',
} as const

async function openReplay(page: Page, palette: string, mode: string) {
  await page.addInitScript(
    ({ palette, mode }) => {
      localStorage.setItem('hp-palette', palette)
      localStorage.setItem('hp-theme', mode)
    },
    { palette, mode },
  )
  await page.goto('/tty-replay/e2e-xterm-theme')
  await expect(page.locator('html')).toHaveAttribute('data-hp-theme', palette)
  await expect(page.locator('html')).toHaveAttribute('data-theme', mode)
  await expect(page.getByLabel('Terminal playback').locator('.xterm-screen')).toBeVisible({ timeout: 20_000 })
}

async function terminalTheme(page: Page) {
  return page.getByLabel('Terminal playback').evaluate((host) => {
    const terminal = (host as HTMLElement & {
      __xoreTerminal?: { options: { theme?: Record<string, string> } }
    }).__xoreTerminal
    if (!terminal?.options.theme) throw new Error('xterm seam missing')
    return terminal.options.theme
  })
}

async function resolvedThemeTokens(page: Page) {
  return page.evaluate((tokens) => {
    const probe = document.createElement('span')
    document.documentElement.appendChild(probe)
    const theme = Object.fromEntries(Object.entries(tokens).map(([key, token]) => {
      probe.style.color = `var(${token})`
      return [key, getComputedStyle(probe).color]
    }))
    probe.remove()
    return theme
  }, themeTokens)
}

for (const entry of cases) {
  test(`${entry.palette}/${entry.mode}/${entry.width} uses the exact shadcn xterm theme`, async ({ page }) => {
    await page.setViewportSize({ width: entry.width, height: entry.height })
    await openReplay(page, entry.palette, entry.mode)

    expect(await terminalTheme(page)).toEqual(await resolvedThemeTokens(page))

    const play = page.getByRole('button', { name: 'Play' })
    await play.focus()
    await page.keyboard.press('Enter')
    await expect(page.getByLabel('Terminal playback')).toContainText('$ echo xterm-theme')

    const seek = page.getByRole('slider', { name: 'Seek within the recording' })
    await seek.focus()
    await page.keyboard.press('End')
    await expect(seek).toHaveValue('2')
    await expect(page.getByLabel('Terminal playback')).toContainText('xterm-theme')
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  })
}
