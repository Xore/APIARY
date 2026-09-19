// #3205 F3: run this same spec against both production builds.
// F3_CAPTURE_DIR selects the evidence directory, not the rendering setup.
import { expect, test } from '@playwright/test'
import { resolve } from 'node:path'

const shots = process.env.F3_CAPTURE_DIR || resolve('../../../../dash-shots/f2-follow-up/after')
const palette = process.env.E2E_PALETTE === 'ocean' ? 'ocean' : 'claude'

for (const width of [1280, 390]) for (const mode of ['light', 'dark'] as const) {
  const height = width === 1280 ? 800 : 844
  test(`matched overview ${width}x${height} ${mode}`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height })
    await page.emulateMedia({ colorScheme: mode, reducedMotion: 'reduce' })
    await page.clock.setFixedTime(new Date('2026-09-17T00:00:00Z'))
    await page.addInitScript(({ mode, palette }) => {
      localStorage.setItem('hp-palette', palette)
      localStorage.setItem('hp-theme', mode)
    }, { mode, palette })
    await page.goto('/')
    await expect(page.locator('main.app-main')).toBeVisible()
    await expect(page.locator('#overview-kpis')).toBeVisible()
    await expect(page.locator('html')).toHaveAttribute('data-theme', mode)
    await expect(page.locator('html')).toHaveAttribute('data-hp-theme', palette)
    await page.evaluate(() => document.fonts.ready)
    await page.waitForLoadState('networkidle')
    await page.screenshot({ path: resolve(shots, `overview-${width}x${height}-${mode}.png`), animations: 'disabled' })
    expect(errors).toEqual([])
  })
}
