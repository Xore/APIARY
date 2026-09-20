import { expect, test } from '@playwright/test'
import { join } from 'node:path'

const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
const surfaces = [
  { name: 'overview', path: '/', marker: '#overview-kpis' },
  { name: 'search', path: '/search?q=fixture', marker: 'table' },
  { name: 'search-empty', path: '/search?q=no-fixture-match', marker: '[data-slot="empty"]' },
  { name: 'ip', path: '/investigate/ip/203.0.113.7', marker: '#attacker-block-expires' },
  { name: 'sensor', path: '/sensors/citrix', marker: 'text=What this sensor did' },
  { name: 'payload', path: `/payload-analysis/${hash}`, marker: 'text=Static risk' },
  { name: 'settings-modal', path: '/', marker: 'role=dialog' },
] as const

for (const surface of surfaces) for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`${surface.name} ${width} ${mode}`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
    await page.goto(surface.path)
    if (surface.name === 'settings-modal') {
      await page.getByRole('menuitem', { name: 'Toolbar actions' }).click()
      await page.getByRole('menuitem', { name: 'Account & settings' }).click()
    }
    await expect(page.locator(surface.marker).first()).toBeVisible()
    if (surface.name === 'settings-modal') {
      const input = await page.getByRole('searchbox', { name: 'Search settings' }).boundingBox()
      const close = await page.getByRole('button', { name: 'Close settings' }).boundingBox()
      expect(input && close && (close.x + close.width <= input.x || input.x + input.width <= close.x || close.y + close.height <= input.y || input.y + input.height <= close.y)).toBe(true)
    }
    if (surface.name === 'search') await expect(page.getByRole('link', { name: 'fixture-command' })).toBeVisible()
    if (surface.name === 'ip') await expect(page.getByRole('table').first()).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    const shot = process.env.EVIDENCE_DIR
      ? join(process.env.EVIDENCE_DIR, 'shots', `${surface.name}-${width}-${mode}.png`)
      : testInfo.outputPath(`${surface.name}-${width}-${mode}.png`)
    await page.screenshot({ path: shot, fullPage: true })
    expect(errors).toEqual([])
  })
}
