import { expect, test } from '@playwright/test'
import { join } from 'node:path'

const routes = [
  { name: 'events', path: '/events', heading: 'Event explorer', loaded: 'login attempt root/admin' },
  { name: 'payloads', path: '/payloads', heading: 'Captured payloads', loaded: 'uname -a' },
  { name: 'canarytokens', path: '/canarytokens', heading: 'Canarytokens', loaded: 'Deployed decoy tokens' },
] as const

for (const route of routes) for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`${route.name} loaded ${width} ${mode} without console errors or document overflow`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
    await page.goto(route.path)
    await expect(page.getByRole('heading', { name: route.heading, exact: true }).first()).toBeVisible()
    await expect(page.getByText(route.loaded, { exact: false }).first()).toBeVisible()

    if (route.name === 'events') {
      await expect(page.locator('table tbody tr').filter({ hasText: 'login attempt root/admin' })).toBeVisible()
      await page.getByRole('button', { name: /filters/i }).click()
      for (const label of ['Source IP', 'Sensor', 'Country', 'City', 'Protocol', 'Port', 'Kind', 'Since']) {
        await expect(page.getByText(label, { exact: true })).toBeVisible()
      }
      await page.keyboard.press('Escape')
    }
    if (route.name === 'payloads') {
      await expect(page.getByRole('heading', { name: 'Payload inventory' })).toBeVisible()
      await expect(page.getByRole('link', { name: 'Analysis workbench' })).toBeVisible()
      await expect(page.getByRole('link', { name: 'Download sample' })).toBeVisible()
    }
    if (route.name === 'canarytokens') {
      for (const template of ['Fake .docx', 'QR code', 'Windows folder', 'Web bug image']) {
        await expect(page.getByRole('heading', { name: template })).toBeVisible()
      }
      await expect(page.getByRole('tab', { name: 'Tokens', exact: true })).toHaveAttribute('data-state', 'active')
    }

    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
    if (process.env.EVIDENCE_DIR) await page.screenshot({ path: join(process.env.EVIDENCE_DIR, `b3-${route.name}-${width}-${mode}.png`), fullPage: true })
    expect(errors).toEqual([])
  })
}
