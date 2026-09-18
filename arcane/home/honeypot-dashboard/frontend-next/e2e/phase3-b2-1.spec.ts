import { expect, test } from '@playwright/test'
import { join } from 'node:path'

const routes = [
  { name: 'credentials', path: '/credentials', text: 'router-root' },
  { name: 'dead-letters', path: '/dead-letters', text: 'mapping rejected' },
  { name: 'commands', path: '/commands', text: 'session activity 1' },
  { name: 'history', path: '/history', text: 'login attempt root/admin' },
  { name: 'source-health', path: '/source-health', text: 'YARA scanner' },
] as const

for (const route of routes) for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`${route.name} loaded ${width} ${mode}`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
    await page.goto(route.path)
    await expect(page.getByText(route.text, { exact: true }).first()).toBeVisible()
    if (route.name === 'credentials') await expect(page.getByRole('heading', { name: 'Provision a new credential' })).toBeVisible()
    if (route.name === 'dead-letters') await expect(page.getByRole('textbox', { name: 'Dead-letter query' })).toBeVisible()
    if (route.name === 'history') await expect(page.getByRole('searchbox', { name: 'History search query' })).toBeVisible()
    if (route.name === 'source-health') await expect(page.getByRole('heading', { name: 'Configured feeds' })).toBeVisible()
    if (route.name === 'commands' || route.name === 'history') {
      await page.locator('table.recent tbody tr').first().click()
      await expect(page.locator('.hp-md__pane pre').first()).toContainText('honeypot')
    }
    if (route.name === 'dead-letters') {
      await page.getByRole('button', { name: 'purge shown' }).click()
      await expect(page.getByRole('alertdialog', { name: 'Purge dead letters?' })).toBeVisible()
      await page.keyboard.press('Escape')
    }
    if (route.name === 'source-health') await expect(page.getByText('cowrie', { exact: true }).first()).toBeVisible()
    if (process.env.EVIDENCE_DIR) await page.screenshot({ path: join(process.env.EVIDENCE_DIR, `b1-${route.name}-${width}-${mode}.png`), fullPage: true })
    expect(errors).toEqual([])
  })
}
