import { expect, test } from '@playwright/test'
import { join } from 'node:path'

const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
const routes = [
  { name: 'sensor', path: '/sensors/citrix', text: 'Who reached it' },
  { name: 'session', path: '/sessions/sess-0', text: 'Brute Force' },
  { name: 'payload', path: `/payload-analysis/${hash}`, text: 'Operator actions' },
  { name: 'workbench', path: '/payload-workbench/results', text: 'Start a new analysis' },
] as const

for (const route of routes) for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`${route.name} loaded ${width} ${mode}`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
    await page.goto(route.path)
    if (route.name === 'session') await expect(page.getByRole('link', { name: 'T1110 — Brute Force' })).toBeVisible()
    else if (route.name === 'payload') await expect(page.getByText(route.text, { exact: true }).first()).toBeVisible()
    else await expect(page.getByText(route.text, { exact: true }).first()).toBeVisible()
    if (route.name === 'payload') {
      await page.getByRole('tab', { name: /Findings/ }).click()
      await expect(page.getByText('FixtureRule')).toBeVisible()
    }
    if (route.name === 'workbench') {
      await expect(page.getByRole('button', { name: 'Toggle details for Local static checks' })).toBeVisible()
      await page.getByRole('button', { name: 'Toggle details for Local static checks' }).click()
      await expect(page.getByRole('button', { name: 'Refresh status' })).toBeVisible()
      await page.getByRole('searchbox', { name: 'Filter workbench runs' }).fill('unmatched')
      await expect(page.getByRole('searchbox', { name: 'Filter workbench runs' })).toHaveValue('unmatched')
    }
    if (process.env.EVIDENCE_DIR) await page.screenshot({ path: join(process.env.EVIDENCE_DIR, `c2-${route.name}-${width}-${mode}.png`), fullPage: true })
    if (route.name === 'sensor') {
      await page.getByRole('link', { name: '203.0.113.7' }).first().click()
      await expect(page).toHaveURL(/\/investigate\/ip\/203\.0\.113\.7/)
    }
    if (route.name === 'session') {
      await page.getByRole('link', { name: 'filtered events' }).click()
      await expect(page).toHaveURL(/\/events\?session=sess-0/)
    }
    expect(errors).toEqual([])
  })
}
