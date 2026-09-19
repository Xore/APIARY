import { expect, test } from '@playwright/test'
import { join } from 'node:path'

const routes = [
  { name: 'agent-campaigns', path: '/agent-campaigns', heading: 'Encoded egress external campaign', row: 'agent-fixture-01' },
  { name: 'ml-anomalies', path: '/ml-anomalies', heading: 'Anomalies, 24h', row: 'fixture score anomaly' },
  { name: 'attackers', path: '/attackers', heading: 'Attacker identities', row: 'att-1' },
] as const

for (const route of routes) for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`${route.name} loaded ${width} ${mode} without console errors`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
    await page.goto(route.path)
    await expect(page.getByRole('heading', { name: route.heading })).toBeVisible()
    await expect(page.getByText(route.row, { exact: false }).first()).toBeVisible()
    if (route.name === 'agent-campaigns') {
      await expect(page.getByRole('link', { name: /encoded egress external campaign/i })).toHaveAttribute('href', /category=encoded-egress-external/)
    }
    if (route.name === 'ml-anomalies') {
      await page.getByRole('button', { name: /filters/i }).click()
      for (const label of ['Severity', 'Event type', 'Status']) await expect(page.getByText(label, { exact: true })).toBeVisible()
      await page.getByRole('dialog', { name: 'Filters' }).getByRole('combobox', { name: 'Severity' }).click()
      await page.getByRole('option', { name: 'critical' }).click()
      await page.getByRole('button', { name: 'Apply filters' }).click()
      await expect(page.getByRole('button', { name: 'Filters (1)' })).toBeVisible()
      await expect(page.getByText('fixture score anomaly')).toHaveCount(0)
    }
    if (route.name === 'attackers') {
      await page.locator('table tbody tr').first().click()
      await expect(page.getByRole('heading', { name: 'Identity', exact: true })).toBeVisible()
      const overview = page.getByRole('tab', { name: 'Overview' })
      await expect(overview).toHaveAttribute('aria-controls', 'attacker-dossier-panel-overview')
      await page.getByRole('tab', { name: 'Indicators' }).click()
      await expect(page.locator('#attacker-dossier-panel-indicators')).toHaveAttribute('aria-labelledby', 'attacker-dossier-tab-indicators')
      await expect(page.getByText('root/admin')).toBeVisible()
    }
    if (process.env.EVIDENCE_DIR) await page.screenshot({ path: join(process.env.EVIDENCE_DIR, `b2-${route.name}-${width}-${mode}.png`), fullPage: true })
    expect(errors).toEqual([])
  })
}
