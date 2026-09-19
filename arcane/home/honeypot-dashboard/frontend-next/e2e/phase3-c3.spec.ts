import { expect, test } from '@playwright/test'
import { join } from 'node:path'

for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`CIDR correlation loaded ${width} ${mode}`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
    await page.goto('/investigate/cidr/203.0.113.0%2F24')
    await expect(page.getByRole('heading', { name: '203.0.113.0/24' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Sensors', exact: true })).toBeVisible()
    await expect(page.getByText('Showing the 2 most recent of 12 total matches.')).toBeVisible()
    await expect(page.getByText('Linux (fixture)', { exact: false }).first()).toBeVisible()
    await expect(page.getByRole('table').first().getByRole('row')).toHaveCount(2)
    if (process.env.EVIDENCE_DIR) await page.screenshot({ path: join(process.env.EVIDENCE_DIR, `c3-cidr-${width}-${mode}.png`), fullPage: true })
    await page.getByRole('link', { name: 'in-memory events for this network' }).click()
    await expect(page).toHaveURL(/\/events\?ip=203\.0\.113\.0%2F24&since=168h/)
    expect(errors).toEqual([])
  })
}
