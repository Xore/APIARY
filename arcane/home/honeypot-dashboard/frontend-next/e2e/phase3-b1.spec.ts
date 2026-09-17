import { expect, test } from '@playwright/test'
import { join } from 'node:path'

for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`migrated overview ${width} ${mode} has no console errors`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(value => {
      localStorage.setItem('hp-palette', 'claude')
      localStorage.setItem('hp-theme', value)
    }, mode)
    await page.goto('/')
    await expect(page.locator('main.app-main')).toBeVisible()
    await expect(page.locator('#overview-kpis')).toBeVisible()
    if (width === 1280) await expect(page.locator('aside [data-hp-sidebar-tabs]')).toBeVisible()
    else await expect(page.locator('main [role="tablist"]')).toBeVisible()
    // Captures go to the per-test results dir (or EVIDENCE_DIR) instead of
    // hardcoding a repo path — running this suite must not rewrite
    // dash-shots inputs (same defect class the review flagged as F2).
    const shot = process.env.EVIDENCE_DIR
      ? join(process.env.EVIDENCE_DIR, 'phase3-b1', `overview-${width}-${mode}.png`)
      : testInfo.outputPath(`overview-${width}-${mode}.png`)
    await page.screenshot({ path: shot })
    expect(errors).toEqual([])
  })
}

test('overview tabs keep URL state and keyboard navigation', async ({ page }) => {
  await page.goto('/')
  const tabs = page.locator('aside [role="tablist"]')
  await expect(tabs).toBeVisible()
  await expect(tabs.getByRole('tab', { name: /live operations/i })).toHaveAttribute('aria-controls', 'ov-panel-live')
  await tabs.getByRole('tab', { name: /collection health/i }).click()
  await expect(page).toHaveURL(/tab=health/)
  await expect(page.locator('#ov-panel-health')).toBeVisible()
  await page.reload()
  await expect(tabs.getByRole('tab', { name: /collection health/i })).toHaveAttribute('aria-selected', 'true')
  await tabs.getByRole('tab', { name: /collection health/i }).focus()
  await page.keyboard.press('ArrowDown')
  await expect(page).toHaveURL(/tab=threats/)
})

test('gallery and mobile navigation render without console errors', async ({ page }) => {
  const errors: string[] = []
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('/dev/gallery')
  await expect(page.getByRole('heading', { name: 'Component gallery' })).toBeVisible()
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('button', { name: 'Toggle navigation' }).click()
  await expect(page.locator('aside[aria-label="Primary navigation"]')).toBeVisible()
  await page.keyboard.press('Escape')
  expect(errors).toEqual([])
})

test('theme previews retain their full tile layout', async ({ page }) => {
  await page.goto('/settings')
  await page.locator('.settings-layout__sidebar').getByText('Appearance').click()
  const tile = page.locator('[role="radiogroup"][aria-label="Theme"] [data-value="claude"]')
  await expect(tile).toBeVisible()
  expect((await tile.boundingBox())?.height).toBeGreaterThan(90)
})
