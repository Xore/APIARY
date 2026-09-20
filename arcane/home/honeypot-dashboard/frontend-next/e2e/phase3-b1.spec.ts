import { expect, test } from '@playwright/test'
import { join } from 'node:path'
const palette = process.env.E2E_PALETTE === 'ocean' ? 'ocean' : 'claude'

for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`migrated overview ${width} ${mode} has no console errors`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(({ mode, palette }) => {
      localStorage.setItem('hp-palette', palette)
      localStorage.setItem('hp-theme', mode)
    }, { mode, palette })
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
  await expect(page.locator('[data-mobile="true"] aside[aria-label="Primary navigation"]')).toBeVisible()
  await page.keyboard.press('Escape')
  expect(errors).toEqual([])
})

test('theme previews retain their full tile layout', async ({ page }) => {
  await page.goto('/settings')
  await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'Appearance' }).click()
  const mode = page.getByRole('group', { name: 'Theme mode' }).getByRole('button', { name: 'Light' })
  await expect(mode).toBeVisible()
  await mode.click()
  await expect(mode).toHaveAttribute('aria-pressed', 'true')
  const tile = page.getByRole('radiogroup', { name: 'Theme' }).locator('[data-value="claude"]')
  await expect(tile).toBeVisible()
  expect((await tile.boundingBox())?.height).toBeGreaterThan(90)
})
