import { expect, test } from '@playwright/test'
import { join } from 'node:path'
import { THEME_IDS } from '../src/lib/themes'

const tokens = [
  'background', 'foreground', 'primary', 'secondary', 'muted', 'accent', 'card', 'popover',
  'border', 'input', 'ring', 'destructive', 'chart-1', 'chart-2', 'chart-3', 'chart-4', 'chart-5',
  'sidebar', 'sidebar-foreground', 'sidebar-primary', 'sidebar-accent', 'sidebar-border', 'sidebar-ring',
]

test('theme picker maps all nine palettes in both modes without console errors', async ({ page }, testInfo) => {
  test.setTimeout(120_000)
  await page.setViewportSize({ width: 1280, height: 800 })
  const errors: string[] = []
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('/settings')
  await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'Appearance' }).click()

  for (const mode of ['light', 'dark']) {
    await page.locator(`[role="group"][aria-label="Theme mode"] [data-value="${mode}"]`).click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', mode)
    for (const palette of THEME_IDS) {
      await page.locator(`[role="radiogroup"][aria-label="Theme"] [data-value="${palette}"]`).click()
      await expect(page.locator('html')).toHaveAttribute('data-hp-theme', palette)
      await expect(page.locator('html')).toHaveAttribute('data-hp-palette', palette)
      const failures = await page.evaluate(tokens => {
        const probe = document.createElement('span')
        document.body.append(probe)
        const bad: string[] = []
        for (const token of tokens) {
          probe.style.color = `var(--${token})`
          const actual = getComputedStyle(probe).color
          if (!actual) bad.push(token)
        }
        probe.style.borderRadius = 'var(--radius)'
        if (Number.parseFloat(getComputedStyle(probe).borderTopLeftRadius) <= 0) bad.push('radius')
        probe.remove()
        return bad
      }, tokens)
      expect(failures, `${palette}/${mode}`).toEqual([])
      expect(await page.evaluate(() => localStorage.getItem('hp-palette'))).toBe(palette)
    }
    await page.locator('[role="radiogroup"][aria-label="Theme"] [data-value="claude"]').click()
    for (const [route, name] of [['/', 'index'], ['/events', 'events'], ['/attackers', 'attackers']]) {
      await page.goto(route)
      await expect(page.locator('main.app-main')).toBeVisible()
      const filename = `new-${name}-${mode}-1280.png`
      await page.screenshot({ path: process.env.EVIDENCE_DIR
        ? join(process.env.EVIDENCE_DIR, 'theme-port', filename)
        : testInfo.outputPath(filename) })
    }
    if (mode === 'light') {
      await page.goto('/settings')
      await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'Appearance' }).click()
    }
  }
  expect(errors).toEqual([])
})
