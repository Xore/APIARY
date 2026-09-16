import { expect, test } from '@playwright/test'
import { THEME_IDS } from '../src/lib/themes'

const mapping: Record<string, string> = {
  background: 'bg-000', foreground: 'text-000', primary: 'accent', secondary: 'bg-200',
  'shadcn-muted': 'bg-300', 'shadcn-accent': 'accent-soft', card: 'bg-100',
  popover: 'bg-raised', border: 'border-200', input: 'border-200', ring: 'border-focus',
  destructive: 'danger', 'chart-1': 'accent', 'chart-2': 'success', 'chart-3': 'info',
  'chart-4': 'warning', 'chart-5': 'danger', sidebar: 'bg-sidebar',
  'sidebar-foreground': 'text-000', 'sidebar-primary': 'accent',
  'sidebar-accent': 'bg-300', 'sidebar-border': 'border-100', 'sidebar-ring': 'border-focus',
}

test('theme picker maps all nine palettes in both modes without console errors', async ({ page }) => {
  test.setTimeout(120_000)
  await page.setViewportSize({ width: 1280, height: 800 })
  const errors: string[] = []
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('/settings')
  await page.locator('.settings-layout__sidebar').getByText('Appearance').click({ timeout: 5000 })

  for (const mode of ['light', 'dark']) {
    await page.locator(`[role="group"][aria-label="Theme mode"] [data-value="${mode}"]`).click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', mode)
    for (const palette of THEME_IDS) {
      await page.locator(`[role="radiogroup"][aria-label="Theme"] [data-value="${palette}"]`).click()
      await expect(page.locator('html')).toHaveAttribute('data-hp-theme', palette)
      await expect(page.locator('html')).toHaveAttribute('data-hp-palette', palette)
      const failures = await page.evaluate(entries => {
        const probe = document.createElement('span')
        document.body.append(probe)
        const bad: string[] = []
        for (const [token, legacy] of entries) {
          probe.style.color = `var(--${token})`
          const actual = getComputedStyle(probe).color
          probe.style.color = `var(--${legacy})`
          const expected = getComputedStyle(probe).color
          if (!expected || actual !== expected) bad.push(`${token}: ${actual} != ${legacy}: ${expected}`)
        }
        probe.style.borderRadius = 'var(--radius)'
        if (getComputedStyle(probe).borderTopLeftRadius !== '12px') bad.push('radius')
        probe.remove()
        return bad
      }, Object.entries(mapping))
      expect(failures, `${palette}/${mode}`).toEqual([])
      expect(await page.evaluate(() => localStorage.getItem('hp-palette'))).toBe(palette)
    }
    await page.locator('[role="radiogroup"][aria-label="Theme"] [data-value="claude"]').click()
    for (const [route, name] of [['/', 'index'], ['/events', 'events'], ['/attackers', 'attackers']]) {
      await page.goto(route)
      await expect(page.locator('main.app-main')).toBeVisible()
      await page.screenshot({ path: `../../../../dash-shots/theme-port/new-${name}-${mode}-1280.png` })
    }
    if (mode === 'light') {
      await page.goto('/settings')
      await page.locator('.settings-layout__sidebar').getByText('Appearance').click({ timeout: 5000 })
    }
  }
  expect(errors).toEqual([])
})
