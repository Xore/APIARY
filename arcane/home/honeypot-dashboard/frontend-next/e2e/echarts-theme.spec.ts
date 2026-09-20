import { expect, test, type Page } from '@playwright/test'

const palettes = ['claude', 'ocean', 'neon'] as const
const modes = ['light', 'dark'] as const
const viewports = [
  { name: 'desktop', width: 1280, height: 800 },
  { name: 'mobile', width: 390, height: 844 },
] as const

async function openChart(page: Page, palette: string, mode: string) {
  await page.addInitScript(
    ({ palette, mode }) => {
      localStorage.setItem('hp-palette', palette)
      localStorage.setItem('hp-theme', mode)
    },
    { palette, mode },
  )
  await page.goto('/topology')
  await expect(page.locator('html')).toHaveAttribute('data-hp-theme', palette)
  await expect(page.locator('html')).toHaveAttribute('data-theme', mode)
  await expect(page.locator('canvas').first()).toBeVisible({ timeout: 20_000 })
  await expect(page.getByText('scroll to zoom')).toBeVisible()
}

async function chartColors(page: Page) {
  return page.evaluate(() => {
    const host = document.querySelector('[_echarts_instance_]') as
      | (HTMLElement & { __xoreChart?: { getOption: () => { color?: string[] } } })
      | null
    if (!host?.__xoreChart) throw new Error('chart seam missing')
    return host.__xoreChart.getOption().color
  })
}

async function shadcnChartColors(page: Page) {
  return page.evaluate(() => {
    const probe = document.createElement('span')
    document.documentElement.appendChild(probe)
    const colors = [1, 2, 3, 4, 5].map((index) => {
      probe.style.color = `var(--chart-${index})`
      return getComputedStyle(probe).color
    })
    probe.remove()
    return colors
  })
}

for (const viewport of viewports) {
  for (const mode of modes) {
    for (const palette of palettes) {
      test(`${palette}/${mode}/${viewport.name} renders from shadcn chart tokens`, async ({ page }) => {
        await page.setViewportSize(viewport)
        await openChart(page, palette, mode)
        const colors = await chartColors(page)
        expect(colors).toEqual(await shadcnChartColors(page))
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
        if (process.env.ECHART_EVIDENCE_DIR) {
          await page.waitForTimeout(1_500)
          await page.screenshot({ path: `${process.env.ECHART_EVIDENCE_DIR}/${palette}-${mode}-${viewport.name}.png`, fullPage: true })
        }
      })
    }
  }
}

test('mode switch re-registers the theme and preserves resize and zoom', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 })
  await openChart(page, 'claude', 'dark')
  const before = await chartColors(page)

  await page.evaluate(() => {
    localStorage.setItem('hp-theme', 'light')
    window.dispatchEvent(new StorageEvent('storage', { key: 'hp-theme', newValue: 'light' }))
  })
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await expect.poll(() => chartColors(page)).not.toEqual(before)

  const initialWidth = await page.locator('canvas').first().evaluate((canvas) => (canvas as HTMLCanvasElement).width)
  await page.setViewportSize({ width: 390, height: 844 })
  await expect.poll(() => page.locator('canvas').first().evaluate((canvas) => (canvas as HTMLCanvasElement).width)).not.toBe(initialWidth)

  await page.getByRole('button', { name: 'Zoom in' }).click()
  await expect(page.getByText('120%', { exact: true })).toBeVisible()
})
