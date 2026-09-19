import { expect, test } from '@playwright/test'
import { join } from 'node:path'

const routes = [
  { name: 'llm-analysis', path: '/llm-analysis', heading: 'LLM analysis', loaded: 'Fixture model summary', labels: ['Semantic search query'] },
  { name: 'auth-events', path: '/auth-events', heading: 'Auth-failure events', loaded: 'fixture-user', labels: [] },
  { name: 'problem-reports', path: '/problem-reports', heading: 'Problem reports', loaded: 'filters remain open', labels: [] },
  { name: 'reports', path: '/reports', heading: 'Reports studio', loaded: 'APIARY Executive Security Report', labels: ['Name', 'Theme', 'Window', 'Event appendix limit'] },
] as const

for (const route of routes) for (const width of [1280, 390]) {
  test(`${route.name} loaded at ${width}px in light and dark without console errors or document overflow`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })

    for (const mode of ['light', 'dark']) {
      await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
      await page.goto(route.path)
      await expect(page.getByRole('heading', { name: route.heading, exact: true }).first()).toBeVisible()
      for (const label of route.labels) await expect(page.getByText(label, { exact: true }).first()).toBeVisible()
      if (route.name === 'reports') await page.locator('#rp-library').click()
      await expect(page.getByText(route.loaded, { exact: false }).first()).toBeVisible()
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
      if (process.env.EVIDENCE_DIR) await page.screenshot({ path: join(process.env.EVIDENCE_DIR, `b4-${route.name}-${width}-${mode}.png`), fullPage: true })
    }

    expect(errors).toEqual([])
  })
}
