import { expect, test } from '@playwright/test'
import { join } from 'node:path'

const routes = [
  { path: '/settings', name: 'settings' },
  { path: '/investigate/lookup', name: 'lookup' },
  { path: '/investigate/cluster?kind=asn&value=AS64500', name: 'cluster' },
  { path: '/search?q=fixture', name: 'search' },
] as const

for (const route of routes) for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`${route.name} ${width} ${mode}: route chrome and console`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
    await page.goto(route.path)
    await expect(page.locator('main.app-main')).toBeVisible()
    if (route.name === 'lookup') {
      await expect(page.getByRole('button', { name: 'Look up' })).toBeDisabled()
      await page.getByRole('textbox', { name: 'Value to look up' }).fill('AS64500')
      await expect(page.getByRole('button', { name: 'Look up' })).toBeEnabled()
    } else if (route.name === 'search') {
      await page.getByRole('searchbox', { name: 'Search query' }).fill('test')
      await page.getByRole('button', { name: 'Search', exact: true }).click()
      await expect(page).toHaveURL(/q=test/)
    } else if (route.name === 'settings') {
      await page.getByRole('searchbox', { name: 'Search settings' }).fill('timezone')
      await expect(page.getByRole('navigation', { name: 'Settings sections' })).toBeVisible()
    } else {
      await expect(page.getByRole('heading', { name: /asn: AS64500/i })).toBeVisible()
    }
    if (process.env.EVIDENCE_DIR) await page.screenshot({ path: join(process.env.EVIDENCE_DIR, `${route.name}-${width}-${mode}.png`), fullPage: true })
    expect(errors).toEqual([])
  })
}

test('cluster back control returns to clusters without a document navigation', async ({ page }) => {
  await page.goto('/investigate/cluster?kind=asn&value=AS64500')
  await page.getByRole('link', { name: '← clusters' }).click()
  await expect(page).toHaveURL(/\/clusters$/)
})

test('settings selection opens its keyboard-operated options', async ({ page }) => {
  await page.goto('/settings?pane=navigation')
  await page.getByRole('combobox', { name: 'Rows per page' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('option', { name: '25', exact: true })).toBeVisible()
  await page.keyboard.press('Escape')
})

test('search fixture emits scoped backend groups and a genuine zero state', async ({ page }) => {
  await page.goto('/search?q=fixture')
  await expect(page.getByRole('link', { name: /fixture-command/ })).toHaveAttribute('href', '/events?cmd=fixture-command')
  await expect(page.getByRole('link', { name: /more/i }).first()).toHaveAttribute('href', '/history?q=fixture')
  await page.goto('/search?q=no-fixture-match')
  await expect(page.getByText('fixture-command')).toHaveCount(0)
})

for (const width of [1280, 390]) for (const mode of ['light', 'dark']) for (const kind of ['callback', 'login']) {
  test(`auth ${kind} error ${width} ${mode}: bundled chrome without console errors`, async ({ page }) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(theme => localStorage.setItem('hp-theme', theme), mode)
    await page.goto(kind === 'callback' ? '/auth/callback?error=access_denied' : '/auth/error?kind=unavailable')
    await expect(page.locator('main').getByRole('heading', { name: kind === 'callback' ? 'Sign-in was not completed' : 'Sign-in is temporarily unavailable' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Try signing in again' })).toBeVisible()
    if (process.env.EVIDENCE_DIR) await page.screenshot({ path: join(process.env.EVIDENCE_DIR, `auth-${kind}-${width}-${mode}.png`), fullPage: true })
    expect(errors).toEqual([])
  })
}
