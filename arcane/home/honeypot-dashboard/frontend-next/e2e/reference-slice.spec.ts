import { expect, test } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { SESSION_COOKIE_NAME, fixtureSid } from './fixture-session'

const evidence = process.env.EVIDENCE_DIR

const SETTINGS_PANES = ['account', 'appearance', 'navigation', 'time', 'map'] as const
const IP_TABS = ['Activity', 'Indicators', 'Correlation & timeline'] as const
const VIEWPORTS = [
  { label: '1280', width: 1280, height: 900 },
  { label: '390', width: 390, height: 844 },
] as const

for (const vp of VIEWPORTS) {
  for (const mode of ['light', 'dark'] as const) {
    test('reference captures ' + vp.label + '/' + mode, async ({ page }) => {
      test.setTimeout(180_000)
      const errors: string[] = []
      page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()) })
      page.on('pageerror', (error) => errors.push(error.message))
      await page.setViewportSize({ width: vp.width, height: vp.height })
      await page.addInitScript((m) => {
        localStorage.setItem('hp-theme', m)
        localStorage.setItem('hp-palette', 'claude')
      }, mode)
      if (evidence) await mkdir(join(evidence, 'captures'), { recursive: true })

      for (const pane of SETTINGS_PANES) {
        await page.goto('/settings?pane=' + pane)
        await expect(page.locator('[data-hp-pane="' + pane + '"]')).toBeVisible()
        await expect(page.getByText('Preferences could not be loaded')).toHaveCount(0)
        const name = 'settings-' + pane
        if (evidence) await page.screenshot({ path: join(evidence, 'captures', name + '-' + vp.label + '-' + mode + '.png') })
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
        expect(overflow, name).toBe(false)
      }

      await page.goto('/investigate/ip/203.0.113.7')
      await expect(page.getByText('Sensors contacted', { exact: true })).toBeVisible()
      for (const tab of IP_TABS) {
        await page.getByRole('tab', { name: tab, exact: true }).click()
        const name = 'ip-' + tab.toLowerCase().replace(/[^a-z0-9]+/g, '-')
        if (evidence) await page.screenshot({ path: join(evidence, 'captures', name + '-' + vp.label + '-' + mode + '.png') })
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
        expect(overflow, name).toBe(false)
      }
      await page.getByRole('tab', { name: 'Activity', exact: true }).click()
      await expect(page.locator('a[href="/sessions/fixture-session-1"]')).toBeVisible()
      await expect(page.locator('a[href="/api/export/events.csv?ip=203.0.113.7"]')).toBeVisible()
      await page.getByRole('tab', { name: 'Indicators', exact: true }).click()
      await expect(page.getByRole('link', { name: /T1110/ })).toBeVisible()
      await expect(page.getByRole('button', { name: 'block', exact: true })).toBeVisible()
      expect(errors).toEqual([])
    })
  }
}

test('settings page and modal preserve heading hierarchy and modal dismissal', async ({ page }) => {
  await page.goto('/settings?pane=account')
  await expect(page.locator('h2#hp-dash-settings-title')).toBeVisible()
  await page.goto('/')
  const trigger = page.getByRole('link', { name: 'Account and settings', exact: true })
  await trigger.click()
  await expect(page.locator('h1#hp-dash-settings-title')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.locator('#hp-dash-settings-title')).toHaveCount(0)
  await expect(trigger).toBeFocused()
})

test('settings search keeps staged edits and inactive panes; user role gets no admin panes', async ({ page, context }) => {
  await context.addCookies([{ name: SESSION_COOKIE_NAME, value: fixtureSid('user'), domain: '127.0.0.1', path: '/', secure: true }])
  await page.goto('/settings?pane=services')
  await expect(page.locator('[data-hp-pane="account"]')).toBeVisible()
  await expect(page.locator('[data-hp-pane="services"]')).toHaveCount(0)
  await page.getByRole('button', { name: 'Time & live data', exact: true }).click()
  await page.getByLabel('Timezone').fill('Europe/Berlin')
  await page.getByRole('button', { name: 'Account', exact: true }).click()
  const search = page.getByRole('searchbox', { name: 'Search settings' })
  await search.fill('timezone')
  await expect(page.getByLabel('Timezone')).toHaveValue('Europe/Berlin')
  await search.press('Escape')
  await expect(search).toHaveValue('')
  await expect(page.locator('[data-hp-pane="account"]')).toBeVisible()
})
