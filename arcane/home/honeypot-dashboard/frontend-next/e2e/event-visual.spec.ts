import { expect, test } from '@playwright/test'
import { join } from 'node:path'

for (const width of [1280, 390]) for (const mode of ['light', 'dark']) {
  test(`event detail ${width} ${mode} loads without console errors`, async ({ page }, testInfo) => {
    const errors: string[] = []
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
    await page.setViewportSize({ width, height: 844 })
    await page.addInitScript(value => {
      localStorage.setItem('hp-palette', 'claude')
      localStorage.setItem('hp-theme', value)
    }, mode)
    await page.goto('/event/e2e-event-0')
    await expect(page.getByRole('heading', { name: 'citrix-honeypot event' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'The complete record' })).toBeVisible()
    await expect(page.getByText('cve_2019_19781_payload', { exact: true })).toBeVisible()
    const shot = process.env.EVIDENCE_DIR
      ? join(process.env.EVIDENCE_DIR, 'shots', `event-${width}-${mode}.png`)
      : testInfo.outputPath(`event-${width}-${mode}.png`)
    await page.screenshot({ path: shot, fullPage: true })
    expect(errors).toEqual([])
  })
}

test('missing event renders the not-found state', async ({ page }, testInfo) => {
  await page.goto('/event/missing-e2e-event')
  await expect(page.getByText('Event not found')).toBeVisible()
  const shot = process.env.EVIDENCE_DIR
    ? join(process.env.EVIDENCE_DIR, 'shots', 'event-missing.png')
    : testInfo.outputPath('event-missing.png')
  await page.screenshot({ path: shot, fullPage: true })
})
