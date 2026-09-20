import { expect, test, type Page } from '@playwright/test'
import { join } from 'node:path'

const cases = [
  { palette: 'claude', mode: 'light', width: 1280, height: 800 },
  { palette: 'claude', mode: 'dark', width: 390, height: 844 },
  { palette: 'ocean', mode: 'light', width: 390, height: 844 },
  { palette: 'ocean', mode: 'dark', width: 1280, height: 800 },
] as const

async function openMap(page: Page, palette: string, mode: string) {
  await page.addInitScript(
    ({ palette, mode }) => {
      localStorage.setItem('hp-palette', palette)
      localStorage.setItem('hp-theme', mode)
    },
    { palette, mode },
  )
  await page.goto('/')
  await expect(page.locator('#attack-map.leaflet-shadcn')).toBeVisible()
  await page.evaluate(
    ({ palette, mode }) => {
      localStorage.setItem('hp-theme', mode)
      window.dispatchEvent(new StorageEvent('storage', { key: 'hp-theme', newValue: mode }))
      localStorage.setItem('hp-palette', palette)
      window.dispatchEvent(new StorageEvent('storage', { key: 'hp-palette', newValue: palette }))
    },
    { palette, mode },
  )
  await expect(page.locator('html')).toHaveAttribute('data-hp-theme', palette)
  await expect(page.locator('html')).toHaveAttribute('data-theme', mode)
  await expect(page.locator('#attack-map.leaflet-shadcn')).toBeVisible()
  await expect(page.locator('#attack-map .leaflet-control-zoom')).toBeVisible()
}

async function mapState(page: Page) {
  return page.locator('#attack-map').evaluate((host) => {
    const map = (host as HTMLDivElement & { __xoreLeaflet?: import('leaflet').Map }).__xoreLeaflet
    if (!map) throw new Error('leaflet seam missing')
    let tileUrl = ''
    map.eachLayer((layer) => {
      const candidate = layer as typeof layer & { _url?: string }
      if (candidate._url) tileUrl = candidate._url
    })
    return { zoom: map.getZoom(), tileUrl }
  })
}

async function themeColors(page: Page) {
  return page.locator('#attack-map').evaluate((host) => {
    const probe = document.createElement('span')
    document.documentElement.appendChild(probe)
    const color = (value: string) => {
      probe.style.color = value
      return getComputedStyle(probe).color
    }
    const token = (name: string) => color(`var(${name})`)
    const tile = host.querySelector('.leaflet-tile-pane') as HTMLElement
    const zoom = host.querySelector('.leaflet-control-zoom-in') as HTMLElement
    const attribution = host.querySelector('.leaflet-control-attribution') as HTMLElement
    const actual = {
      tile: getComputedStyle(tile).backgroundColor,
      zoomBackground: getComputedStyle(zoom).backgroundColor,
      zoomForeground: getComputedStyle(zoom).color,
      attributionBackground: getComputedStyle(attribution).backgroundColor,
      attributionForeground: getComputedStyle(attribution).color,
    }
    const expected = {
      tile: token('--background'),
      zoomBackground: token('--popover'),
      zoomForeground: token('--popover-foreground'),
      attributionBackground: token('--popover'),
      attributionForeground: token('--popover-foreground'),
    }
    probe.remove()
    return { actual, expected }
  })
}

for (const entry of cases) {
  test(`${entry.palette}/${entry.mode}/${entry.width} themes leaflet controls and keeps interactions`, async ({ page }) => {
    await page.setViewportSize({ width: entry.width, height: entry.height })
    await openMap(page, entry.palette, entry.mode)

    const colors = await themeColors(page)
    expect(colors.actual).toEqual(colors.expected)

    const before = await mapState(page)
    expect(before.tileUrl).toContain('{z}/{x}/{y}')

    const marker = page.getByRole('link', { name: 'Amsterdam, NL, 44 events' })
    await marker.hover()
    await expect(page.locator('#attack-map .leaflet-tooltip')).toBeVisible()

    await page.locator('#attack-map .leaflet-control-zoom-in').click()
    await expect.poll(async () => (await mapState(page)).zoom).toBe(before.zoom + 1)

    const nextMode = entry.mode === 'light' ? 'dark' : 'light'
    await page.evaluate((mode) => {
      localStorage.setItem('hp-theme', mode)
      window.dispatchEvent(new StorageEvent('storage', { key: 'hp-theme', newValue: mode }))
    }, nextMode)
    await page.mouse.move(0, 0)
    await expect(page.locator('html')).toHaveAttribute('data-theme', nextMode)
    await expect.poll(async () => (await themeColors(page)).actual).not.toEqual(colors.actual)
    const updatedColors = await themeColors(page)
    expect(updatedColors.actual).toEqual(updatedColors.expected)
    expect((await mapState(page)).tileUrl).not.toBe(before.tileUrl)

    if (process.env.EVIDENCE_DIR) {
      await page.screenshot({
        path: join(process.env.EVIDENCE_DIR, `leaflet-${entry.palette}-${entry.mode}-${entry.width}.png`),
        fullPage: true,
      })
    }
  })
}
