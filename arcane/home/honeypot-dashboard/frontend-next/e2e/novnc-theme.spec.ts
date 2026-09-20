import { expect, test, type Page } from '@playwright/test'
import { join } from 'node:path'

const cases = [
  { palette: 'claude', mode: 'light', width: 1280, height: 800 },
  { palette: 'claude', mode: 'dark', width: 390, height: 844 },
  { palette: 'ocean', mode: 'light', width: 390, height: 844 },
  { palette: 'ocean', mode: 'dark', width: 1280, height: 800 },
] as const

async function openViewer(page: Page, palette: string, mode: string) {
  await page.addInitScript(
    ({ palette, mode }) => {
      localStorage.setItem('hp-palette', palette)
      localStorage.setItem('hp-theme', mode)
      class OpenWebSocket {
        static readonly CONNECTING = 0
        static readonly OPEN = 1
        static readonly CLOSING = 2
        static readonly CLOSED = 3
        binaryType = 'blob'
        onerror: ((event: Event) => void) | null = null
        onmessage: ((event: MessageEvent) => void) | null = null
        onopen: ((event: Event) => void) | null = null
        onclose: ((event: CloseEvent) => void) | null = null
        protocol = ''
        readyState = OpenWebSocket.CONNECTING

        constructor(url: string | URL) {
          ;(window as typeof window & { __novncConnections?: string[] }).__novncConnections ??= []
          ;(window as typeof window & { __novncConnections: string[] }).__novncConnections.push(String(url))
          queueMicrotask(() => {
            this.readyState = OpenWebSocket.OPEN
            this.onopen?.(new Event('open'))
          })
        }

        send() {}

        close() {
          this.readyState = OpenWebSocket.CLOSED
          this.onclose?.(new CloseEvent('close', { wasClean: true }))
        }
      }
      window.WebSocket = OpenWebSocket as unknown as typeof WebSocket
    },
    { palette, mode },
  )
  await page.goto('/sandbox/vnc')
  await expect(page.locator('[data-vnc-state]')).toBeVisible()
  await expect(page.locator('[data-vnc-state] canvas')).toBeAttached({ timeout: 20_000 })
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
  await expect.poll(() => page.evaluate(() => (
    window as typeof window & { __novncConnections?: string[] }
  ).__novncConnections ?? [])).toContain('ws://127.0.0.1:9/e2e-novnc-theme')
}

async function chromeColors(page: Page) {
  return page.locator('[data-vnc-state]').evaluate((host) => {
    const toolbar = host.querySelector('[role="status"]') as HTMLElement
    const frame = host.querySelector('[aria-busy]')?.parentElement as HTMLElement
    const probe = document.createElement('span')
    document.documentElement.appendChild(probe)
    const color = (value: string) => {
      probe.style.color = value
      return getComputedStyle(probe).color
    }
    const token = (name: string) => color(`var(${name})`)
    const hostStyle = getComputedStyle(host)
    const actual = {
      statusForeground: getComputedStyle(toolbar).color,
      frameBorder: getComputedStyle(frame).borderTopColor,
      buttonBackground: color(hostStyle.getPropertyValue('--novnc-button-background')),
      buttonForeground: color(hostStyle.getPropertyValue('--novnc-button-foreground')),
    }
    const expected = {
      statusForeground: token('--muted-foreground'),
      frameBorder: token('--border'),
      buttonBackground: token('--secondary'),
      buttonForeground: token('--secondary-foreground'),
    }
    probe.remove()
    return { actual, expected }
  })
}

for (const entry of cases) {
  test(`${entry.palette}/${entry.mode}/${entry.width} themes noVNC chrome and starts RFB`, async ({ page }) => {
    await page.setViewportSize({ width: entry.width, height: entry.height })
    await openViewer(page, entry.palette, entry.mode)

    const colors = await chromeColors(page)
    expect(colors.actual).toEqual(colors.expected)

    const nextMode = entry.mode === 'light' ? 'dark' : 'light'
    await page.evaluate((mode) => {
      localStorage.setItem('hp-theme', mode)
      window.dispatchEvent(new StorageEvent('storage', { key: 'hp-theme', newValue: mode }))
    }, nextMode)
    await expect(page.locator('html')).toHaveAttribute('data-theme', nextMode)
    await expect.poll(async () => (await chromeColors(page)).actual).not.toEqual(colors.actual)
    const updatedColors = await chromeColors(page)
    expect(updatedColors.actual).toEqual(updatedColors.expected)
    await expect(page.locator('[data-vnc-state] canvas')).toBeAttached()

    if (process.env.EVIDENCE_DIR) {
      await page.screenshot({
        path: join(process.env.EVIDENCE_DIR, `novnc-${entry.palette}-${entry.mode}-${entry.width}.png`),
        fullPage: true,
      })
    }
  })
}
