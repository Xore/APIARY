import { expect, test, type Page } from '@playwright/test'
import { join } from 'node:path'

const cases = [
  { palette: 'claude', mode: 'light', width: 1280, height: 800 },
  { palette: 'claude', mode: 'dark', width: 390, height: 844 },
  { palette: 'ocean', mode: 'light', width: 390, height: 844 },
  { palette: 'ocean', mode: 'dark', width: 1280, height: 800 },
] as const

async function openGraph(page: Page, palette: string, mode: string) {
  await page.addInitScript(
    ({ palette, mode }) => {
      localStorage.setItem('hp-palette', palette)
      localStorage.setItem('hp-theme', mode)
    },
    { palette, mode },
  )
  await page.goto('/attackers')
  await page.locator('table tbody tr').first().click()
  const graph = page.getByRole('img', { name: 'Attacker entity graph around one entity node' })
  await expect(graph).toBeVisible()
  await expect.poll(() => graph.evaluate(host => Boolean((host as HTMLElement & { __xoreCytoscape?: unknown }).__xoreCytoscape))).toBe(true)
}

async function graphTheme(page: Page) {
  return page.getByRole('img', { name: 'Attacker entity graph around one entity node' }).evaluate((host) => {
    const cy = (host as HTMLElement & { __xoreCytoscape?: import('cytoscape').Core }).__xoreCytoscape
    if (!cy) throw new Error('cytoscape seam missing')

    const probe = document.createElement('span')
    const canvas = document.createElement('canvas')
    canvas.width = canvas.height = 1
    const context = canvas.getContext('2d')!
    document.documentElement.appendChild(probe)
    const color = (value: string) => {
      probe.style.color = value
      context.clearRect(0, 0, 1, 1)
      context.fillStyle = getComputedStyle(probe).color
      context.fillRect(0, 0, 1, 1)
      const [red, green, blue, alpha] = context.getImageData(0, 0, 1, 1).data
      return alpha === 255 ? `rgb(${red}, ${green}, ${blue})` : `rgba(${red}, ${green}, ${blue}, ${alpha / 255})`
    }
    const channels = (value: string) => color(value).match(/[\d.]+/g)?.map(Number)
    const token = (name: string) => color(`var(${name})`)
    const rules = Object.fromEntries((cy.json().style as Array<{ selector: string; style: Record<string, string> }>).map(rule => [rule.selector, rule.style]))
    const ruleColor = (selector: string, property: string) => color(String(rules[selector][property]))
    const hub = cy.nodes('[kind = "hub"]').first()
    const spoke = cy.nodes('[kind = "spoke"]').first()
    const edge = cy.edges().first()

    spoke.emit('mouseover')
    edge.emit('mouseover')
    const interaction = {
      nodeHover: color(spoke.style('background-color')),
      edgeHover: color(edge.style('line-color')),
      nodeClass: spoke.hasClass('hover'),
      edgeClass: edge.hasClass('hover'),
    }
    spoke.emit('mouseout')
    edge.emit('mouseout')
    hub.select()

    const actual = {
      nodeBackground: color(spoke.style('background-color')),
      nodeBorder: color(spoke.style('border-color')),
      nodeText: color(spoke.style('color')),
      hubBackground: color(hub.style('background-color')),
      hubBorder: color(hub.style('border-color')),
      hubText: color(hub.style('color')),
      edge: (edge as unknown as { pstyle(name: string): { value: number[] } }).pstyle('line-color').value,
      selected: color(hub.style('overlay-color')),
      overflow: ruleColor('node[kind = "overflow"]', 'border-color'),
    }
    const expected = {
      nodeBackground: token('--card'),
      nodeBorder: token('--chart-1'),
      nodeText: token('--muted-foreground'),
      hubBackground: token('--chart-1'),
      hubBorder: token('--chart-2'),
      hubText: token('--foreground'),
      edge: channels('var(--border)'),
      selected: token('--chart-4'),
      overflow: token('--chart-5'),
    }
    const hoverColor = token('--chart-3')
    probe.remove()
    return {
      actual,
      expected,
      interaction,
      hoverColor,
      counts: { nodes: cy.nodes().length, edges: cy.edges().length },
    }
  })
}

for (const entry of cases) {
  test(`${entry.palette}/${entry.mode}/${entry.width} uses the exact shadcn cytoscape theme`, async ({ page }) => {
    await page.setViewportSize({ width: entry.width, height: entry.height })
    await openGraph(page, entry.palette, entry.mode)

    const theme = await graphTheme(page)
    expect(theme.actual).toEqual(theme.expected)
    expect(theme.counts).toEqual({ nodes: 2, edges: 1 })
    expect(theme.interaction).toEqual({
      nodeHover: theme.hoverColor,
      edgeHover: theme.hoverColor,
      nodeClass: true,
      edgeClass: true,
    })

    const nextMode = entry.mode === 'light' ? 'dark' : 'light'
    await page.evaluate((mode) => {
      localStorage.setItem('hp-theme', mode)
      window.dispatchEvent(new StorageEvent('storage', { key: 'hp-theme', newValue: mode }))
    }, nextMode)
    await expect(page.locator('html')).toHaveAttribute('data-theme', nextMode)
    const updatedTheme = await graphTheme(page)
    expect(updatedTheme.actual).toEqual(updatedTheme.expected)
    expect(updatedTheme.counts).toEqual(theme.counts)

    if (process.env.EVIDENCE_DIR) {
      await page.screenshot({
        path: join(process.env.EVIDENCE_DIR, `cytoscape-${entry.palette}-${entry.mode}-${entry.width}.png`),
        fullPage: true,
      })
    }

    await page.getByRole('img', { name: 'Attacker entity graph around one entity node' }).evaluate((host) => {
      const cy = (host as HTMLElement & { __xoreCytoscape?: import('cytoscape').Core }).__xoreCytoscape
      cy?.nodes('[kind = "spoke"]').emit('tap')
    })
    await expect(page).toHaveURL(/\/events\?ip=203\.0\.113\.7/)
  })
}
