import type cytoscape from 'cytoscape'
import { cssVar } from './cssVar'

function cytoscapeColor(value: string): string {
  const canvas = document.createElement('canvas')
  canvas.width = canvas.height = 1
  const context = canvas.getContext('2d')
  if (!context) return value
  context.fillStyle = value
  context.fillRect(0, 0, 1, 1)
  const [red, green, blue, alpha] = context.getImageData(0, 0, 1, 1).data
  return alpha === 255 ? `rgb(${red}, ${green}, ${blue})` : `rgba(${red}, ${green}, ${blue}, ${alpha / 255})`
}

export function cytoscapeTheme(): cytoscape.StylesheetStyle[] {
  const foreground = cytoscapeColor(cssVar('--foreground', '#e9e6df'))
  const card = cytoscapeColor(cssVar('--card', '#383835'))
  const border = cytoscapeColor(cssVar('--border', 'rgba(255,255,255,0.14)'))
  const mutedForeground = cytoscapeColor(cssVar('--muted-foreground', '#a5a9a6'))
  const charts = [
    cssVar('--chart-1', '#d97757'),
    cssVar('--chart-2', '#79c99e'),
    cssVar('--chart-3', '#78a9d4'),
    cssVar('--chart-4', '#deb36a'),
    cssVar('--chart-5', '#dc7774'),
  ].map(cytoscapeColor)

  return [
    {
      selector: 'node',
      style: {
        label: 'data(label)',
        'font-size': 10,
        color: mutedForeground,
        'text-valign': 'bottom',
        'text-margin-y': 6,
        'background-color': card,
        'border-color': charts[0],
        'border-width': 1.2,
        width: 26,
        height: 26,
      },
    },
    {
      selector: 'node[kind = "hub"]',
      style: {
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': 12,
        'font-weight': 600,
        color: foreground,
        'background-color': charts[0],
        'border-color': charts[1],
        'border-width': 2,
        width: 56,
        height: 56,
      },
    },
    {
      selector: 'node[kind = "overflow"]',
      style: {
        'background-color': card,
        'border-color': charts[4],
        color: mutedForeground,
      },
    },
    {
      selector: 'edge',
      style: {
        width: 1.2,
        'line-color': border,
        'curve-style': 'straight',
      },
    },
    {
      selector: 'element:selected',
      style: {
        'overlay-color': charts[3],
        'overlay-opacity': 0.18,
        'overlay-padding': 6,
      },
    },
    {
      selector: 'node.hover',
      style: {
        'background-color': charts[2],
        'border-color': foreground,
      },
    },
    {
      selector: 'edge.hover',
      style: {
        'line-color': charts[2],
        width: 2,
      },
    },
  ]
}
