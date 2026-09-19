import { cssVar } from './cssVar'
import { echarts } from './echarts'

export const chartColor = cssVar

function buildShadcnTheme() {
  const foreground = chartColor('--foreground', '#e9e6df')
  const mutedForeground = chartColor('--muted-foreground', '#a5a9a6')
  const border = chartColor('--border', 'rgba(255,255,255,0.14)')
  const muted = chartColor('--chart-grid', 'rgba(255,255,255,0.075)')
  const card = chartColor('--card', '#383835')
  const axis = {
    axisLine: { lineStyle: { color: border } },
    axisTick: { lineStyle: { color: border } },
    axisLabel: { color: mutedForeground },
    splitLine: { lineStyle: { color: muted } },
  }

  return {
    color: [
      chartColor('--chart-1', '#d97757'),
      chartColor('--chart-2', '#79c99e'),
      chartColor('--chart-3', '#78a9d4'),
      chartColor('--chart-4', '#deb36a'),
      chartColor('--chart-5', '#dc7774'),
    ],
    backgroundColor: 'transparent',
    textStyle: { color: foreground },
    title: { textStyle: { color: foreground }, subtextStyle: { color: mutedForeground } },
    legend: { textStyle: { color: foreground } },
    tooltip: { backgroundColor: card, borderColor: border, textStyle: { color: foreground } },
    visualMap: { textStyle: { color: mutedForeground } },
    categoryAxis: axis,
    valueAxis: axis,
    timeAxis: axis,
    logAxis: axis,
  }
}

export function registerShadcnTheme(): void {
  echarts.registerTheme('shadcn', buildShadcnTheme())
}

export { echarts }
