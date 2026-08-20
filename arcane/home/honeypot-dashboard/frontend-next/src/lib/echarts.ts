// ECharts theming for xore/theme, ported from hp-echarts-theme.js
// (#1532): canvas can't resolve CSS var() references, so every color is
// resolved to its literal value via getComputedStyle at init time, and
// the "xore" theme is re-registered on each chart init so a live theme
// toggle is picked up by the next chart. Client-only module.
import * as echarts from 'echarts'
import { cssVar } from './cssVar'

export { echarts }

export const chartColor = cssVar

function buildTheme() {
  const textPrimary = chartColor('--text-primary', '#e9e6df')
  const textMuted = chartColor('--text-muted', '#a5a9a6')
  const border = chartColor('--border-strong', 'rgba(255,255,255,0.14)')
  const borderSubtle = chartColor('--border-subtle', 'rgba(255,255,255,0.075)')
  const surface = chartColor('--surface-raised', '#383835')
  const accent = chartColor('--accent', '#d97757')
  const axis = {
    axisLine: { lineStyle: { color: border } },
    axisTick: { lineStyle: { color: border } },
    axisLabel: { color: textMuted },
    splitLine: { lineStyle: { color: borderSubtle } },
  }
  return {
    color: [
      accent,
      chartColor('--info', '#78a9d4'),
      chartColor('--success', '#79c99e'),
      chartColor('--warning', '#deb36a'),
      chartColor('--danger', '#dc7774'),
    ],
    backgroundColor: 'transparent',
    textStyle: { color: textPrimary },
    title: { textStyle: { color: textPrimary }, subtextStyle: { color: textMuted } },
    legend: { textStyle: { color: textPrimary } },
    tooltip: { backgroundColor: surface, borderColor: border, textStyle: { color: textPrimary } },
    visualMap: { textStyle: { color: textMuted } },
    categoryAxis: axis,
    valueAxis: axis,
    timeAxis: axis,
    logAxis: axis,
  }
}

export function registerXoreTheme() {
  echarts.registerTheme('xore', buildTheme())
}
