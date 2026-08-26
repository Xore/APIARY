// ECharts theming for xore/theme, ported from hp-echarts-theme.js
// (#1532): canvas can't resolve CSS var() references, so every color is
// resolved to its literal value via getComputedStyle at init time, and
// the "xore" theme is re-registered on each chart init so a live theme
// toggle is picked up by the next chart. Client-only module.
//
// #1964: this is the app's only echarts entry point, and it goes through
// echarts/core with explicit registration instead of the full barrel.
// EChart.tsx draws nine kinds (sankey, timeline, heatmap, pie, line, bar,
// barh, scatter, radar); the barrel also shipped gl stubs, treemap,
// sunburst, themeRiver, funnel, gauge and friends that no builder will
// ever ask for -- roughly two thirds of the chunk a browser parses before
// the first chart card hydrates. Registration lives here rather than at
// the call sites so the builders stay declarative about options only:
// adding a tenth kind means one import above and nowhere else. The
// component set below is exactly what those builders' options reference;
// TooltipComponent installs the axis pointer its trigger:'axis' needs, so
// nothing else is required for parity with the barrel import.
import * as echarts from 'echarts/core'
import {
  BarChart,
  CustomChart,
  HeatmapChart,
  LineChart,
  PieChart,
  RadarChart,
  SankeyChart,
  ScatterChart,
} from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent, VisualMapComponent } from 'echarts/components'
import { LabelLayout } from 'echarts/features'
import { CanvasRenderer } from 'echarts/renderers'

import { cssVar } from './cssVar'

echarts.use([
  // sankey/timeline/heatmap/pie/line/bar/barh/scatter/radar: bar covers
  // both bar orientations, and CustomChart is the campaign timeline's
  // custom-series renderer.
  BarChart,
  CustomChart,
  HeatmapChart,
  LineChart,
  PieChart,
  RadarChart,
  SankeyChart,
  ScatterChart,
  GridComponent,
  LegendComponent,
  TooltipComponent,
  VisualMapComponent,
  CanvasRenderer,
  // #2130: LabelLayout is the feature that implements labelLayout's
  // hideOverlap/moveOverlap -- a lifecycle hook, not a component, so no
  // chart or component registration above pulls it in. Missing from this
  // list, any `labelLayout` option is silently ignored and sankey labels
  // overprint each other; the full-barrel builds of echarts happen to
  // keep it, which is why labs never reproduced the app behavior.
  LabelLayout,
])

export { echarts }

export const chartColor = cssVar

function buildTheme() {
  const textPrimary = chartColor('--text-000', '#e9e6df')
  const textMuted = chartColor('--text-200', '#a5a9a6')
  const border = chartColor('--border-200', 'rgba(255,255,255,0.14)')
  const borderSubtle = chartColor('--border-100', 'rgba(255,255,255,0.075)')
  const surface = chartColor('--bg-raised', '#383835')
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
