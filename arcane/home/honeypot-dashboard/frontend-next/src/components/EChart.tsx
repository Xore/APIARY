// Chart card body, ported from hp-kill-chain.js's page-agnostic
// [data-echart] bootstrap: nine builder kinds (sankey/timeline/heatmap/
// pie/line/bar/barh/scatter/radar), each producing the same options —
// and therefore the same rendered pixels — as the legacy dashboard.
// Client-only: echarts is imported dynamically inside useEffect so SSR
// ships the skeleton and the canvas hydrates in.
import { useCallback, useEffect, useRef, useState } from 'react'
import { copyWithFlash } from '../lib/flash'
import { useAppearanceKey } from '../lib/prefs'

export type ChartKind = 'sankey' | 'timeline' | 'heatmap' | 'pie' | 'line' | 'bar' | 'barh' | 'scatter' | 'radar'

type Builder = (
  chart: import('echarts/core').EChartsType,
  data: unknown,
  themeColor: (name: string, fallback?: string) => string,
  echartsModule: typeof import('echarts/core'),
) => string

const humanizeNumber = (n: number): string => {
  const abs = Math.abs(n)
  if (abs >= 1e12) return +(n / 1e12).toFixed(1) + 'T'
  if (abs >= 1e9) return +(n / 1e9).toFixed(1) + 'G'
  if (abs >= 1e6) return +(n / 1e6).toFixed(1) + 'M'
  if (abs >= 1e3) return +(n / 1e3).toFixed(1) + 'K'
  return String(n)
}

type SankeyPayload = { nodes?: { name: string }[]; links?: { source: string; target: string; value: number }[] }
type HeatmapPayload = { tactics?: string[]; techniques?: string[]; cells?: { tactic_idx: number; technique_idx: number; count: number }[] }
type PiePayload = { name: string; value: number }[]
type SeriesPayload = { name: string; points: { time: string; value: number }[] }[]
type BarPayload = { categories?: string[]; values?: number[] }
type RadarPayload = { categories?: string[]; values?: number[] }
type TimelinePayload = { cidr: string; start_ms: number; end_ms: number; score: number; events: number }[]

const builders: Record<ChartKind, Builder> = {
  sankey: (chart, raw, themeColor) => {
    const data = (raw ?? {}) as SankeyPayload
    const nodes = data.nodes ?? []
    const links = data.links ?? []
    chart.setOption({
      tooltip: { trigger: 'item' },
      series:
        nodes.length === 0
          ? []
          : [
              {
                type: 'sankey',
                orient: 'vertical',
                emphasis: { focus: 'adjacency' },
                data: nodes,
                links,
                lineStyle: { color: 'gradient', curveness: 0.5 },
                label: { position: 'top', color: themeColor('--text-000', '#e9e6df') },
              },
            ],
    })
    if (nodes.length === 0) return 'No attacker sessions with a recognized ATT&CK technique yet.'
    return `${nodes.length} tactic${nodes.length === 1 ? '' : 's'} observed, ${links.length} flow${links.length === 1 ? '' : 's'}.`
  },

  heatmap: (chart, raw, themeColor) => {
    const data = (raw ?? {}) as HeatmapPayload
    const tactics = data.tactics ?? []
    const techniques = data.techniques ?? []
    const cells = data.cells ?? []
    const max = cells.reduce((m, c) => Math.max(m, c.count), 1)
    chart.setOption({
      tooltip: { position: 'top' },
      grid: { height: '70%', top: '8%', left: '22%' },
      xAxis: {
        type: 'category',
        data: tactics,
        splitArea: { show: true, areaStyle: { color: [themeColor('--bg-200', '#2c2c2a'), themeColor('--bg-300', '#232321')] } },
        axisLabel: { rotate: 30, color: themeColor('--text-000', '#e9e6df') },
      },
      yAxis: {
        type: 'category',
        data: techniques,
        splitArea: { show: true, areaStyle: { color: [themeColor('--bg-200', '#2c2c2a'), themeColor('--bg-300', '#232321')] } },
        axisLabel: { color: themeColor('--text-000', '#e9e6df') },
      },
      visualMap: {
        min: 0,
        max,
        calculable: true,
        orient: 'horizontal',
        left: 'center',
        bottom: '0%',
        inRange: { color: [themeColor('--bg-400', '#3d3d3b'), themeColor('--accent', '#d97757')] },
      },
      series: [
        {
          type: 'heatmap',
          data: cells.map((c) => [c.tactic_idx, c.technique_idx, c.count]),
          label: { show: true },
          emphasis: { itemStyle: { shadowBlur: 10, shadowColor: 'rgba(0,0,0,0.5)' } },
        },
      ],
    })
    if (techniques.length === 0) return 'No ATT&CK-mapped technique evidence yet.'
    return `${techniques.length} technique${techniques.length === 1 ? '' : 's'} across ${new Set(cells.map((c) => c.tactic_idx)).size} tactics.`
  },

  pie: (chart, raw, themeColor) => {
    const data = (raw ?? []) as PiePayload
    const total = data.reduce((sum, d) => sum + (d.value || 0), 0)
    const trimmed = data.map((d) => {
      const pct = total > 0 ? ((d.value || 0) / total) * 100 : 0
      return pct < 2 ? { ...d, label: { show: false }, labelLine: { show: false } } : d
    })
    chart.setOption({
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { orient: 'vertical', left: 'left', textStyle: { color: themeColor('--text-000', '#e9e6df') } },
      series: [
        {
          type: 'pie',
          radius: ['35%', '65%'],
          avoidLabelOverlap: true,
          itemStyle: { borderColor: themeColor('--bg-200', '#2c2c2a'), borderWidth: 2 },
          label: { color: themeColor('--text-000', '#e9e6df') },
          data: trimmed,
        },
      ],
    })
    if (data.length === 0) return 'No data yet.'
    return `${data.length} categor${data.length === 1 ? 'y' : 'ies'}, ${total} total.`
  },

  radar: (chart, raw, themeColor) => {
    const data = (raw ?? {}) as RadarPayload
    const categories = data.categories ?? []
    const values = data.values ?? []
    const max = Math.max(1, ...values)
    chart.setOption({
      tooltip: { trigger: 'item' },
      radar: {
        indicator: categories.map((c) => ({ name: c, max })),
        axisName: { color: themeColor('--text-000', '#e9e6df') },
        axisLine: { lineStyle: { color: themeColor('--border-200', 'rgba(255,255,255,0.14)') } },
        splitLine: { lineStyle: { color: themeColor('--border-100', 'rgba(255,255,255,0.075)') } },
        splitArea: { areaStyle: { color: ['transparent'] } },
      },
      series: [
        {
          type: 'radar',
          data: [{ value: values, areaStyle: { opacity: 0.25 }, itemStyle: { color: themeColor('--accent', '#d97757') } }],
        },
      ],
    })
    const total = values.reduce((sum, v) => sum + v, 0)
    if (categories.length === 0) return 'No data yet.'
    if (total === 0) return "No shared signals across this entity's member IPs yet."
    return `${total} shared signal value${total === 1 ? '' : 's'} across ${categories.length} categories.`
  },

  line: (chart, raw) => {
    const data = (raw ?? []) as SeriesPayload
    const totalPoints = data.reduce((sum, s) => sum + s.points.length, 0)
    chart.setOption({
      tooltip: { trigger: 'axis' },
      legend: {},
      grid: { left: '12%', right: '5%' },
      xAxis: {
        type: 'time',
        axisLabel: {
          formatter: {
            year: '{yyyy}',
            month: '{MMM}',
            day: '{MMM} {d}',
            hour: '{HH}:{mm}',
            minute: '{HH}:{mm}',
            second: '{HH}:{mm}:{ss}',
          },
        },
      },
      yAxis: { type: 'value', axisLabel: { formatter: humanizeNumber } },
      series: data.map((s) => ({
        name: s.name,
        type: 'line',
        showSymbol: false,
        areaStyle: { opacity: 0.15 },
        data: s.points.map((p) => [p.time, p.value]),
      })),
    })
    if (totalPoints === 0) return 'No data yet.'
    return `${data.length} series, ${totalPoints} points.`
  },

  bar: (chart, raw, themeColor) => {
    const data = (raw ?? {}) as BarPayload
    const categories = data.categories ?? []
    const values = data.values ?? []
    const longLabels = categories.some((c) => c.length > 14)
    chart.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: '10%', right: '5%', bottom: longLabels ? 130 : 30 },
      xAxis: {
        type: 'category',
        data: categories,
        axisLabel: {
          color: themeColor('--text-000', '#e9e6df'),
          rotate: longLabels ? 30 : 0,
          overflow: longLabels ? 'break' : undefined,
          width: longLabels ? 200 : undefined,
        },
      },
      yAxis: { type: 'value', axisLabel: { formatter: humanizeNumber } },
      series: [{ type: 'bar', barMaxWidth: 56, data: values, itemStyle: { color: themeColor('--accent', '#d97757') } }],
    })
    const total = values.reduce((sum, v) => sum + v, 0)
    if (categories.length === 0) return 'No data yet.'
    return `${categories.length} bucket${categories.length === 1 ? '' : 's'}, ${total} total.`
  },

  barh: (chart, raw, themeColor) => {
    const data = (raw ?? {}) as BarPayload
    const categories = data.categories ?? []
    const values = data.values ?? []
    chart.setOption({
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: '34%', right: '8%', top: 10, bottom: 10 },
      xAxis: { type: 'value', axisLabel: { formatter: humanizeNumber } },
      yAxis: {
        type: 'category',
        data: categories,
        inverse: true,
        axisLabel: { color: themeColor('--text-000', '#e9e6df'), overflow: 'truncate', width: 220 },
      },
      series: [{ type: 'bar', barMaxWidth: 18, data: values, itemStyle: { color: themeColor('--accent', '#d97757') } }],
    })
    chart.off('click')
    chart.on('click', (params) => {
      if (params.componentType !== 'series') return
      const label = categories[params.dataIndex]
      // Visible confirmation, hp-kill-chain.js flashCopied's contract —
      // a silent copy (and a silently swallowed failure) reads as a dead
      // click (#1653).
      if (label) copyWithFlash(label)
    })
    const total = values.reduce((sum, v) => sum + v, 0)
    if (categories.length === 0) return 'No data yet.'
    return `${categories.length} fingerprint${categories.length === 1 ? '' : 's'}, ${total} total. Click a bar to copy its full value.`
  },

  scatter: (chart, raw) => {
    const data = (raw ?? []) as SeriesPayload
    const totalPoints = data.reduce((sum, s) => sum + s.points.length, 0)
    chart.setOption({
      tooltip: {
        trigger: 'item',
        formatter: (p: { seriesName: string; value: [string, number] }) => `${p.seriesName}: ${p.value[1].toFixed(3)}`,
      },
      legend: {},
      grid: { left: '12%', right: '5%' },
      xAxis: { type: 'time' },
      yAxis: { type: 'value' },
      series: data.map((s) => ({
        name: s.name,
        type: 'scatter',
        symbolSize: 6,
        data: s.points.map((p) => [p.time, p.value]),
      })),
    })
    if (totalPoints === 0) return 'No anomalies scored yet.'
    return `${data.length} series, ${totalPoints} points.`
  },

  timeline: (chart, raw, themeColor, echartsModule) => {
    const rows = (raw ?? []) as TimelinePayload
    const categories = rows.map((r) => r.cidr)
    const maxScore = rows.reduce((m, r) => Math.max(m, r.score), 1)
    chart.setOption({
      tooltip: {
        formatter: (p: { value: number[] }) => {
          const r = rows[p.value[0]]
          return `${r.cidr}<br/>score ${r.score} &middot; ${r.events} events`
        },
      },
      grid: { left: '18%' },
      xAxis: { type: 'time' },
      yAxis: { type: 'category', data: categories },
      visualMap: {
        min: 0,
        max: maxScore,
        dimension: 3,
        show: false,
        inRange: { color: [themeColor('--info', '#78a9d4'), themeColor('--accent', '#d97757'), themeColor('--danger', '#dc7774')] },
      },
      series: [
        {
          type: 'custom',
          renderItem: (params: any, api: any) => {
            const categoryIndex = api.value(0)
            const start = api.coord([api.value(1), categoryIndex])
            const end = api.coord([api.value(2), categoryIndex])
            const height = api.size([0, 1])[1] * 0.6
            const rectShape = echartsModule.graphic.clipRectByRect(
              { x: start[0], y: start[1] - height / 2, width: Math.max(end[0] - start[0], 2), height },
              { x: params.coordSys.x, y: params.coordSys.y, width: params.coordSys.width, height: params.coordSys.height },
            )
            return rectShape && { type: 'rect', transition: ['shape'], shape: rectShape, style: api.style() }
          },
          encode: { x: [1, 2], y: 0 },
          data: rows.map((r, i) => [i, r.start_ms, r.end_ms, r.score]),
        },
      ],
    })
    if (rows.length === 0) return 'No campaigns in the current window.'
    return `${rows.length} campaign${rows.length === 1 ? '' : 's'} plotted.`
  },
}

export function EChart({ kind, url, height }: { kind: ChartKind; url: string; height: number }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState('Loading…')
  const [state, setState] = useState<'loading' | 'ready' | 'empty' | 'error'>('loading')
  // #1757: the payload is kept so an appearance change can repaint from it.
  // Every colour in a chart is resolved from a CSS custom property into a
  // pixel value at build time and cannot re-resolve itself, so a theme change
  // has to rebuild -- but a theme change is not new data, and making it cost
  // a refetch would put a network round trip behind a toggle.
  const dataRef = useRef<unknown>(null)
  const chartRef = useRef<import('echarts/core').EChartsType | null>(null)
  const observerRef = useRef<ResizeObserver | null>(null)
  const appearance = useAppearanceKey()

  const teardown = useCallback(() => {
    observerRef.current?.disconnect()
    observerRef.current = null
    chartRef.current?.dispose()
    chartRef.current = null
  }, [])

  // Build (or rebuild) the chart from whatever is already in dataRef.
  //
  // ECharts binds its theme at init(), so re-registering does not reach an
  // existing instance -- repainting means dispose and re-init. That is cheap
  // next to the fetch this deliberately does not repeat.
  const paint = useCallback(async () => {
    const container = containerRef.current
    if (!container || dataRef.current == null) return
    const { echarts, chartColor, registerXoreTheme } = await import('../lib/echarts')
    if (!containerRef.current) return
    teardown()
    registerXoreTheme()
    const chart = echarts.init(container, 'xore')
    chartRef.current = chart
    const summary = builders[kind](chart, dataRef.current, chartColor, echarts)
    if (summary.startsWith('No ')) {
      teardown()
      setState('empty')
      setStatus(summary)
      return
    }
    setState('ready')
    setStatus(summary)
    const observer = new ResizeObserver(() => chartRef.current?.resize())
    observer.observe(container)
    observerRef.current = observer
  }, [kind, teardown])

  // Data: fetch once per kind/url, then paint.
  useEffect(() => {
    let disposed = false
    ;(async () => {
      try {
        const response = await fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' } })
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
        const data = await response.json()
        if (disposed) return
        dataRef.current = data
        await paint()
      } catch (error) {
        if (!disposed) {
          setState('error')
          setStatus(`Chart failed to load: ${error instanceof Error ? error.message : String(error)}`)
        }
      }
    })()
    return () => {
      disposed = true
      teardown()
    }
  }, [kind, url, paint, teardown])

  // Appearance: repaint in place, no refetch. Skipped on the first run --
  // the data effect above has just painted, or has nothing to paint yet.
  const paintedFor = useRef<string | null>(null)
  useEffect(() => {
    if (paintedFor.current === null) {
      paintedFor.current = appearance
      return
    }
    if (paintedFor.current === appearance) return
    paintedFor.current = appearance
    void paint()
  }, [appearance, paint])

  return (
    <>
      {/* echarts.init(container, ...) below injects its own DOM nodes
          directly into this div, entirely outside React's tracking. It
          must never also be a parent React renders children into --
          confirmed live (#1628): mixing the two crashed every chart that
          ever reached 'empty' (no data) with "Failed to execute
          'removeChild' on 'Node': the node to be removed is not a child
          of this node", because chart.dispose() below removes echarts'
          own DOM synchronously, inside the same effect tick as the
          setState that swaps in the "No data yet" React children --
          React's reconciler then tries to remove a sibling node echarts
          already tore down. Loading/empty/error status is rendered as an
          absolutely-positioned OVERLAY SIBLING instead, inside a
          position:relative wrapper, so React never owns any node inside
          the div echarts controls. */}
      <div style={{ position: 'relative', width: '100%', height }}>
        <div
          ref={containerRef}
          style={{ width: '100%', height }}
          aria-busy={state === 'loading'}
          role={state === 'error' ? 'alert' : undefined}
        />
        {state === 'loading' ? (
          <span
            className="skeleton-line"
            aria-hidden="true"
            style={{ position: 'absolute', inset: 0, height: '100%', margin: 0 }}
          />
        ) : null}
        {state === 'empty' || state === 'error' ? (
          <p
            className="empty"
            style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', padding: '2rem', textAlign: 'center' }}
          >
            {status}
          </p>
        ) : null}
      </div>
      {state === 'ready' ? <p className="note">{status}</p> : null}
    </>
  )
}
