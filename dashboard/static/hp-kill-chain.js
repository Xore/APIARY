/* Kill-chain analytics (#1224): three ECharts-powered charts (vendored,
 * static/echarts.min.js -- see assets.go's own doc comment for why
 * third-party JS is vendored rather than CDN-loaded here), each fetching
 * its own /api/... endpoint independently -- same fetch-then-render split
 * hp-attackers.js/hp-app.js's map already use, so one slow chart never
 * blocks the others or the page shell.
 */
(() => {
  "use strict";

  if (typeof echarts === "undefined") return;

  const initFns = { sankey: initSankey, timeline: initTimeline, heatmap: initHeatmap };

  document.querySelectorAll("[data-echart]").forEach(container => {
    const kind = container.dataset.echartKind;
    const url = container.dataset.echart;
    const status = document.querySelector(`[data-echart-status="${url}"]`);
    const setStatus = text => { if (status) status.textContent = text; };
    const init = initFns[kind];
    if (!init) return;

    fetch(url, { cache: "no-store", headers: { Accept: "application/json" } })
      .then(response => {
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
        return response.json();
      })
      .then(data => {
        const chart = echarts.init(container);
        const summary = init(chart, data);
        setStatus(summary);
        const resize = () => chart.resize();
        if (typeof ResizeObserver !== "undefined") {
          new ResizeObserver(resize).observe(container);
        } else {
          window.addEventListener("resize", resize);
        }
      })
      .catch(err => setStatus(`Chart failed to load: ${err.message}`));
  });

  function initSankey(chart, data) {
    const nodes = data.nodes || [];
    const links = data.links || [];
    // ECharts' own sankey series throws during layout on a genuinely empty
    // node set (confirmed live) -- an empty series list instead is a
    // completely normal ECharts state (the same one every chart here is
    // briefly in before its own fetch resolves) and, unlike omitting
    // setOption entirely, still gives the chart instance valid internal
    // state for the ResizeObserver's later chart.resize() calls to act on.
    chart.setOption({
      tooltip: { trigger: "item" },
      series: nodes.length === 0 ? [] : [{
        type: "sankey",
        emphasis: { focus: "adjacency" },
        data: nodes,
        links: links,
        lineStyle: { color: "gradient", curveness: 0.5 },
        label: { color: "var(--text)" },
      }],
    });
    if (nodes.length === 0) return "No attacker sessions with a recognized ATT&CK technique yet.";
    return `${nodes.length} tactic${nodes.length === 1 ? "" : "s"} observed, ${links.length} flow${links.length === 1 ? "" : "s"}.`;
  }

  function initHeatmap(chart, data) {
    const tactics = data.tactics || [];
    const techniques = data.techniques || [];
    const cells = data.cells || [];
    const max = cells.reduce((m, c) => Math.max(m, c.count), 1);
    chart.setOption({
      tooltip: { position: "top" },
      grid: { height: "70%", top: "8%", left: "22%" },
      xAxis: { type: "category", data: tactics, splitArea: { show: true }, axisLabel: { rotate: 30 } },
      yAxis: { type: "category", data: techniques, splitArea: { show: true } },
      visualMap: {
        min: 0, max: max, calculable: true, orient: "horizontal",
        left: "center", bottom: "0%", inRange: { color: ["#1f2937", "var(--accent)"] },
      },
      series: [{
        type: "heatmap",
        data: cells.map(c => [c.tactic_idx, c.technique_idx, c.count]),
        label: { show: true },
        emphasis: { itemStyle: { shadowBlur: 10, shadowColor: "rgba(0,0,0,0.5)" } },
      }],
    });
    if (techniques.length === 0) return "No ATT&CK-mapped technique evidence yet.";
    return `${techniques.length} technique${techniques.length === 1 ? "" : "s"} across ${new Set(cells.map(c => c.tactic_idx)).size} tactics.`;
  }

  function initTimeline(chart, rows) {
    rows = rows || [];
    const categories = rows.map(r => r.cidr);
    const maxScore = rows.reduce((m, r) => Math.max(m, r.score), 1);

    function renderGanttItem(params, api) {
      const categoryIndex = api.value(0);
      const start = api.coord([api.value(1), categoryIndex]);
      const end = api.coord([api.value(2), categoryIndex]);
      const height = api.size([0, 1])[1] * 0.6;
      const rectShape = echarts.graphic.clipRectByRect(
        { x: start[0], y: start[1] - height / 2, width: Math.max(end[0] - start[0], 2), height },
        { x: params.coordSys.x, y: params.coordSys.y, width: params.coordSys.width, height: params.coordSys.height },
      );
      return rectShape && { type: "rect", transition: ["shape"], shape: rectShape, style: api.style() };
    }

    chart.setOption({
      tooltip: {
        formatter: p => {
          const r = rows[p.value[0]];
          return `${r.cidr}<br/>score ${r.score} &middot; ${r.events} events`;
        },
      },
      grid: { left: "18%" },
      xAxis: { type: "time" },
      yAxis: { type: "category", data: categories },
      visualMap: {
        min: 0, max: maxScore, dimension: 3, show: false,
        inRange: { color: ["#3b82f6", "var(--accent)", "#f87171"] },
      },
      series: [{
        type: "custom",
        renderItem: renderGanttItem,
        encode: { x: [1, 2], y: 0 },
        data: rows.map((r, i) => [i, r.startMs || r.start_ms, r.endMs || r.end_ms, r.score]),
      }],
    });
    if (rows.length === 0) return "No campaigns in the current window.";
    return `${rows.length} campaign${rows.length === 1 ? "" : "s"} plotted.`;
  }
})();
