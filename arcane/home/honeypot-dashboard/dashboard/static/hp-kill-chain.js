/* Originally kill-chain analytics (#1224): three ECharts-powered charts
 * (vendored, static/echarts.min.js -- see assets.go's own doc comment for
 * why third-party JS is vendored rather than CDN-loaded here), each
 * fetching its own /api/... endpoint independently -- same fetch-then-
 * render split hp-attackers.js/hp-app.js's map already use, so one slow
 * chart never blocks the others or the page shell. The [data-echart]
 * bootstrap below is page-agnostic (queries the whole document, not a
 * kill-chain-specific container), so #1277 reuses it from the overview
 * page too for a plain pie chart rather than duplicating this file's own
 * fetch/init/resize wiring -- this file's name is now a bit narrower than
 * what it covers, kept as-is rather than a rename for a one-chart addition.
 */
(() => {
  "use strict";

  if (typeof echarts === "undefined") return;

  // #1532: ECharts' canvas renderer can't resolve a CSS var() the way real
  // DOM elements can (see hp-echarts-theme.js's own comment) -- every
  // itemStyle/lineStyle/visualMap color below that needs one explicit
  // color resolves it through here instead of handing ECharts the raw
  // "var(--x)" string, which silently fails to parse and falls back to
  // black/ECharts-default-grey.
  const themeColor = window.hpChartColor || (name => name);

  const initFns = { sankey: initSankey, timeline: initTimeline, heatmap: initHeatmap, pie: initPie, line: initLine, bar: initBar, scatter: initScatter, radar: initRadar };

  // #1277: exposed as window.initHoneypotCharts (same convention hp-app.js's
  // own window.initHoneypotMaps already uses) so a page whose content gets
  // wholesale-replaced on a refresh cycle (the overview page's
  // replaceHoneypotPage, every ~15s) can re-run this against the fresh DOM
  // -- the [data-echart] element(s) that existed at initial script load are
  // gone after that replace, along with whatever ResizeObserver was
  // watching them, so without this the chart would go dead after the very
  // first background refresh. The kill-chain page itself never replaces its
  // own content this way, so calling this twice against the same
  // already-initialized container (which just re-creates the ECharts
  // instance and re-fetches) is a real but harmless cost there, not a bug.
  function initCharts() {
    document.querySelectorAll("[data-echart]").forEach(container => {
      const kind = container.dataset.echartKind;
      const url = container.dataset.echart;
      const status = document.querySelector(`[data-echart-status="${url}"]`);
      const setStatus = text => { if (status) status.textContent = text; };
      const renderState = (text, error = false) => {
        container.replaceChildren();
        container.setAttribute("aria-busy", "false");
        container.setAttribute("role", error ? "alert" : "status");
        const message = document.createElement("p");
        message.className = "empty";
        message.textContent = text;
        message.style.cssText = "display:grid;place-items:center;width:100%;height:100%;padding:2rem;text-align:center";
        container.appendChild(message);
        setStatus(text);
      };
      const init = initFns[kind];
      if (!init) return;

      fetch(url, { cache: "no-store", headers: { Accept: "application/json" } })
        .then(response => {
          if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
          return response.json();
        })
        .then(data => {
          container.replaceChildren();
          container.setAttribute("aria-busy", "false");
          const chart = echarts.init(container, "xore");
          const summary = init(chart, data);
          if (summary.startsWith("No ")) {
            chart.dispose();
            renderState(summary);
            return;
          }
          setStatus(summary);
          const resize = () => chart.resize();
          if (typeof ResizeObserver !== "undefined") {
            new ResizeObserver(resize).observe(container);
          } else {
            window.addEventListener("resize", resize);
          }
        })
        .catch(err => renderState(`Chart failed to load: ${err.message}`, true));
    });
  }

  initCharts();
  window.initHoneypotCharts = initCharts;

  // #1577: operator preference is kill-chain progressions stacking top to
  // bottom rather than the previous left-to-right flow -- matching how
  // events.html's own single-IP attack-chain view already reads
  // ("chronological -- the attack reads top to bottom"). ECharts' sankey
  // series supports this as a first-class orient flip rather than a
  // reshape of the underlying data: buildKillChainSankey (kill_chain.go)
  // hands over the same {nodes, links} shape either way, so only the
  // rendering options below change. label.position moves from the
  // horizontal layout's "right" (natural next to a vertical node bar) to
  // "top" (natural above a horizontal node bar, clear of the flow curves
  // entering its bottom edge from the tactic above).
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
        orient: "vertical",
        emphasis: { focus: "adjacency" },
        data: nodes,
        links: links,
        lineStyle: { color: "gradient", curveness: 0.5 },
        label: { position: "top", color: themeColor("--text-primary", "#e9e6df") },
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
        left: "center", bottom: "0%",
        inRange: { color: [themeColor("--surface-3", "#3d3d3b"), themeColor("--accent", "#d97757")] },
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

  // Generic pie chart -- data is already the [{name, value}] array ECharts'
  // own pie series expects, so this only ever needs to wrap it once, no
  // per-endpoint reshaping. First consumer: #1277's /api/os-distribution.
  function initPie(chart, data) {
    data = data || [];
    const total = data.reduce((sum, d) => sum + (d.value || 0), 0);
    chart.setOption({
      tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
      legend: { orient: "vertical", left: "left", textStyle: { color: themeColor("--text-primary", "#e9e6df") } },
      series: [{
        type: "pie",
        radius: ["35%", "65%"],
        avoidLabelOverlap: true,
        itemStyle: { borderColor: themeColor("--surface-1", "#2c2c2a"), borderWidth: 2 },
        label: { color: themeColor("--text-primary", "#e9e6df") },
        data,
      }],
    });
    if (data.length === 0) return "No data yet.";
    return `${data.length} categor${data.length === 1 ? "y" : "ies"}, ${total} total.`;
  }

  // Single-series radar chart -- data is {categories: [string], values:
  // [number], ips: [string]}, one axis per category. First consumer:
  // #1280's /api/attacker-fusion, where each axis is a signal category
  // (JA3/JA4/p0f OS/SSH client/Payload hash) and the value is how many
  // distinct values in that category are shared by 2+ of the entity's
  // member IPs -- a visibly larger radar lobe on one axis is direct
  // evidence that signal drove the merge. Max per axis is derived from the
  // data itself (largest value across all axes, floor 1 so an
  // all-zero/no-overlap-yet entity still renders a real polygon instead of
  // a degenerate point).
  function initRadar(chart, data) {
    data = data || {};
    const categories = data.categories || [];
    const values = data.values || [];
    const max = Math.max(1, ...values);
    chart.setOption({
      tooltip: { trigger: "item" },
      radar: {
        indicator: categories.map(c => ({ name: c, max })),
        axisName: { color: themeColor("--text-primary", "#e9e6df") },
        axisLine: { lineStyle: { color: themeColor("--border-strong", "rgba(255,255,255,0.14)") } },
        splitLine: { lineStyle: { color: themeColor("--border-subtle", "rgba(255,255,255,0.075)") } },
        splitArea: { areaStyle: { color: ["transparent"] } },
      },
      series: [{
        type: "radar",
        data: [{ value: values, areaStyle: { opacity: 0.25 }, itemStyle: { color: themeColor("--accent", "#d97757") } }],
      }],
    });
    const total = values.reduce((sum, v) => sum + v, 0);
    if (categories.length === 0) return "No data yet.";
    if (total === 0) return "No shared signals across this entity's member IPs yet.";
    return `${total} shared signal value${total === 1 ? "" : "s"} across ${categories.length} categories.`;
  }

  // Generic multi-series time line/area chart -- data is [{name, points:
  // [{time, value}]}], ISO time strings parsed straight into ECharts' own
  // time-axis type. First consumer: #1283's /api/ml-backlog.
  function initLine(chart, data) {
    data = data || [];
    const totalPoints = data.reduce((sum, s) => sum + s.points.length, 0);
    chart.setOption({
      tooltip: { trigger: "axis" },
      legend: { textStyle: { color: themeColor("--text-primary", "#e9e6df") } },
      grid: { left: "12%", right: "5%" },
      xAxis: { type: "time" },
      yAxis: { type: "value" },
      series: data.map(s => ({
        name: s.name,
        type: "line",
        showSymbol: false,
        areaStyle: { opacity: 0.15 },
        data: s.points.map(p => [p.time, p.value]),
      })),
    });
    if (totalPoints === 0) return "No data yet.";
    return `${data.length} series, ${totalPoints} points.`;
  }

  // Generic single-series bar/histogram chart -- data is {categories:
  // [string], values: [number]}, one bar per category in the given order
  // (a pre-binned histogram, a top-N ranking, whatever the endpoint already
  // sorted). First consumer: #1294's /api/endlessh-held-histogram (short,
  // fixed-width bucket labels like "1-5s"). #1276's /api/dionaea-cves added
  // a second consumer whose labels can run long ("DoublePulsar connection
  // attempt (CVE-2017-0144..CVE-2017-0148)") -- rotated + truncated with
  // the full text still in the axis tooltip (trigger: "axis" already shows
  // it untruncated) rather than a fixed-length category axis overlapping
  // itself illegibly.
  function initBar(chart, data) {
    data = data || {};
    const categories = data.categories || [];
    const values = data.values || [];
    const longLabels = categories.some(c => c.length > 14);
    chart.setOption({
      tooltip: { trigger: "axis" },
      grid: { left: "10%", right: "5%", bottom: longLabels ? 110 : 30 },
      xAxis: {
        type: "category",
        data: categories,
        axisLabel: {
          color: themeColor("--text-primary", "#e9e6df"),
          rotate: longLabels ? 30 : 0,
          overflow: "truncate",
          width: longLabels ? 160 : undefined,
        },
      },
      yAxis: { type: "value" },
      series: [{ type: "bar", data: values, itemStyle: { color: themeColor("--accent", "#d97757") } }],
    });
    const total = values.reduce((sum, v) => sum + v, 0);
    if (categories.length === 0) return "No data yet.";
    return `${categories.length} bucket${categories.length === 1 ? "" : "s"}, ${total} total.`;
  }

  // Generic multi-series time scatter chart -- same [{name, points:
  // [{time, value}]}] shape initLine consumes (structurally a scatter
  // series is identical to a line series, a named list of time+value
  // points), just rendered as unconnected points instead of a line/area so
  // several series plotted together show agreement/disagreement rather
  // than obscuring each other under overlapping fills. First consumer:
  // #1284's /api/ml-anomaly-scores (one series per ml-worker model, plus
  // composite).
  function initScatter(chart, data) {
    data = data || [];
    const totalPoints = data.reduce((sum, s) => sum + s.points.length, 0);
    chart.setOption({
      tooltip: { trigger: "item", formatter: p => `${p.seriesName}: ${p.value[1].toFixed(3)}` },
      legend: { textStyle: { color: themeColor("--text-primary", "#e9e6df") } },
      grid: { left: "12%", right: "5%" },
      xAxis: { type: "time" },
      yAxis: { type: "value" },
      series: data.map(s => ({
        name: s.name,
        type: "scatter",
        symbolSize: 6,
        data: s.points.map(p => [p.time, p.value]),
      })),
    });
    if (totalPoints === 0) return "No anomalies scored yet.";
    return `${data.length} series, ${totalPoints} points.`;
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
        inRange: { color: [themeColor("--info", "#78a9d4"), themeColor("--accent", "#d97757"), themeColor("--danger", "#dc7774")] },
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
