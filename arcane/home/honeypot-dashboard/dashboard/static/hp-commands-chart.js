/* #1268 "ask 3": a bar chart of the top commands by frequency, summarizing
   the full table beneath it (intel.html's own "commands" template) rather
   than replacing it -- same data, no separate fetch. window.__hpTopCommands
   is inlined server-side, same pattern hp-problem-reports-admin.js's own
   window.__hpProblemReports uses.

   Horizontal bars (category axis on Y), sensor-colored, longest command
   truncated with the full text in a tooltip -- commands are often long
   shell one-liners that would collide/truncate badly as X-axis labels. */
(() => {
  "use strict";

  const container = document.getElementById("commands-chart");
  const rows = window.__hpTopCommands;
  if (!container || typeof echarts === "undefined" || !Array.isArray(rows) || !rows.length) return;

  const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const truncate = (value, max) => (value.length > max ? value.slice(0, max - 1) + "…" : value);

  // Chart reads top-to-bottom in the same descending-frequency order the
  // table already sorts by; ECharts' own category axis draws bottom-to-top
  // by default, so the data (and labels) are reversed once here to match.
  const ordered = rows.slice().reverse();
  const labels = ordered.map(r => truncate(r.Command, 40));
  const counts = ordered.map(r => r.Count);
  const fullCommands = ordered.map(r => r.Command);
  const sensors = ordered.map(r => r.Sensor);

  // #1532: echarts.init(..., "xore") applies hp-echarts-theme.js's
  // registered theme (axis/legend/tooltip colors); itemStyle.color below
  // still needs its own resolved value -- ECharts' canvas renderer parses
  // color strings itself and cannot resolve a CSS var() the way real DOM
  // elements can (see hp-echarts-theme.js's own comment).
  const chart = echarts.init(container, "xore");
  chart.setOption({
    grid: { left: "28%", right: "4%", top: "4%", bottom: "4%" },
    tooltip: {
      trigger: "item",
      formatter: params => `<code>${escapeHTML(fullCommands[params.dataIndex])}</code><br>${escapeHTML(sensors[params.dataIndex])} &bull; ${params.value} occurrence${params.value === 1 ? "" : "s"}`,
    },
    xAxis: { type: "value" },
    yAxis: { type: "category", data: labels, axisLabel: { fontFamily: "monospace" } },
    series: [{
      type: "bar",
      data: counts,
      itemStyle: { color: window.hpChartColor("--accent", "#d97757") },
    }],
  });

  const resize = () => chart.resize();
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(resize).observe(container);
  } else {
    window.addEventListener("resize", resize);
  }
})();
