/* #1292: a syscall frequency profile is a classic malware-behavior
   fingerprint (a dropper vs. ransomware vs. a backdoor have distinctly
   different shapes) -- this bar chart summarizes the "Top system calls"
   table beneath it, same data, no separate fetch. window.__hpTopSyscalls
   is inlined server-side, same pattern hp-commands-chart.js's own
   window.__hpTopCommands uses (#1268).

   Horizontal bars (category axis on Y), longest syscall name truncated
   with the full name still in the tooltip. */
(() => {
  "use strict";

  const container = document.getElementById("syscalls-chart");
  const rows = window.__hpTopSyscalls;
  if (!container || typeof echarts === "undefined" || !Array.isArray(rows) || !rows.length) return;

  const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const truncate = (value, max) => (value.length > max ? value.slice(0, max - 1) + "…" : value);

  // Chart reads top-to-bottom in the same descending-frequency order the
  // table already sorts by; ECharts' own category axis draws bottom-to-top
  // by default, so the data (and labels) are reversed once here to match.
  const ordered = rows.slice().reverse();
  const labels = ordered.map(r => truncate(r.name, 30));
  const counts = ordered.map(r => r.count);
  const fullNames = ordered.map(r => r.name);

  const chart = echarts.init(container);
  chart.setOption({
    grid: { left: "30%", right: "6%", top: "4%", bottom: "4%" },
    tooltip: {
      trigger: "item",
      formatter: params => `<code>${escapeHTML(fullNames[params.dataIndex])}</code>: ${params.value} call${params.value === 1 ? "" : "s"}`,
    },
    xAxis: { type: "value" },
    yAxis: { type: "category", data: labels, axisLabel: { fontFamily: "monospace" } },
    series: [{
      type: "bar",
      data: counts,
      itemStyle: { color: "var(--accent)" },
    }],
  });

  const resize = () => chart.resize();
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(resize).observe(container);
  } else {
    window.addEventListener("resize", resize);
  }
})();
