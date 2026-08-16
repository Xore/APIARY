/* #1532: shared ECharts theming for xore/theme.
 *
 * Root cause: every ECharts-powered chart on the dashboard (hp-commands-
 * chart.js, hp-syscalls-chart.js, hp-kill-chain.js) passes color values
 * like "var(--accent)"/"var(--text-primary)" straight into ECharts'
 * itemStyle/axisLabel/legend/etc. options, the same way those custom
 * properties are used in real CSS elsewhere on the page. But ECharts'
 * default renderer draws to <canvas>, not the DOM -- canvas 2D context
 * properties (fillStyle/strokeStyle) are parsed by the browser as a
 * standalone CSS <color> value with no element/cascade to resolve a
 * var() reference against, so "var(--accent)" is simply an invalid color
 * and the browser silently keeps whatever fillStyle was already set
 * (effectively: black). Combined with every axis/gridline/legend/tooltip
 * that was never styled at all (ECharts' own built-in default theme:
 * light grey lines/text designed for a white page), every chart ends up
 * grey-on-grey regardless of the site's actual light/dark theme -- the
 * root cause behind #1532 across Commands, ml-anomalies, Overview, and
 * Kill-chain analytics.
 *
 * Fix, two parts:
 *  1. hpChartColor(name) resolves a theme.css custom property to its
 *     current literal value via getComputedStyle, so call sites that need
 *     one explicit color (e.g. a bar's itemStyle.color) can hand ECharts
 *     something it can actually parse.
 *  2. A registered ECharts theme ("xore") gives every axis/legend/tooltip/
 *     text element a real default color, the same way ECharts' own built-
 *     in "dark" example theme works (see echarts/theme/dark.js upstream)
 *     -- echarts.init(container, "xore") picks this up without every chart
 *     file repeating the same textStyle/axisLine/splitLine boilerplate.
 *
 * Cytoscape.js (hp-attackers.js, hp-ghidra-callgraph.js) has the identical
 * canvas-var() problem but no theme-registration mechanism of its own;
 * those files use hpChartColor() directly at each style property instead.
 */
(() => {
  "use strict";

  const cssVar = (name, fallback) => {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback || "";
  };
  window.hpChartColor = cssVar;

  if (typeof echarts === "undefined") return;

  function buildTheme() {
    const textPrimary = cssVar("--text-primary", "#e9e6df");
    const textMuted = cssVar("--text-muted", "#a5a9a6");
    const border = cssVar("--border-strong", "rgba(255,255,255,0.14)");
    const borderSubtle = cssVar("--border-subtle", "rgba(255,255,255,0.075)");
    const surface = cssVar("--surface-raised", "#383835");
    const accent = cssVar("--accent", "#d97757");
    const axis = {
      axisLine: { lineStyle: { color: border } },
      axisTick: { lineStyle: { color: border } },
      axisLabel: { color: textMuted },
      splitLine: { lineStyle: { color: borderSubtle } },
    };
    return {
      color: [accent, cssVar("--info", "#78a9d4"), cssVar("--success", "#79c99e"), cssVar("--warning", "#deb36a"), cssVar("--danger", "#dc7774")],
      backgroundColor: "transparent",
      textStyle: { color: textPrimary },
      title: { textStyle: { color: textPrimary }, subtextStyle: { color: textMuted } },
      legend: { textStyle: { color: textPrimary } },
      tooltip: {
        backgroundColor: surface,
        borderColor: border,
        textStyle: { color: textPrimary },
      },
      visualMap: { textStyle: { color: textMuted } },
      categoryAxis: axis,
      valueAxis: axis,
      timeAxis: axis,
      logAxis: axis,
    };
  }

  // Re-registered under the same name (not registered once and forgotten)
  // so a live theme toggle (hp-settings.js's data-theme switch, no page
  // reload) is picked up by the next chart that calls
  // echarts.init(container, "xore") -- echarts looks the theme up by name
  // at init time. Charts already on screen don't retheme live; that's true
  // of every canvas-rendered element here, not something this file
  // introduces.
  const register = () => echarts.registerTheme("xore", buildTheme());
  register();
  window.hpRegisterChartTheme = register;
})();
