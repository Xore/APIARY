/* Attacker entity graph (#1203, reworked onto Cytoscape.js) -- one selected
 * entity's member IPs around a central hub node. The page still
 * server-renders everything else (table, metrics); this only fetches
 * /api/attacker-graph once and hands it to Cytoscape (vendored,
 * static/cytoscape.min.js -- see assets.go's own doc comment for why
 * third-party JS is vendored rather than CDN-loaded here) to lay out and
 * render into the canvas div. Same fetch-then-render split /api/map-points'
 * Leaflet consumer (hp-app.js's initMaps) uses, minus the live-refresh
 * loop: unlike the map, one entity's member IPs don't change while its page
 * is open, so this loads once.
 */
(() => {
  "use strict";

  const canvas = document.querySelector("[data-attacker-graph-url]");
  if (!canvas || typeof cytoscape === "undefined") return;

  const status = document.querySelector("[data-attacker-graph-status]");
  const setStatus = text => { if (status) status.textContent = text; };
  const renderState = (text, error = false) => {
    canvas.replaceChildren();
    canvas.setAttribute("aria-busy", "false");
    canvas.setAttribute("role", error ? "alert" : "status");
    const message = document.createElement("p");
    message.className = "empty";
    message.textContent = text;
    message.style.cssText = "display:grid;place-items:center;width:100%;height:100%;padding:2rem;text-align:center";
    canvas.appendChild(message);
    setStatus(text);
  };

  fetch(canvas.dataset.attackerGraphUrl, { cache: "no-store", headers: { Accept: "application/json" } })
    .then(response => {
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return response.json();
    })
    .then(data => {
      if (!data.nodes || data.nodes.length === 0) {
        renderState("No graph nodes were returned for this attacker identity.");
        return;
      }
      canvas.replaceChildren();
      canvas.setAttribute("aria-busy", "false");
      const elements = [
        ...data.nodes.map(n => ({ data: { id: n.id, label: n.label, kind: n.kind } })),
        ...data.edges.map(e => ({ data: { source: e.source, target: e.target } })),
      ];
      // #1532: Cytoscape.js has the same problem ECharts does -- it draws
      // to <canvas> and parses style color values itself, so a literal
      // "var(--x)" string is not a color it understands and silently
      // fails, leaving nodes/edges in Cytoscape's own default grey/black.
      // hp-echarts-theme.js's window.hpChartColor resolves the current
      // theme.css value up front instead (same helper ECharts' own chart
      // files use for their one-off itemStyle colors).
      const c = window.hpChartColor || ((name, fallback) => fallback || name);
      const cy = cytoscape({
        container: canvas,
        elements,
        style: [
          {
            selector: "node",
            style: {
              label: "data(label)",
              "font-size": 10,
              color: c("--text-muted", "#a5a9a6"),
              "text-valign": "bottom",
              "text-margin-y": 6,
              "background-color": c("--surface-2", "#343432"),
              "border-color": c("--accent", "#d97757"),
              "border-width": 1.2,
              width: 26,
              height: 26,
            },
          },
          {
            selector: "node[kind = 'hub']",
            style: {
              label: "data(label)",
              "text-valign": "center",
              "text-halign": "center",
              "font-size": 12,
              "font-weight": 600,
              color: c("--text-on-accent", "#211a17"),
              "background-color": c("--accent", "#d97757"),
              "border-color": c("--surface-1", "#2c2c2a"),
              "border-width": 2,
              width: 56,
              height: 56,
            },
          },
          {
            selector: "node[kind = 'overflow']",
            style: {
              "background-color": c("--surface-2", "#343432"),
              "border-color": c("--border-strong", "rgba(255,255,255,0.14)"),
              color: c("--text-muted", "#a5a9a6"),
            },
          },
          {
            selector: "edge",
            style: {
              width: 1.2,
              "line-color": c("--border-strong", "rgba(255,255,255,0.14)"),
              "curve-style": "straight",
            },
          },
        ],
        layout: {
          name: "concentric",
          concentric: n => (n.data("kind") === "hub" ? 2 : 1),
          levelWidth: () => 1,
          minNodeSpacing: 34,
          animate: false,
        },
        minZoom: 0.25,
        maxZoom: 4,
      });

      cy.on("tap", "node[kind = 'spoke']", event => {
        window.location.assign(`/events?ip=${encodeURIComponent(event.target.data("label"))}`);
      });

      const fit = () => { cy.resize(); cy.fit(undefined, 24); };
      if (typeof ResizeObserver !== "undefined") {
        new ResizeObserver(fit).observe(canvas);
      } else {
        window.addEventListener("resize", fit);
      }

      setStatus(`${data.nodes.length - 1} member IP${data.nodes.length - 1 === 1 ? "" : "s"} — drag to pan, scroll to zoom, drag the corner to resize`);
    })
    .catch(err => renderState(`Graph failed to load: ${err.message}`, true));
})();
