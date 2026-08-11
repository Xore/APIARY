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

  fetch(canvas.dataset.attackerGraphUrl, { cache: "no-store", headers: { Accept: "application/json" } })
    .then(response => {
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return response.json();
    })
    .then(data => {
      const elements = [
        ...data.nodes.map(n => ({ data: { id: n.id, label: n.label, kind: n.kind } })),
        ...data.edges.map(e => ({ data: { source: e.source, target: e.target } })),
      ];
      const cy = cytoscape({
        container: canvas,
        elements,
        style: [
          {
            selector: "node",
            style: {
              label: "data(label)",
              "font-size": 10,
              color: "var(--text-muted)",
              "text-valign": "bottom",
              "text-margin-y": 6,
              "background-color": "var(--surface-2)",
              "border-color": "var(--accent)",
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
              color: "#fff",
              "background-color": "var(--accent)",
              "border-color": "var(--surface-1)",
              "border-width": 2,
              width: 56,
              height: 56,
            },
          },
          {
            selector: "node[kind = 'overflow']",
            style: {
              "background-color": "var(--surface-2)",
              "border-color": "var(--border-strong)",
              color: "var(--text-muted)",
            },
          },
          {
            selector: "edge",
            style: {
              width: 1.2,
              "line-color": "var(--border-strong)",
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
    .catch(err => setStatus(`Graph failed to load: ${err.message}`));
})();
