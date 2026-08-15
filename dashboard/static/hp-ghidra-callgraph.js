/* Interactive Ghidra call graph (#1287) -- built from the same recovered
 * Callers/Callees cross-reference data the existing static graphviz SVG
 * card renders as a flat image, fetched from /api/ghidra-callgraph/{sha}
 * (ghidra_callgraph.go's buildGhidraCallGraph, same graphNode/graphEdge
 * wire shape hp-attackers.js's entity graph already uses) and handed to
 * Cytoscape.js (vendored -- see assets.go's own doc comment) the same
 * way.
 *
 * Untrusted-label safety: function names are attacker-influenced (Ghidra
 * names them from whatever symbols/strings it recovered from the
 * sample), which is exactly why the static SVG is embedded as an <img>
 * rather than inline markup. Cytoscape's own "label": "data(label)"
 * style property (below, same as hp-attackers.js) draws every label to
 * an HTML5 <canvas> via fillText -- a canvas has no HTML parser in its
 * paint path at all, so a function literally named "<img onerror=...>"
 * still just paints as that literal text. This is a different rendering
 * backend achieving the same "cannot execute script" property the SVG's
 * image-embedding relies on, not a weaker substitute for it -- see this
 * file's own ghidra_callgraph.go counterpart for the fuller reasoning.
 *
 * #1288/#1285/#1286 shell+hydrate means the [data-ghidra-callgraph-url]
 * canvas this script looks for doesn't exist in the DOM until
 * hp-ghidra-report.js's own fragment fetch inserts it -- this script's
 * own <script defer> tag runs once, well before that resolves, so
 * initGraph is exposed as window.initHoneypotGhidraCallGraph (same
 * convention hp-kill-chain.js's window.initHoneypotCharts already uses)
 * for hp-ghidra-report.js to call again once the fragment lands.
 */
(() => {
  "use strict";

  if (typeof cytoscape === "undefined") return;

  function initGraph() {
    const canvas = document.querySelector("[data-ghidra-callgraph-url]");
    if (!canvas) return;

    const status = document.querySelector("[data-ghidra-callgraph-status]");
    const setStatus = text => { if (status) status.textContent = text; };
    const filterInput = document.querySelector("[data-ghidra-callgraph-filter]");
    const renderGraphState = (message, isError = false) => {
      canvas.replaceChildren();
      canvas.setAttribute("aria-busy", "false");
      canvas.setAttribute("role", isError ? "alert" : "status");
      const state = document.createElement("p");
      state.className = "empty";
      state.textContent = message;
      state.style.cssText = "display:grid;place-items:center;width:100%;height:100%;padding:2rem;text-align:center";
      canvas.appendChild(state);
      setStatus(message);
    };

    fetch(canvas.dataset.ghidraCallgraphUrl, { cache: "no-store", headers: { Accept: "application/json" } })
      .then(response => {
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
        return response.json();
      })
      .then(data => {
        if (!data.nodes || data.nodes.length === 0) {
          renderGraphState("No caller/callee cross-references were recovered for this binary's deep-dived functions.");
          return;
        }

        canvas.replaceChildren();
        canvas.setAttribute("aria-busy", "false");
        canvas.setAttribute("role", "img");
        if (filterInput) filterInput.disabled = false;
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
                "font-size": 9,
                color: "var(--text-muted)",
                "text-valign": "bottom",
                "text-margin-y": 4,
                "text-wrap": "ellipsis",
                "text-max-width": "80px",
                "background-color": "var(--surface-2)",
                "border-color": "var(--border-strong)",
                "border-width": 1,
                width: 14,
                height: 14,
              },
            },
            {
              // Deepened functions (their own Callers/Callees were
              // recovered, not just referenced from another function's
              // list) get the accent treatment -- the graph's real
              // subjects, versus the leaf nodes around them.
              selector: `node[kind = "function"]`,
              style: {
                "background-color": "var(--accent)",
                "border-color": "var(--surface-1)",
                "border-width": 1.5,
                width: 22,
                height: 22,
                color: "var(--text)",
                "font-weight": 600,
              },
            },
            {
              selector: "edge",
              style: {
                width: 1,
                "line-color": "var(--border-strong)",
                "target-arrow-color": "var(--border-strong)",
                "target-arrow-shape": "triangle",
                "arrow-scale": 0.7,
                "curve-style": "bezier",
              },
            },
            // Dimmed state (below) is toggled by class, not by rewriting
            // every element's own style -- cheaper to apply/clear on a
            // click than diffing which nodes changed.
            { selector: ".hp-gh-dim", style: { opacity: 0.15 } },
          ],
          layout: { name: "cose", animate: false, nodeRepulsion: 6000, idealEdgeLength: 60 },
          minZoom: 0.1,
          maxZoom: 4,
        });

        // Click a node: dim everything except it and its direct
        // neighbors, so a dense graph becomes readable for one function
        // at a time (#1287's own "show only this function's neighbors"
        // ask). Click empty background to clear back to the full graph.
        cy.on("tap", "node", event => {
          const node = event.target;
          const keep = node.closedNeighborhood();
          cy.elements().difference(keep).addClass("hp-gh-dim");
          keep.removeClass("hp-gh-dim");
        });
        cy.on("tap", event => {
          if (event.target === cy) cy.elements().removeClass("hp-gh-dim");
        });

        if (filterInput) {
          filterInput.addEventListener("input", () => {
            const q = filterInput.value.trim().toLowerCase();
            if (!q) {
              cy.elements().removeClass("hp-gh-dim");
              return;
            }
            const matches = cy.nodes().filter(n => n.data("label").toLowerCase().includes(q));
            cy.elements().addClass("hp-gh-dim");
            matches.removeClass("hp-gh-dim");
          });
        }

        const fit = () => { cy.resize(); cy.fit(undefined, 24); };
        if (typeof ResizeObserver !== "undefined") {
          new ResizeObserver(fit).observe(canvas);
        } else {
          window.addEventListener("resize", fit);
        }

        const functionCount = data.nodes.filter(n => n.kind === "function").length;
        let statusText = `${functionCount} function${functionCount === 1 ? "" : "s"}, ${data.nodes.length} node${data.nodes.length === 1 ? "" : "s"} total — click a node to focus its neighbors, click the background to clear`;
        if (data.truncated) statusText += " (truncated to the largest functions)";
        setStatus(statusText);
      })
      .catch(err => renderGraphState(`Call graph failed to load: ${err.message}`, true));
  }

  initGraph();
  window.initHoneypotGhidraCallGraph = initGraph;
})();
