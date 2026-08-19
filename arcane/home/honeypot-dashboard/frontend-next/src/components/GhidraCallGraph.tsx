// Interactive Ghidra call graph (#1287 parity) — built from the same
// recovered Callers/Callees cross-reference data the static graphviz SVG
// card renders as a flat image, fetched from /api/v1/ghidra-callgraph/{sha}
// and handed to Cytoscape.js the same way AttackerGraph.tsx's entity graph
// already is. Click a node to dim everything but its direct neighbors;
// click empty background to clear. A text filter dims every node whose
// label doesn't match.
//
// Untrusted-label safety: function names are attacker-influenced (Ghidra
// names them from whatever symbols/strings it recovered from the sample).
// Cytoscape's "label": "data(label)" style draws every label to an HTML5
// <canvas> via fillText — a canvas has no HTML parser in its paint path at
// all, so a function literally named "<img onerror=...>" still just paints
// as that literal text. Same property the static SVG's own image-embedding
// relies on, a different rendering backend achieving it.
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useRef, useState } from 'react'
import type { Core, NodeSingular } from 'cytoscape'

type GraphNode = { id: string; label: string; kind: 'function' | 'leaf' }
type GraphEdge = { source: string; target: string }
type Graph = { nodes: GraphNode[]; edges: GraphEdge[]; truncated: boolean }

const fetchCallGraph = createServerFn({ method: 'GET' })
  .inputValidator((input: { sha: string }) => input)
  .handler(async ({ data }): Promise<Graph | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Graph>(`/api/v1/ghidra-callgraph/${encodeURIComponent(data.sha)}`)
  })

function cssColor(name: string, fallback: string): string {
  if (typeof document === 'undefined') return fallback
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}

const DIM_CLASS = 'hp-gh-dim'

export function GhidraCallGraph({ sha }: { sha: string }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const [graph, setGraph] = useState<Graph | null>(null)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    let cancelled = false
    setGraph(null)
    fetchCallGraph({ data: { sha } }).then((result) => {
      if (!cancelled) setGraph(result)
    })
    return () => {
      cancelled = true
    }
  }, [sha])

  useEffect(() => {
    const container = containerRef.current
    if (!container || !graph || graph.nodes.length === 0) return
    let disposed = false
    ;(async () => {
      const cytoscape = (await import('cytoscape')).default
      if (disposed) return
      const accent = cssColor('--accent', '#d97757')
      const accentText = cssColor('--text-on-accent', '#211a17')
      const border = cssColor('--border-strong', 'rgba(255,255,255,0.14)')
      const surface = cssColor('--surface-2', '#343432')
      const surface1 = cssColor('--surface-1', '#2c2c2a')
      const text = cssColor('--text-muted', '#a5a9a6')
      const cy = cytoscape({
        container,
        elements: [
          ...graph.nodes.map((node) => ({ data: { id: node.id, label: node.label, kind: node.kind } })),
          ...graph.edges.map((edge) => ({ data: { source: edge.source, target: edge.target } })),
        ],
        style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'font-size': 9,
              color: text,
              'text-valign': 'bottom',
              'text-margin-y': 4,
              'text-wrap': 'ellipsis',
              'text-max-width': '80px',
              'background-color': surface,
              'border-color': border,
              'border-width': 1,
              width: 14,
              height: 14,
            },
          },
          {
            // Deepened functions (their own Callers/Callees were recovered,
            // not just referenced from another function's list) get the
            // accent treatment — the graph's real subjects, versus the
            // leaf nodes around them.
            selector: 'node[kind = "function"]',
            style: {
              'background-color': accent,
              'border-color': surface1,
              'border-width': 1.5,
              width: 22,
              height: 22,
              color: accentText,
              'font-weight': 600,
            },
          },
          {
            selector: 'edge',
            style: {
              width: 1,
              'line-color': border,
              'target-arrow-color': border,
              'target-arrow-shape': 'triangle',
              'arrow-scale': 0.7,
              'curve-style': 'bezier',
            },
          },
          { selector: `.${DIM_CLASS}`, style: { opacity: 0.15 } },
        ],
        layout: { name: 'cose', animate: false, nodeRepulsion: () => 6000, idealEdgeLength: () => 60 },
        minZoom: 0.1,
        maxZoom: 4,
      })

      cy.on('tap', 'node', (event) => {
        const node = event.target as NodeSingular
        const keep = node.closedNeighborhood()
        cy.elements().difference(keep).addClass(DIM_CLASS)
        keep.removeClass(DIM_CLASS)
      })
      cy.on('tap', (event) => {
        if (event.target === cy) cy.elements().removeClass(DIM_CLASS)
      })

      cyRef.current = cy
    })()
    return () => {
      disposed = true
      cyRef.current?.destroy()
      cyRef.current = null
    }
  }, [graph])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const q = filter.trim().toLowerCase()
    if (!q) {
      cy.elements().removeClass(DIM_CLASS)
      return
    }
    const matches = cy.nodes().filter((node) => (node.data('label') as string).toLowerCase().includes(q))
    cy.elements().addClass(DIM_CLASS)
    matches.removeClass(DIM_CLASS)
  }, [filter])

  if (graph === null) return <span className="skeleton-line" aria-hidden="true" />
  if (graph.nodes.length === 0) {
    return <p className="empty">No caller/callee cross-references were recovered for this binary's deep-dived functions.</p>
  }

  const functionCount = graph.nodes.filter((node) => node.kind === 'function').length
  return (
    <>
      <div className="filters" style={{ marginBottom: 8 }}>
        <input
          className="input"
          type="search"
          placeholder="Filter by function name"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          aria-label="Filter call graph nodes"
        />
      </div>
      <p className="note" role="status">
        {functionCount} function{functionCount === 1 ? '' : 's'}, {graph.nodes.length} node{graph.nodes.length === 1 ? '' : 's'}{' '}
        total — click a node to focus its neighbors, click the background to clear
        {graph.truncated ? ' (truncated to the largest functions)' : ''}
      </p>
      <div ref={containerRef} style={{ width: '100%', height: 420 }} role="img" aria-label="interactive function call graph" />
    </>
  )
}
