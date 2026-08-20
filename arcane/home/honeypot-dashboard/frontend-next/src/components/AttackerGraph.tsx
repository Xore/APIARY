// Entity hub/spoke graph for one attacker identity — cytoscape over the
// same node/edge shape the legacy /api/attacker-graph served, colors
// resolved from theme.css at init (canvas can't resolve var(), #1532).
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useRef } from 'react'
import { cssVar as cssColor } from '../lib/cssVar'
import { useServerQuery } from '../lib/useServerQuery'

type GraphNode = { id: string; label: string; kind: 'hub' | 'spoke' | 'overflow' }
type GraphEdge = { source: string; target: string }
type Graph = { nodes: GraphNode[]; edges: GraphEdge[] }

const fetchGraph = createServerFn({ method: 'GET' })
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<Graph | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Graph>(`/api/v1/attackers-graph?id=${encodeURIComponent(data.id)}`)
  })

export function AttackerGraph({ id }: { id: string }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const graph = useServerQuery(fetchGraph, { id }, [id])

  useEffect(() => {
    const container = containerRef.current
    if (!container || !graph || graph.nodes.length === 0) return
    let instance: import('cytoscape').Core | null = null
    let disposed = false
    ;(async () => {
      const cytoscape = (await import('cytoscape')).default
      if (disposed) return
      const accent = cssColor('--accent', '#d97757')
      const muted = cssColor('--text-muted', '#a5a9a6')
      const border = cssColor('--border-strong', 'rgba(255,255,255,0.14)')
      const text = cssColor('--text-primary', '#e9e6df')
      instance = cytoscape({
        container,
        elements: [
          ...graph.nodes.map((node) => ({ data: { id: node.id, label: node.label, kind: node.kind } })),
          ...graph.edges.map((edge) => ({ data: { source: edge.source, target: edge.target } })),
        ],
        layout: { name: 'concentric', concentric: (node) => (node.data('kind') === 'hub' ? 2 : 1), levelWidth: () => 1 },
        userZoomingEnabled: false,
        style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'font-size': 8,
              color: text,
              'background-color': muted,
              width: 14,
              height: 14,
              'text-valign': 'bottom',
              'text-margin-y': 3,
            },
          },
          { selector: 'node[kind = "hub"]', style: { 'background-color': accent, width: 30, height: 30, 'font-size': 10 } },
          { selector: 'node[kind = "overflow"]', style: { 'background-color': border, shape: 'round-rectangle' } },
          { selector: 'edge', style: { width: 1, 'line-color': border, 'curve-style': 'straight' } },
        ],
      })
    })()
    return () => {
      disposed = true
      instance?.destroy()
    }
  }, [graph])

  if (graph === null) return <span className="skeleton-line" aria-hidden="true" />
  if (graph.nodes.length <= 1) return null
  return (
    <>
      <p className="subtitle">Member IPs ({graph.nodes.length - 1} nodes)</p>
      <div ref={containerRef} style={{ width: '100%', height: 260 }} aria-label="attacker entity graph" />
    </>
  )
}
