// Entity hub/spoke graph for one attacker identity — cytoscape over the
// same node/edge shape the legacy /api/attacker-graph served, colors
// resolved from theme.css at init (canvas can't resolve var(), #1532).
// Interaction model ports hp-attackers.js: tap a spoke → /events?ip=…,
// scroll-zoom within min/max bounds, and a ResizeObserver keeps the
// layout fitted while the shell is resized (hp-attackers.js:135-146) —
// the shell itself carries attackers.html:150's resize:vertical style so
// the operator can drag it taller.
import { createServerFn } from '@tanstack/react-start'
import { useNavigate } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
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
  const navigate = useNavigate()
  const [memberCount, setMemberCount] = useState<number | null>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container || !graph || graph.nodes.length === 0) return
    let instance: import('cytoscape').Core | null = null
    let observer: ResizeObserver | null = null
    let disposed = false
    ;(async () => {
      const cytoscape = (await import('cytoscape')).default
      if (disposed) return
      const accent = cssColor('--accent', '#d97757')
      const muted = cssColor('--text-muted', '#a5a9a6')
      const border = cssColor('--border-strong', 'rgba(255,255,255,0.14)')
      instance = cytoscape({
        container,
        elements: [
          ...graph.nodes.map((node) => ({ data: { id: node.id, label: node.label, kind: node.kind } })),
          ...graph.edges.map((edge) => ({ data: { source: edge.source, target: edge.target } })),
        ],
        layout: {
          name: 'concentric',
          concentric: (node) => (node.data('kind') === 'hub' ? 2 : 1),
          levelWidth: () => 1,
          minNodeSpacing: 34,
          animate: false,
        },
        minZoom: 0.25,
        maxZoom: 4,
        style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'font-size': 10,
              color: muted,
              'text-valign': 'bottom',
              'text-margin-y': 6,
              'background-color': cssColor('--surface-2', '#343432'),
              'border-color': accent,
              'border-width': 1.2,
              width: 26,
              height: 26,
            },
          },
          {
            selector: 'node[kind = "hub"]',
            style: {
              'text-valign': 'center',
              'text-halign': 'center',
              'font-size': 12,
              'font-weight': 600,
              color: cssColor('--text-on-accent', '#211a17'),
              'background-color': accent,
              'border-color': cssColor('--surface-1', '#2c2c2a'),
              'border-width': 2,
              width: 56,
              height: 56,
            },
          },
          {
            selector: 'node[kind = "overflow"]',
            style: { 'background-color': cssColor('--surface-2', '#343432'), 'border-color': border, color: muted },
          },
          { selector: 'edge', style: { width: 1.2, 'line-color': border, 'curve-style': 'straight' } },
        ],
      })
      instance.on('tap', 'node[kind = "spoke"]', (event) => {
        void navigate({ to: '/events', search: { ip: event.target.data('label') as string } })
      })
      const fit = () => {
        instance?.resize()
        instance?.fit(undefined, 24)
      }
      if (typeof ResizeObserver !== 'undefined') {
        observer = new ResizeObserver(fit)
        observer.observe(container)
      }
      setMemberCount(graph.nodes.length - 1)
    })()
    return () => {
      disposed = true
      observer?.disconnect()
      instance?.destroy()
    }
  }, [graph, navigate])

  if (graph === null) return <span className="skeleton-line" aria-hidden="true" />
  if (graph.nodes.length <= 1) return null
  return (
    <>
      <div
        style={{
          position: 'relative',
          width: '100%',
          height: 320,
          minHeight: 220,
          maxHeight: '80vh',
          resize: 'vertical',
          overflow: 'hidden',
          border: '1px solid var(--border-strong)',
          borderRadius: 8,
        }}
      >
        <div ref={containerRef} style={{ width: '100%', height: '100%' }} role="img" aria-label="Attacker entity graph around one entity node" />
      </div>
      <p className="note">
        {memberCount === null
          ? 'Loading graph…'
          : `${memberCount} member IP${memberCount === 1 ? '' : 's'} — drag to pan, scroll to zoom, drag the corner to resize`}
      </p>
    </>
  )
}
