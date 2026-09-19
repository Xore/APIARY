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
import { cytoscapeTheme } from '../lib/cytoscapeTheme'
import { ErrorStateBlock } from './ErrorState'
import { useServerQuery } from '../lib/useServerQuery'
import { useAppearanceKey } from '../lib/prefs'

type GraphNode = { id: string; label: string; kind: 'hub' | 'spoke' | 'overflow' }
type GraphEdge = { source: string; target: string }
type Graph = { nodes: GraphNode[]; edges: GraphEdge[] }

const fetchGraph = createServerFn({ method: 'GET' })
  .validator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<Graph | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Graph>(`/api/v1/attackers-graph?id=${encodeURIComponent(data.id)}`)
  })

export function AttackerGraph({ id }: { id: string }) {
  const containerRef = useRef<HTMLDivElement & { __xoreCytoscape?: import('cytoscape').Core }>(null)
  const cyRef = useRef<import('cytoscape').Core | null>(null)
  // #1966: tri-state -- an error is no longer a forever-skeleton.
  const query = useServerQuery(fetchGraph, { id }, [id])
  const graph = query.status === 'ready' ? query.data : null
  const navigate = useNavigate()
  const [memberCount, setMemberCount] = useState<number | null>(null)
  const appearance = useAppearanceKey()

  useEffect(() => {
    cyRef.current?.style(cytoscapeTheme())
  }, [appearance])

  useEffect(() => {
    const container = containerRef.current
    if (!container || !graph || graph.nodes.length === 0) return
    let instance: import('cytoscape').Core | null = null
    let observer: ResizeObserver | null = null
    let disposed = false
    ;(async () => {
      const cytoscape = (await import('cytoscape')).default
      if (disposed) return
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
        style: cytoscapeTheme(),
      })
      cyRef.current = instance
      container.__xoreCytoscape = instance
      instance.on('mouseover', 'node, edge', (event) => event.target.addClass('hover'))
      instance.on('mouseout', 'node, edge', (event) => event.target.removeClass('hover'))
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
      delete container.__xoreCytoscape
      if (cyRef.current === instance) cyRef.current = null
      instance?.destroy()
    }
  }, [graph, navigate])

  if (query.status === 'error') {
    return (
      <ErrorStateBlock
        title="The attacker graph failed to load"
        hint="The identity graph endpoint was not reachable."
        onRetry={query.retry}
      />
    )
  }
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
          border: '1px solid var(--border-200)',
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
