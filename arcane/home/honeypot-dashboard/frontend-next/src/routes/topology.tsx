// Fleet topology (#1989) — what exposes what, where a byte flows, and
// which stack owns which container. The SHAPE is static configuration,
// served by /api/v1/topology; the LIVENESS is joined here from the two
// endpoints that already own it: source-health freshness per sensor and
// services-adapter container states. No new writes, no new indices.
import { createFileRoute, useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { EChart } from '../components/EChart'
import { ErrorStateBlock } from '../components/ErrorState'
import { InvestigateHeader } from '../components/Investigate'
import { useLiveInterval } from '../lib/live'

type ExposedPort = {
  proto: string
  /** Attacker-facing port on the VPS; 0 = tunnel-only, never published. */
  public: number
  host: number
  proxy: boolean
}

type SensorRow = {
  sensor: string
  stack: string
  containers: string[]
  ingress: string[]
  hostnames: string[]
  ports: ExposedPort[]
  raw_index: string
}

type StackRow = {
  stack: string
  containers: { name: string; adapterVisible: boolean }[]
}

type Topology = {
  generated_at: string
  sensors: SensorRow[]
  stacks: StackRow[]
}

type SensorFreshness = {
  sensor: string
  last_seen: string
  state: 'ACTIVE' | 'QUIET' | 'STALE'
}

type ContainerState = {
  name: string
  state: string
  exit_code?: number | null
  health?: string
}

const fetchTopology = createServerFn({ method: 'GET' }).handler(async (): Promise<Topology | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<Topology>('/api/v1/topology')
})

const fetchHealth = createServerFn({ method: 'GET' }).handler(async (): Promise<SensorFreshness[] | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const health = await serviceJSON<{ sensors: SensorFreshness[] }>('/api/v1/source-health')
  return health?.sensors ?? null
})

const fetchServices = createServerFn({ method: 'GET' }).handler(async (): Promise<ContainerState[] | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const services = await serviceJSON<{ available: boolean; services: ContainerState[] }>('/api/v1/services')
  return services?.available ? services.services : null
})

export const Route = createFileRoute('/topology')({
  loader: async () => ({
    // Three independent sources, joined client-side; a liveness failure must
    // not take the static shape down with it, so each degrades separately —
    // and a rejected topology call degrades to all-null rather than leaving
    // the page waiting forever (#1966's failure-must-be-visible rule).
    first: Promise.all([fetchTopology(), fetchHealth().catch(() => null), fetchServices().catch(() => null)]).catch(
      () => [null, null, null] as const,
    ),
  }),
  component: TopologyPage,
})

function ingressBadge(kind: string) {
  const cls =
    kind === 'traefik' ? 'badge badge--info' : kind === 'portbridge' ? 'badge' : 'badge badge--warning'
  const label = kind === 'traefik' ? 'Traefik :443' : kind === 'portbridge' ? 'raw portbridge' : 'tunnel only'
  return <span className={cls}>{label}</span>
}

function freshnessBadge(row: SensorFreshness | undefined) {
  if (!row) return <span className="text-muted">—</span>
  const cls = row.state === 'ACTIVE' ? 'badge badge--success' : row.state === 'QUIET' ? 'badge badge--warning' : 'badge badge--danger'
  return (
    <span className={cls} title={row.last_seen}>
      {row.state}
    </span>
  )
}

function portChip(port: ExposedPort) {
  const label =
    port.public === 0
      ? `${port.host}/${port.proto} · tunnel`
      : `${port.public}/${port.proto} → ${port.host}${port.proxy ? ' +PROXY' : ''}`
  return (
    <span className="chip" style={{ fontFamily: 'var(--mono, monospace)', fontSize: '0.78rem' }}>
      {label}
    </span>
  )
}

function containerBadge(state: ContainerState | undefined, adapterVisible: boolean) {
  if (!adapterVisible) {
    return (
      <span className="chip text-muted" title="Outside services-adapter's allowlist — no live state is reported">
        {state?.name.replace(/^hp-/, '') ?? ''}
      </span>
    )
  }
  const label = state?.state ?? 'unknown'
  const cls = label === 'running' ? 'badge badge--success' : label === 'exited' || label === 'not_found' ? 'badge badge--danger' : 'badge badge--warning'
  return (
    <span className={cls} title={state?.health ? `docker health: ${state.health}` : undefined}>
      {label}
    </span>
  )
}

function TopologyPage() {
  const { first } = Route.useLoaderData()
  const [topology, setTopology] = useState<Topology | null>(null)
  const [failed, setFailed] = useState(false)
  const [freshness, setFreshness] = useState<Map<string, SensorFreshness>>(new Map())
  const [containers, setContainers] = useState<Map<string, ContainerState>>(new Map())
  const router = useRouter()

  useEffect(() => {
    let cancelled = false
    void first.then(([topo, health, services]) => {
      if (cancelled) return
      if (!topo) {
        setFailed(true)
        return
      }
      setTopology(topo)
      setFreshness(new Map((health ?? []).map((row) => [row.sensor, row])))
      setContainers(new Map((services ?? []).map((row) => [row.name, row])))
    })
    return () => {
      cancelled = true
    }
  }, [first])

  // Same visible-tab cycle as source-health: the shape is static but the
  // freshness/container joins age, and loaders cover first paint so no
  // leading call.
  const refresh = useCallback(() => void router.invalidate(), [router])
  useLiveInterval(refresh, 60_000)

  if (failed) {
    return (
      <>
        <InvestigateHeader
          label="Operations"
          title="Fleet topology"
          subtitle="What exposes what, where a byte flows, which stack owns which container."
        />
        <ErrorStateBlock title="The topology map failed to load" hint="The backend request failed — nothing here is cached." />
      </>
    )
  }

  const totalContainers = topology?.stacks.reduce((sum, s) => sum + s.containers.length, 0) ?? 0

  return (
    <>
      <InvestigateHeader
        label="Operations"
        title="Fleet topology"
        subtitle="What exposes what, where a byte flows, and which stack owns which container — the joins between the pieces no other page makes."
        chips={
          topology ? (
            <>
              <span className="chip">{topology.sensors.length} sensors</span>
              <span className="chip">{topology.stacks.length} stacks</span>
              <span className="chip">{totalContainers} containers</span>
            </>
          ) : undefined
        }
      />

      <div className="section-heading">
        <div>
          <h2>How a byte flows</h2>
          <p>Ingress path → sensor → Filebeat → raw index → worker → derived index → the page that shows it.</p>
        </div>
      </div>
      {/* The DAG is drawn once from static config; stage liveness lives in
          the sections below where it can carry a verdict, not just a node. */}
      <div className="card wide">
        <EChart kind="sankey" url="/api/topology/flow" height={820} />
        <p className="note">
          Every path crosses the VPS: if it restarts, new attack traffic stops reaching every decoy at once, while
          already-captured logs keep indexing from disk. Canarytokens is drawn deliberately off the Filebeat artery — its
          triggers come back through the HTTP switchboard into the adapter's own index.
        </p>
      </div>

      <div className="section-heading">
        <div>
          <h2>Exposure</h2>
          <p>Per sensor: the ports an attacker can reach, the path they arrive by, and whether the sensor is still feeding.</p>
        </div>
      </div>
      <div className="card wide">
        <table className="data-table">
          <thead>
            <tr>
              <th>sensor</th>
              <th>ingress</th>
              <th>ports (public → home)</th>
              <th>raw index</th>
              <th>feed state</th>
            </tr>
          </thead>
          <tbody>
            {(topology?.sensors ?? []).map((row) => (
              <tr key={row.sensor}>
                <td className="v">{row.sensor}</td>
                <td>
                  {row.ingress.map((kind) => (
                    <span key={kind} style={{ marginRight: 'var(--space-xs)' }}>
                      {ingressBadge(kind)}
                    </span>
                  ))}
                  {row.hostnames.length > 0 ? (
                    <div className="note" style={{ margin: 0 }}>
                      {row.hostnames.join(' · ')}
                    </div>
                  ) : null}
                </td>
                <td>
                  {row.ports.length === 0 ? (
                    <span className="text-muted">hostname only</span>
                  ) : (
                    row.ports.map((port) => (
                      <span key={`${port.proto}-${port.public}-${port.host}`} style={{ display: 'inline-block', marginRight: 'var(--space-xs)', marginBottom: 'var(--space-xs)' }}>
                        {portChip(port)}
                      </span>
                    ))
                  )}
                </td>
                <td className="v text-muted">{row.raw_index}</td>
                <td>{freshnessBadge(freshness.get(row.sensor))}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="note">+PROXY means the upstream appends PROXY protocol v1 — those are the sensors that can see a real client address.</p>
      </div>

      <div className="section-heading">
        <div>
          <h2>Runtime containers</h2>
          <p>Stack membership with live docker state where services-adapter reports it.</p>
        </div>
      </div>
      <div className="hp-flow--loose">
        {(topology?.stacks ?? []).map((stack) => (
          <div className="card half" key={stack.stack}>
            <h2>{stack.stack}</h2>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-xs)' }}>
              {stack.containers.map((container) => (
                <span key={container.name}>{containerBadge(containers.get(container.name), container.adapterVisible)}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
      {topology && containers.size === 0 ? (
        <p className="note">No container states right now — services-adapter is unreachable or answered unavailable; the grouping above is config-only.</p>
      ) : null}
    </>
  )
}
