// Source health — per-sensor ingestion freshness + ES cluster state, plus
// the platform-service cards from ui/source_health.html: YARA scanner,
// runtime, ingestion-freshness verdict, dead letters (#1653).
import { Link, createFileRoute, useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { isLivePaused } from '../lib/live'
import { formatTimestamp } from '../lib/time'

type SensorHealth = {
  sensor: string
  documents: number
  last_seen: string
  state: 'ACTIVE' | 'QUIET' | 'STALE'
}

type SourceHealth = {
  cluster_status: string
  total_documents: number
  sensors: SensorHealth[]
  yara: {
    enabled: boolean
    last_scan: string
    rules_sha256: string
    samples: number
    matched: number
    errors: number
  }
  runtime: {
    uptime_seconds: number
    rss_bytes: number
    vm_bytes: number
  }
  ingest: {
    state: string
    last_ingest: string
    age_seconds: number
    recent_dead_letters: number
  }
  dead_letters: number
  pipeline: {
    state: string
    acked: number
    failed: number
    dropped: number
    active: number
    decode_failures: number
  }
}

const fetchHealth = createServerFn({ method: 'GET' }).handler(async (): Promise<SourceHealth | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<SourceHealth>('/api/v1/source-health')
})

export const Route = createFileRoute('/source-health')({
  loader: async () => ({ first: fetchHealth() }),
  component: SourceHealthPage,
})

function stateBadge(state: SensorHealth['state']) {
  const cls = state === 'ACTIVE' ? 'badge badge--success' : state === 'QUIET' ? 'badge badge--warning' : 'badge badge--danger'
  return <span className={cls}>{state}</span>
}

const COLUMNS: Column<SensorHealth>[] = [
  { header: 'sensor', className: 'v', render: (row) => row.sensor },
  { header: 'state', render: (row) => stateBadge(row.state) },
  { header: 'documents', className: 'n', render: (row) => row.documents.toLocaleString('en-US') },
  { header: 'last event', render: (row) => formatTimestamp(row.last_seen) },
]

function clusterBadge(status: string) {
  const cls = status === 'green' ? 'badge badge--success' : status === 'yellow' ? 'badge badge--warning' : 'badge badge--danger'
  return <span className={cls}>cluster {status}</span>
}

function formatDuration(totalSeconds: number): string {
  if (totalSeconds <= 0) return '—'
  const days = Math.floor(totalSeconds / 86_400)
  const hours = Math.floor((totalSeconds % 86_400) / 3_600)
  const minutes = Math.floor((totalSeconds % 3_600) / 60)
  const seconds = Math.floor(totalSeconds % 60)
  if (days > 0) return `${days}d ${hours}h ${minutes}m`
  if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`
  if (minutes > 0) return `${minutes}m ${seconds}s`
  return `${seconds}s`
}

function formatBytes(bytes: number): string {
  if (bytes <= 0) return '—'
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GiB`
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MiB`
  return `${Math.round(bytes / 1024)} KiB`
}

function CardRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="card__row">
      <span className="card__label">{label}</span>
      <span className="card__value card__value--mono">{value}</span>
    </div>
  )
}

function SourceHealthPage() {
  const { first } = Route.useLoaderData()
  const [health, setHealth] = useState<SourceHealth | null>(null)
  const router = useRouter()
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (!cancelled && result) setHealth(result)
    })
    return () => {
      cancelled = true
    }
  }, [first])
  // The legacy page re-rendered on every visit with fresh snapshot data;
  // here a visible-tab 60s cycle keeps the verdicts current, honoring the
  // shell LIVE switch (resume refetches immediately).
  useEffect(() => {
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible' && !isLivePaused()) void router.invalidate()
    }, 60_000)
    const onResume = () => void router.invalidate()
    window.addEventListener('hp-live-resumed', onResume)
    return () => {
      clearInterval(timer)
      window.removeEventListener('hp-live-resumed', onResume)
    }
  }, [router])
  const yara = health?.yara
  const runtime = health?.runtime
  const ingest = health?.ingest
  const pipeline = health?.pipeline
  return (
    <>
      <InvestigateHeader
        label="Operations"
        title="Source health"
        subtitle="Is every sensor still feeding the pipeline? Freshness per source, ordered by most recent event."
        chips={
          health ? (
            <>
              {clusterBadge(health.cluster_status)}
              <span className="chip">{health.total_documents.toLocaleString('en-US')} documents</span>
              <span className="chip">{health.sensors.length} sensors</span>
              <Link className="chip" to="/dead-letters" title="Inspect documents Elasticsearch rejected">
                {health.dead_letters.toLocaleString('en-US')} dead letters
              </Link>
            </>
          ) : undefined
        }
      />
      {health ? (
        <div className="tw:grid tw:grid-cols-12 tw:gap-3.5 tw:mb-6">
          <div className="card wide">
            <h2>Ingestion freshness</h2>
            <table className="data-table">
              <tbody>
                <tr>
                  <td>state</td>
                  <td className={`state s-${ingest?.state ?? 'unknown'}`}>{ingest?.state ?? 'unknown'}</td>
                </tr>
                <tr>
                  <td>latest indexed event</td>
                  <td className="v">{ingest?.last_ingest ? formatTimestamp(ingest.last_ingest) : '—'}</td>
                </tr>
                <tr>
                  <td>ingestion age</td>
                  <td className="v">{ingest && ingest.age_seconds >= 0 ? (ingest.age_seconds === 0 ? '0s' : formatDuration(ingest.age_seconds)) : '—'}</td>
                </tr>
                <tr>
                  <td>dead letters in 24h</td>
                  <td className="v">
                    <Link to="/dead-letters">{(ingest?.recent_dead_letters ?? 0).toLocaleString('en-US')}</Link>
                  </td>
                </tr>
              </tbody>
            </table>
            <p className="note">Delayed means the newest indexed event is over two minutes old; stale means over fifteen minutes.</p>
          </div>
          <div className="card half">
            <h2>YARA scanner</h2>
            <CardRow label="enabled" value={String(yara?.enabled ?? false)} />
            <CardRow label="last scan" value={yara?.last_scan ? formatTimestamp(yara.last_scan) : '—'} />
            <CardRow label="rules sha256" value={yara?.rules_sha256 || '—'} />
            <CardRow label="samples scanned" value={(yara?.samples ?? 0).toLocaleString('en-US')} />
            <CardRow label="samples matched" value={(yara?.matched ?? 0).toLocaleString('en-US')} />
            <CardRow label="errors" value={(yara?.errors ?? 0).toLocaleString('en-US')} />
            <p className="note">The scanner has no network and receives payload stores read-only.</p>
          </div>
          <div className="card half">
            <h2>Backend runtime</h2>
            <CardRow label="uptime" value={formatDuration(runtime?.uptime_seconds ?? 0)} />
            <CardRow label="resident memory" value={formatBytes(runtime?.rss_bytes ?? 0)} />
            <CardRow label="virtual memory" value={formatBytes(runtime?.vm_bytes ?? 0)} />
            <CardRow label="Elasticsearch cluster" value={health.cluster_status} />
            <p className="note">The Rust backend service's own process, from /proc/self — the legacy card's Go heap and goroutines have no equivalent here.</p>
          </div>
          <div className="card half">
            <h2>Pipeline status</h2>
            <CardRow label="Filebeat" value={pipeline?.state ?? 'unknown'} />
            <CardRow label="acknowledged" value={(pipeline?.acked ?? 0).toLocaleString('en-US')} />
            <CardRow
              label="failed / dropped / active"
              value={`${(pipeline?.failed ?? 0).toLocaleString('en-US')} / ${(pipeline?.dropped ?? 0).toLocaleString('en-US')} / ${(pipeline?.active ?? 0).toLocaleString('en-US')}`}
            />
            <CardRow label="decode failures" value={(pipeline?.decode_failures ?? 0).toLocaleString('en-US')} />
            <p className="note">
              Filebeat's own fallback index for log lines its json.decode processor couldn't parse at all — a distinct,
              earlier failure layer from dead letters above, which only holds documents Elasticsearch itself rejected after
              Filebeat successfully shipped them. Failed/dropped counters or decode-failure growth indicate a pipeline
              error.
            </p>
          </div>
        </div>
      ) : null}
      <MasterDetailTable
        rows={health ? health.sensors : null}
        columns={COLUMNS}
        rowKey={(row) => row.sensor}
        emptyState={{
          title: 'No sensors are reporting yet',
          hint: 'A sensor appears here once its first event reaches Elasticsearch.',
        }}
        inspectorTitle="Sensor details"
      />
    </>
  )
}
