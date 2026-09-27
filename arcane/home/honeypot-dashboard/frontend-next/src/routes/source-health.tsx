// Source health — per-sensor ingestion freshness + ES cluster state, plus
// the platform-service cards from ui/source_health.html: YARA scanner,
// runtime, ingestion-freshness verdict, dead letters (#1653).
import { Link, createFileRoute, useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { useLiveInterval } from '../lib/live'
import { formatTimestamp } from '../lib/time'
import {
  describeWebhookAttempt,
  webhookDeliveryNote,
  webhookDeliveryTone,
  type WebhookDelivery,
} from '../lib/webhookDelivery'

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
  /** Events in the last 24h with no recoverable source address (#1723). */
  unattributed_24h: number
  pipeline: {
    state: string
    acked: number
    failed: number
    dropped: number
    active: number
    decode_failures: number
  }
  /**
   * #3330: whether the alerts this page is about actually reach the
   * configured webhook. Read off this same snapshot rather than through a
   * second request — the page is the one an operator opens when something
   * is not arriving, and "the pipeline is fine, the webhook is refusing
   * us" is the distinction it can now make.
   */
  webhook: WebhookDelivery
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

/**
 * #3330. Deliberately reuses the page's existing badge vocabulary rather
 * than inventing a fourth tone, so the webhook verdict reads the same way
 * as the cluster and sensor badges already on this page. `disabled` is
 * neutral: a deployment with no webhook configured is not unhealthy, and a
 * red badge for it would be crying wolf on the common case.
 */
const DELIVERY_TONE_CLASS: Record<'ok' | 'warn' | 'bad' | 'flat', string> = {
  ok: 'badge badge--success',
  warn: 'badge badge--warning',
  bad: 'badge badge--danger',
  flat: 'badge',
}

function webhookBadge(delivery: WebhookDelivery | undefined) {
  // A chip is a verdict, and "disabled" is not one: a deployment that
  // chose not to configure a webhook is working as intended, and putting
  // that in the header strip would add a badge to every install for no
  // information. The card below still says so, in its own words. Every
  // other state earns the strip -- `unknown` especially, because that one
  // means this tier could not read the record, and saying so beats
  // rendering a card with nothing in it.
  if (!delivery || delivery.state === 'disabled') return null
  return <span className={DELIVERY_TONE_CLASS[webhookDeliveryTone(delivery.state)]}>webhook {delivery.state}</span>
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
  // #2178: every settled section of this page sits behind `health ?`,
  // and the loader collapses failures to null -- so a failed snapshot held
  // the page's opening skeleton forever. Track it separately: a first-load
  // failure names itself, while a failure after good data keeps the last
  // verdicts up (stale truth beats a blanked dashboard) with a note.
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (cancelled) return
      if (!result) {
        setFailed(true)
        return
      }
      setHealth(result)
      setFailed(false)
    })
    return () => {
      cancelled = true
    }
  }, [first])
  // The legacy page re-rendered on every visit with fresh snapshot data;
  // a visible-tab 60s cycle keeps the verdicts current. #1973: that cycle
  // is the shell's shared tick now rather than another hand-rolled copy
  // of the guards (resume refetches immediately; loaders cover first
  // paint, so no leading call).
  const refresh = useCallback(() => void router.invalidate(), [router])
  useLiveInterval(refresh, 60_000)
  const yara = health?.yara
  const runtime = health?.runtime
  const ingest = health?.ingest
  const pipeline = health?.pipeline
  const webhook = health?.webhook
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
              {webhookBadge(webhook)}
              <span className="chip">{health.total_documents.toLocaleString('en-US')} documents</span>
              <span className="chip">{health.sensors.length} sensors</span>
              <Link className="chip" to="/dead-letters" title="Inspect documents Elasticsearch rejected">
                {health.dead_letters.toLocaleString('en-US')} dead letters
              </Link>
            </>
          ) : undefined
        }
      />
      {failed && !health ? (
        <ErrorStateBlock
          title="Pipeline health failed to load"
          hint="The backend request failed — nothing here is cached."
          onRetry={refresh}
        />
      ) : null}
      {failed && health ? (
        <p className="note" role="alert">
          The latest health refresh failed — the figures below are the last ones fetched.
        </p>
      ) : null}
      {/* source_health.html:24-33's KPI strip. All four values were already
          on the API response; only the tiles were missing, so the page
          opened with no at-a-glance verdict at all. The two in-page
          anchors match the ids further down, same as the Go tier. */}
      {health ? (
        <div className="metric-grid">
          <a className="metric" href="#sensor-feeds" title="Jump to the per-sensor feed table">
            <div className="metric__value">{health.sensors.length.toLocaleString('en-US')}</div>
            <div className="metric__label">Configured feeds</div>
          </a>
          <Link className="metric" to="/history" title="Browse all indexed documents in Elasticsearch history">
            <div className="metric__value">{health.total_documents.toLocaleString('en-US')}</div>
            <div className="metric__label">Indexed documents</div>
          </Link>
          <a className="metric" href="#pipeline-status" title="Jump to the Filebeat pipeline status card">
            <div className="metric__value">{health.pipeline?.state ?? 'unknown'}</div>
            <div className="metric__label">Filebeat</div>
          </a>
          <Link className="metric" to="/dead-letters" title="Inspect rejected documents">
            <div className="metric__value">{health.dead_letters.toLocaleString('en-US')}</div>
            <div className="metric__label">Dead letters</div>
          </Link>
        </div>
      ) : null}
      {/* source_health.html:35 — the page's two organising headings were
          dropped, leaving eight cards in a flat run with nothing saying
          where the ingestion story ends and the platform story begins.
          Reworded from "sensor log tail to indexed document": this tier
          reads Elasticsearch only, and there is no log tail to describe. */}
      <div className="section-heading">
        <div>
          <h2>Ingestion pipeline detail</h2>
          <p>Every stage from sensor to indexed document, with freshness and failure counters.</p>
        </div>
        <Link className="section-link" to="/dead-letters">
          Inspect dead letters →
        </Link>
      </div>
      {health ? (
        <div className="hp-flow--loose">
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
        </div>
      ) : null}
      {/* source_health.html:44. The Go tier's "Prometheus metrics →"
          section-link is deliberately not restored: neither this frontend
          nor backend-service exposes a /metrics route, so it would be a
          link to nothing. */}
      <div className="section-heading">
        <div>
          <h2>Platform services</h2>
          <p>The scanner, the backend process itself, and the end-to-end pipeline verdict.</p>
        </div>
      </div>
      {health ? (
        <div className="hp-flow--loose">
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
            <CardRow label="Elasticsearch cluster" value={clusterBadge(health.cluster_status)} />
            <p className="note">The Rust backend service's own process, from /proc/self — the legacy card's Go heap and goroutines have no equivalent here.</p>
          </div>
          <div className="card half" id="pipeline-status">
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
          {/* #3330. Everything above this card describes ingestion; nothing
              on this page said whether the alerts it raises then reached
              the configured webhook, so a webhook that had been rejecting
              them looked identical to a healthy one. This is the last
              stage of the same path, and the one that fails silently. */}
          <div className="card half" id="webhook-delivery">
            <h2>Alert webhook delivery</h2>
            {!webhook ? (
              <p className="empty">The delivery record is not part of this backend&apos;s response.</p>
            ) : !webhook.available ? (
              <>
                <CardRow label="state" value={<span className={DELIVERY_TONE_CLASS.flat}>unknown</span>} />
                <p className="note">{webhookDeliveryNote(webhook)}</p>
              </>
            ) : webhook.state === 'disabled' ? (
              <p className="empty">{webhookDeliveryNote(webhook)}</p>
            ) : (
              <>
                <CardRow label="state" value={<span className={DELIVERY_TONE_CLASS[webhookDeliveryTone(webhook.state)]}>{webhook.state}</span>} />
                <CardRow label="target" value={webhook.target || '—'} />
                <CardRow label="deliveries attempted" value={webhook.messages.toLocaleString('en-US')} />
                <CardRow
                  label="consecutive failures"
                  value={`${webhook.consecutive_failures.toLocaleString('en-US')} (warns at ${webhook.failure_threshold})`}
                />
                <CardRow
                  label="last success"
                  value={webhook.last_success ? `${describeWebhookAttempt(webhook.last_success)} · ${formatTimestamp(webhook.last_success.at)}` : '—'}
                />
                <CardRow
                  label="last failure"
                  value={webhook.last_failure ? `${describeWebhookAttempt(webhook.last_failure)} · ${formatTimestamp(webhook.last_failure.at)}` : '—'}
                />
                {webhook.last_failure?.error ? <p className="note">Last error: {webhook.last_failure.error}</p> : null}
                <p className="note">{webhookDeliveryNote(webhook)}</p>
                <p className="note">
                  The worker records the outcome of every delivery — status, latency, retries, and the error — and never the
                  alert body, which quotes attacker-controlled text by construction. The target shown is the
                  webhook&apos;s origin only: a bot URL&apos;s path and query is where its secret lives, so neither is stored.
                </p>
              </>
            )}
          </div>
        </div>
      ) : null}
      <div className="section-heading" id="sensor-feeds">
        <div>
          <h2>Per-sensor feeds</h2>
          <p>Document counts and freshness per sensor, ordered by most recent event.</p>
        </div>
      </div>
      {/* source_health.html:41. Restored once the API could count these
          (#1723). Reworded from the Go tier's "in this tail": that
          described an in-memory log tail this stack does not have, and the
          figure is now a 24h Elasticsearch window. Only rendered when
          non-zero — a note explaining a discrepancy that isn't there would
          be noise. */}
      {health && health.unattributed_24h > 0 ? (
        <p className="note">
          {health.unattributed_24h.toLocaleString('en-US')} event
          {health.unattributed_24h === 1 ? '' : 's'} in the last 24 hours arrived over the WireGuard tunnel with no
          recoverable client address. They are counted in every total above but attributed to no source IP, because the
          tunnel peer is our own VPS and not an attacker — so the per-sensor counts below will not add up to those totals.
          Sensors reached over UDP, or on ports without a PROXY-protocol rule, have no way back to the real address.
        </p>
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
