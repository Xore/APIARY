// One sensor's captured events, read in that sensor's own terms (#1856).
//
// Every sensor that produces events gets a view through here. Where
// lib/sensorProtocols knows the protocol, the columns and the expanded
// artefact are that protocol's — the SIP request, the ICS request and the
// response served, the DNS name queried, the raw DNP3 frame. Where it does
// not, the sensor's own fields are shown instead of nothing, which is the
// state this replaces for twenty-three of twenty-six sensors.
//
// The full record is always one row away regardless, so a curated reading
// can never be a lossy one.
import { Link } from '@tanstack/react-router'
import { MasterDetailTable, type Column } from './Investigate'
import { formatTimestamp } from '../lib/time'
import { type Json } from '../lib/json'
import {
  fieldBlock,
  fieldText,
  meaningfulFields,
  protocolFor,
  readField,
  type SensorEventRow,
} from '../lib/sensorProtocols'

function block(value: Json | undefined) {
  const text = fieldBlock(value)
  if (!text) return ''
  return <pre className="hp-md__preview">{text}</pre>
}

function buildColumns(sensor: string): Column<SensorEventRow>[] {
  const spec = protocolFor(sensor)
  const columns: Column<SensorEventRow>[] = [
    { header: 'seen', render: (row) => formatTimestamp(row.when) },
    {
      header: 'source',
      className: 'v',
      render: (row) => (row.src_ip ? `${row.src_ip}${row.src_port ? `:${row.src_port}` : ''}` : '—'),
    },
    { header: 'port', className: 'n', render: (row) => (row.dst_port ? String(row.dst_port) : '') },
  ]

  if (spec) {
    for (const column of spec.columns) {
      columns.push({
        header: column.header,
        className: column.mono ? 'v' : undefined,
        render: (row) => {
          const text = fieldText(readField(row.fields, column.field))
          if (!text) return ''
          if (column.badge) return <span className={`badge badge--${column.badge}`}>{text}</span>
          return column.mono ? <code>{text}</code> : text
        },
      })
    }
    if (spec.sessionField) {
      columns.push({
        header: 'session',
        detail: true,
        render: (row) => {
          const id = fieldText(readField(row.fields, spec.sessionField as string))
          if (!id) return ''
          // The session record already assembles every sensor's events for
          // this session, so linking beats copying them in here.
          return <Link to="/sessions/$id" params={{ id }}>{id}</Link>
        },
      })
    }
    for (const artefact of spec.artefacts) {
      columns.push({
        header: artefact.label.toLowerCase(),
        detail: true,
        render: (row) => block(readField(row.fields, artefact.field)),
      })
    }
    if (spec.hashFields?.length) {
      columns.push({
        header: 'captured file',
        detail: true,
        render: (row) => {
          for (const ref of spec.hashFields ?? []) {
            const hash = fieldText(readField(row.fields, ref))
            if (hash) {
              // The payload record owns the bytes, the analysis and the
              // verdicts; duplicating any of that here would go stale.
              return (
                <Link to="/payload-analysis/$hash" params={{ hash }}>
                  <code>{hash}</code>
                </Link>
              )
            }
          }
          return ''
        },
      })
    }
  } else {
    // No protocol spec: show what the sensor wrote, which is strictly more
    // than the nothing this page used to show for it.
    columns.push({
      header: 'what the sensor recorded',
      className: 'v',
      render: (row) => {
        const entries = meaningfulFields(row.fields).slice(0, 3)
        if (entries.length === 0) return '—'
        return entries.map(([key, value]) => `${key} ${fieldText(value)}`).join(' · ')
      },
    })
    columns.push({
      header: 'fields',
      detail: true,
      render: (row) => {
        const entries = meaningfulFields(row.fields)
        if (entries.length === 0) return ''
        return <pre className="hp-md__preview">{entries.map(([k, v]) => `${k}: ${fieldText(v)}`).join('\n')}</pre>
      },
    })
  }

  // Always last, always present: a curated reading must never be the only
  // reading available.
  columns.push({
    header: 'raw record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row.fields, null, 2)}</pre>,
  })
  return columns
}

export function SensorEventsTable({
  sensor,
  rows,
  total,
}: {
  sensor: string
  rows: SensorEventRow[] | null
  total?: number
}) {
  const spec = protocolFor(sensor)
  return (
    <>
      <h2 className="label-section">{sensor}</h2>
      <p className="card__meta">
        {spec
          ? `${spec.what}. Newest first, last 48h.`
          : `Everything this sensor recorded, as it recorded it — no protocol reading is defined for it yet. Newest first, last 48h.`}
        {typeof total === 'number' && rows && total > rows.length
          ? ` Showing ${rows.length.toLocaleString('en-US')} of ${total.toLocaleString('en-US')}.`
          : ''}
      </p>
      <MasterDetailTable
        rows={rows}
        columns={buildColumns(sensor)}
        rowKey={(row, index) => `${row.when}-${index}`}
        // #1868: every row opens its own full page — the record, the rest
        // of the session, the rest of the flow, and what else the source
        // did. The inspector pane shows the row's fields and stops there.
        detailHref={(row) => (row.id ? `/event/${encodeURIComponent(row.id)}` : undefined)}
        inspectorTitle={`${sensor} event`}
        emptyState={{
          title: `No ${sensor} activity in the last 48h`,
          hint: 'The sensor is listed because it produced events recently — just not inside this window.',
        }}
      />
    </>
  )
}
