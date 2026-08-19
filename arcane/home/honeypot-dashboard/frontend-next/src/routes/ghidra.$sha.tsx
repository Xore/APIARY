// Ghidra decompilation detail — one binary's analysis record, call-graph
// SVG rendered inline from the artifact store, and every report artifact.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { InvestigateHeader } from '../components/Investigate'
import { ArtifactList } from '../components/ArtifactList'
import { GhidraCallGraph } from '../components/GhidraCallGraph'
import { useResolved } from '../lib/hooks'
import { pathString, type JsonRecord } from '../lib/json'

type Run = JsonRecord

const fetchRun = createServerFn({ method: 'GET' })
  .inputValidator((input: { sha: string }) => input)
  .handler(async ({ data }): Promise<Run | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Run>(`/api/v1/ghidra/${encodeURIComponent(data.sha)}`)
  })

export const Route = createFileRoute('/ghidra/$sha')({
  loader: async ({ params }) => ({ first: fetchRun({ data: { sha: params.sha } }) }),
  component: GhidraDetail,
})

function GhidraDetail() {
  const { first } = Route.useLoaderData()
  const { sha } = Route.useParams()
  const resolved = useResolved(first)
  const run: Run | null | 'missing' = resolved === undefined ? null : resolved ?? 'missing'

  if (run === 'missing') {
    return <InvestigateHeader label="Evidence" title={sha.slice(0, 24)} subtitle="No Ghidra analysis found for this hash." />
  }
  const doc = run === null ? null : run
  const callgraph = pathString(doc, 'ghidra', 'call_graph_svg')
  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title={`Ghidra — ${sha.slice(0, 24)}…`}
        subtitle="Static decompilation of one captured binary: capa capabilities, call graph, and the generated report artifacts."
        chips={
          doc ? (
            <>
              <span className="chip">exit {pathString(doc, 'exit_status')}</span>
              <Link className="chip" to="/payload-analysis/$hash" params={{ hash: sha }}>
                payload analysis →
              </Link>
              <Link className="chip" to="/payload-workbench/results">← all results</Link>
            </>
          ) : undefined
        }
      />
      {doc ? (
        <div className="card wide">
          <h2>Call graph (interactive)</h2>
          <GhidraCallGraph sha={sha} />
        </div>
      ) : null}
      {callgraph ? (
        <div className="card wide">
          <h2>Call graph (static image)</h2>
          <p className="note">
            Assembled from the largest functions outward. A plain, script-free fallback for the interactive graph above —
            always available even with JavaScript disabled, and downloadable on its own.
          </p>
          <div className="card__scroll">
            <img
              src={`/api/artifact/ghidra/${encodeURIComponent(sha)}/${encodeURIComponent(callgraph)}`}
              alt="function call graph"
              style={{ maxWidth: '100%' }}
            />
          </div>
        </div>
      ) : null}
      <div className="card wide">
        <h2>Report artifacts</h2>
        <ArtifactList kind="ghidra" artifactKey={sha} />
      </div>
      <div className="card wide">
        <h2>Analysis record</h2>
        {doc === null ? (
          <span className="skeleton-line" aria-hidden="true" />
        ) : (
          <div className="card__scroll">
            <pre className="code">{JSON.stringify(doc, null, 2)}</pre>
          </div>
        )}
      </div>
    </>
  )
}
