// Artifact list for one analysis run — fetched lazily when the inspector
// opens, each row a download link through the BFF proxy.
import { createServerFn } from '@tanstack/react-start'
import { useServerQuery } from '../lib/useServerQuery'
import { ErrorStateBlock } from './ErrorState'

type ArtifactRow = {
  filename: string
  kind: string
  content_type: string
  size_bytes: number
  imported_at: string
}

const fetchArtifacts = createServerFn({ method: 'GET' })
  .inputValidator((input: { kind: string; key: string }) => input)
  .handler(async ({ data }): Promise<{ rows: ArtifactRow[] } | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<{ rows: ArtifactRow[] }>(
      `/api/v1/artifacts/${encodeURIComponent(data.kind)}/${encodeURIComponent(data.key)}`,
    )
  })

export function ArtifactList({ kind, artifactKey }: { kind: 'ghidra' | 'sandbox'; artifactKey: string }) {
  // #2178: a failed fetch used to land in the same empty row list as
  // "this run produced no artifacts", which rendered as nothing at all --
  // no section header, no explanation, no way back. Tri-state now keeps a
  // genuine zero invisible but names a failure and offers a retry.
  const query = useServerQuery(fetchArtifacts, { kind, key: artifactKey }, [kind, artifactKey])
  if (query.status === 'loading') return <span className="skeleton-line" aria-hidden="true" />
  if (query.status === 'error') {
    return (
      <ErrorStateBlock title="Artifacts failed to load" hint="The backend request failed." onRetry={query.retry} />
    )
  }
  const rows = query.data.rows
  if (rows.length === 0) return null
  return (
    <>
      <p className="subtitle">Artifacts</p>
      <table className="data-table">
        <tbody>
          {rows.map((row) => (
            <tr key={row.filename}>
              <td className="v">
                <a
                  className="lnk"
                  href={`/api/artifact/${kind}/${encodeURIComponent(artifactKey)}/${encodeURIComponent(row.filename)}`}
                >
                  {row.filename} ↓
                </a>
              </td>
              <td>
                <span className="badge badge--muted">{row.kind}</span>
              </td>
              <td className="n">{(row.size_bytes / 1024).toFixed(1)} KB</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}
