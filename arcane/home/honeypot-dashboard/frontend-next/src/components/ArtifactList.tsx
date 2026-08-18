// Artifact list for one analysis run — fetched lazily when the inspector
// opens, each row a download link through the BFF proxy.
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'

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
  const [rows, setRows] = useState<ArtifactRow[] | null>(null)
  useEffect(() => {
    let cancelled = false
    setRows(null)
    fetchArtifacts({ data: { kind, key: artifactKey } }).then((result) => {
      if (!cancelled) setRows(result?.rows ?? [])
    })
    return () => {
      cancelled = true
    }
  }, [kind, artifactKey])
  if (rows === null) return <span className="skeleton-line" aria-hidden="true" />
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
