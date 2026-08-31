// Search results — the full grouped view behind the command palette's
// Enter: every matched group with counts and pivots.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'

type Hit = { label: string; count: number; url: string }
type Group = { title: string; hits: Hit[]; more: number; more_url: string }
type SearchResult = { query: string; redirect: string | null; groups: Group[]; total: number }
/** #2178: result carries 'failed' separately from the no-query idle null. */
type Outcome = SearchResult | 'failed'

const searchFn = createServerFn({ method: 'GET' })
  .validator((input: { q: string }) => input)
  .handler(async ({ data }): Promise<SearchResult | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<SearchResult>(`/api/v1/search?q=${encodeURIComponent(data.q)}`)
  })

export const Route = createFileRoute('/search')({
  validateSearch: (search: Record<string, unknown>): { q: string } => ({
    q: typeof search.q === 'string' ? search.q : '',
  }),
  loaderDeps: ({ search }) => search,
  // #2178: a bare null used to mean three different things here -- no query,
  // still streaming, request failed -- and the page rendered them all the
  // same. Resolve 'failed' explicitly so the UI can tell the outage apart.
  loader: async ({ deps }) => ({
    first: deps.q
      ? searchFn({ data: { q: deps.q } }).then((response): Outcome | null => (response === null ? 'failed' : response))
      : Promise.resolve(null),
  }),
  component: SearchPage,
})

function SearchPage() {
  const { first } = Route.useLoaderData()
  const { q } = Route.useSearch()
  const navigate = Route.useNavigate()
  const [query, setQuery] = useState(q)
  const [result, setResult] = useState<Outcome | null>(null)

  useEffect(() => {
    let cancelled = false
    setResult(null)
    first.then((response) => {
      if (!cancelled) setResult(response)
    })
    return () => {
      cancelled = true
    }
  }, [first])

  return (
    <>
      <InvestigateHeader
        label="Investigate"
        title="Search results"
        subtitle="Grouped matches across sources, sessions, payloads, commands, credentials, fingerprints and signatures."
        chips={result && result !== 'failed' ? <span className="chip">{result.total.toLocaleString('en-US')} matches</span> : undefined}
      />
      <p className="note">
        Every source the dashboard holds, matched against your query.
      </p>
      <form
        className="filters"
        onSubmit={(event) => {
          event.preventDefault()
          void navigate({ search: { q: query.trim() } })
        }}
      >
        <input
          className="form-input"
          type="search"
          placeholder="IP, session, hash, credential, command…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="Search query"
        />
        <button className="btn btn-secondary btn-sm" type="submit">
          Search
        </button>
      </form>
      {q && result === null ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : null}
      {result === 'failed' ? (
        /* #2178: an outage used to hold these skeletons exactly like a slow
           request would. Name it; the form above is the retry. */
        <div className="card wide">
          <ErrorStateBlock
            title="The search request failed"
            hint="The backend did not answer — results here are never cached. Re-submitting the query re-runs the search."
          />
        </div>
      ) : null}
      {result && result !== 'failed' && result.total === 0 ? (
        /* The Go zero-state (search.html:57-66): explain what was searched
           and hand the operator pivots out, never a bare sentence. */
        <div className="card wide">
          <div className="empty-state">
            <h3>Nothing matched “{result.query}”</h3>
            <p>
              No sensor event, session, payload, command, credential, detection, fingerprint, decoy, or sandbox run
              mentions this value. Sensors only hold the retention window configured for this deployment — an older
              indicator may have aged out.
            </p>
            <div className="filters">
              <Link className="chip" to="/events">
                browse all events
              </Link>
              <Link className="chip" to="/ips">
                attack sources
              </Link>
              <Link className="chip" to="/payloads">
                captured payloads
              </Link>
              <Link className="chip" to="/history" search={{ q: result.query }}>
                search Elasticsearch history
              </Link>
            </div>
          </div>
        </div>
      ) : null}
      {result && result !== 'failed'
        ? result.groups.map((group) => (
            <div className="card half" key={group.title}>
              <h2>{group.title}</h2>
              <table className="data-table">
                <tbody>
                  {group.hits.map((hit) => (
                    <tr key={hit.label}>
                      <td className="n">{hit.count.toLocaleString('en-US')}</td>
                      <td className="v">
                        {hit.url.startsWith('/') ? <Link to={hit.url}>{hit.label}</Link> : hit.label}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {group.more > 0 ? (
                /* Overflow past the 8-per-group cap (search.html:51). */
                <p className="note">
                  <a className="lnk" href={group.more_url}>
                    {group.more.toLocaleString('en-US')} more →
                  </a>
                </p>
              ) : null}
            </div>
          ))
        : null}
    </>
  )
}
