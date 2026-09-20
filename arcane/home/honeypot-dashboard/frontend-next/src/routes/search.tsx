// Search results — the full grouped view behind the command palette's
// Enter: every matched group with counts and pivots.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '../components/ui/card'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyTitle } from '../components/ui/empty'
import { Table, TableBody, TableCell, TableRow } from '../components/ui/table'
import { Field, FieldLabel } from '../components/ui/field'
import { Input } from '../components/ui/input'
import { Skeleton } from '../components/ui/skeleton'

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
        chips={result && result !== 'failed' ? <Badge variant="outline" className="font-mono">{result.total.toLocaleString('en-US')} matches</Badge> : undefined}
      />
      <p className="text-sm text-muted-foreground">
        Every source the dashboard holds, matched against your query.
      </p>
      <form
        className="flex flex-col gap-3 sm:flex-row sm:items-end"
        onSubmit={(event) => {
          event.preventDefault()
          void navigate({ search: { q: query.trim() } })
        }}
      >
        <Field className="min-w-0 flex-1"><FieldLabel htmlFor="search-query">Search query</FieldLabel><Input
          id="search-query"
          type="search"
          placeholder="IP, session, hash, credential, command…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        /></Field>
        <Button variant="secondary" type="submit">
          Search
        </Button>
      </form>
      {q && result === null ? (
        <Card aria-label="Loading search results"><CardContent className="flex flex-col gap-3 pt-6"><Skeleton className="h-5 w-1/3" /><Skeleton className="h-5 w-full" /></CardContent></Card>
      ) : null}
      {result === 'failed' ? (
        /* #2178: an outage used to hold these skeletons exactly like a slow
           request would. Name it; the form above is the retry. */
        <Card><CardContent className="pt-6">
          <ErrorStateBlock
            title="The search request failed"
            hint="The backend did not answer — results here are never cached. Re-submitting the query re-runs the search."
          />
        </CardContent></Card>
      ) : null}
      {result && result !== 'failed' && result.total === 0 ? (
        /* The Go zero-state (search.html:57-66): explain what was searched
           and hand the operator pivots out, never a bare sentence. */
        <Card><Empty><EmptyHeader><EmptyTitle>Nothing matched “{result.query}”</EmptyTitle><EmptyDescription>
              No sensor event, session, payload, command, credential, detection, fingerprint, decoy, or sandbox run
              mentions this value. Sensors only hold the retention window configured for this deployment — an older
              indicator may have aged out.
            </EmptyDescription></EmptyHeader><EmptyContent><div className="filters">
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
            </div></EmptyContent></Empty></Card>
      ) : null}
      {result && result !== 'failed'
        ? result.groups.map((group) => (
            <Card className="min-w-0" key={group.title}>
              <CardHeader><CardTitle>{group.title}</CardTitle></CardHeader><CardContent className="overflow-x-auto">
              <Table>
                <TableBody>
                  {group.hits.map((hit) => (
                    <TableRow key={hit.label}>
                      <TableCell className="n">{hit.count.toLocaleString('en-US')}</TableCell>
                      <TableCell className="v">
                        {hit.url.startsWith('/') ? <Link to={hit.url}>{hit.label}</Link> : hit.label}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              </CardContent>{group.more > 0 ? (
                /* Overflow past the 8-per-group cap (search.html:51). */
                <CardFooter>
                  <a className="lnk" href={group.more_url}>
                    {group.more.toLocaleString('en-US')} more →
                  </a>
                </CardFooter>
              ) : null}
            </Card>
          ))
        : null}
    </>
  )
}
