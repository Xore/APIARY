// .index leaf for the same reason as cape.index.tsx (#2127): a
// component-ful revdeck.tsx swallowed revdeck.$sha whole.
// RevDeck — reverse-engineering deck runs (revdeck-analysis-v1). The
// empty state is normal until the ghidra-worker's drain produces output.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'
import { pathString } from '../lib/json'
import { CodeIcon } from '../components/CardIcons'

const fetchPage = createServerFn({ method: 'GET' })
  .validator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/revdeck?offset=${data.offset}&size=25`)
  })

// es_importer.rs wraps the raw revdeck payload one level deeper under the
// "revdeck" source label (build_document); the raw payload's own sha256 may
// also ride flat on some rows — same nested-vs-flat ambiguity the sandbox
// job field has, resolved the same way (nested first, flat fallback), e.g.
// payload-workbench.results.tsx's SANDBOX_COLUMNS.
function revdeckSha(row: StoreRow): string {
  return pathString(row, 'revdeck', 'sha256') || pathString(row, 'sha256')
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  {
    header: 'sha',
    className: 'v',
    primary: true,
    render: (row) => {
      const sha = revdeckSha(row)
      return sha ? <code>{sha.slice(0, 16)}</code> : <span className="text-muted">no source hash</span>
    },
  },
  // Promoted into the card's badge row (detail-only, so the card does
  // not show the same badge twice).
  { header: 'exit', detail: true, render: (row) => <span className="badge badge--muted">{str(row, 'exit_status')}</span> },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row, null, 2)}</pre>,
  },
]

export const Route = createFileRoute('/revdeck/')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      pageSize={25}
      label="Evidence"
      title="RevDeck"
      subtitle="Reverse-engineering deck runs — deep binary walkthroughs produced by the ghidra worker's drain queue."
      columns={COLUMNS}
      rowKey={(_, index) => String(index)}
      inspectorTitle="RevDeck run"
      chipNoun="runs"
      emptyState={{
        title: 'No Rev·Deck runs match this view',
        hint: 'Submit one from the analysis workbench to see its tool-calling triage here.',
      }}
      layout="cards"
      cardIcon={() => CodeIcon}
      cardBadges={(row) => {
        const exit = str(row, 'exit_status')
        return exit ? <span className={exit === 'error' ? 'badge badge--muted text-danger' : 'badge badge--muted'}>{exit}</span> : null
      }}
      cardHref={(row) => {
        const sha = revdeckSha(row)
        return sha ? `/revdeck/${encodeURIComponent(sha)}` : undefined
      }}
    />
  )
}
