// Ghidra decompilation detail — the tabbed report from ghidra.html's
// "ghidra-detail-body" template (ghidra.html:93-263): Overview (identity,
// AI triage, Rev·Deck triage, crypto constants, fuzzy hashes, lief, capa,
// floss), Code (imports, call graphs, decompiled functions), Data (string
// table), Deep dive (types, globals, annotations, memory map, chat threads,
// symbol recovery), plus a Raw tab keeping the full analysis record and the
// report artifacts the port already exposed.
import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { InvestigateHeader } from '../components/Investigate'
import { ArtifactList } from '../components/ArtifactList'
import { GhidraCallGraph } from '../components/GhidraCallGraph'
import { confirmAction } from '../components/ConfirmDialog'
import { useResolved } from '../lib/hooks'
import { formatTimestamp } from '../lib/time'
import { type JsonRecord } from '../lib/json'

type Run = JsonRecord

// The worker's *_ghidra.json result, nested under the ES doc's `ghidra`
// key by the importer (es_importer.rs) — field names from ghidra.go's
// ghidraResult and its member structs. Everything optional: results
// predating a given worker feature simply lack its fields.
type Xref = { addr?: string; name?: string }
type GFunction = {
  address?: string
  name?: string
  signature?: string
  pseudocode?: string
  callers?: Xref[]
  callees?: Xref[]
}
type CryptoHit = { address?: string; constant?: string; algorithm?: string }
type FuzzyHashes = { ssdeep?: string; ssdeep_error?: string; tlsh?: string; tlsh_error?: string }
type Lief = {
  format?: string
  architecture?: string
  entrypoint?: string
  is_pie?: boolean
  stripped?: boolean | null
  is_dll?: boolean | null
  compile_timestamp?: number | null
  section_count?: number
  sections_truncated?: boolean
  libraries?: string[]
}
type Capa = {
  arch?: string
  os?: string
  format?: string
  capabilities?: { name?: string; namespace?: string; matches?: number }[]
  capabilities_truncated?: boolean
  attack?: { id?: string; tactic?: string; technique?: string; subtechnique?: string }[]
  mbc?: { id?: string; objective?: string; behavior?: string; method?: string }[]
  unsupported?: string
}
type Floss = {
  static_strings?: string[]
  static_strings_total?: number
  stack_strings?: string[]
  stack_strings_total?: number
  tight_strings?: string[]
  tight_strings_total?: number
  decoded_strings?: string[]
  decoded_strings_total?: number
  truncated?: boolean
  unsupported?: string
}
/** #1735: the Floss/Windows-sandbox IOC correlation, computed on read by
 * backend-service's ioc_correlation.rs and returned alongside the analysis
 * document (not nested under `ghidra` — it is derived, not worker output). */
type IocKind = {
  floss_only?: string[]
  sandbox_static_only?: string[]
  confirmed_at_runtime?: string[]
}
type IocCorrelation = {
  has_sandbox_run?: boolean
  has_floss_data?: boolean
  is_empty?: boolean
  ips?: IocKind
  domains?: IocKind
  urls?: IocKind
  unc_paths?: IocKind
}

type Citation = { raw?: string }
type RevDeck = {
  workflow?: string
  status?: string
  answer?: string
  steps?: number | null
  tool_calls?: number
  citations?: { valid?: Citation[]; invalid?: Citation[] } | null
  warnings?: string[]
}
type Triage = {
  workflow?: string
  family_guess?: string
  risk_level?: string
  behaviors?: string[]
  model?: string
  evidence_shown?: string
}
type GType = {
  name?: string
  kind?: string
  size?: number
  fields?: { name?: string; type?: string; offset?: number; size?: number }[]
  base_type?: string
}
type GGlobal = { addr?: string; name?: string; type?: string; size?: number }
type Annotations = {
  revision?: number
  entries?: Record<string, { display_name?: string; comment?: string; tags?: string[] }>
}
type MemoryBlock = {
  name?: string
  start?: string
  end?: string
  size?: number
  hexdump_preview?: { hex?: string; ascii?: string } | null
}
type ChatMessage = { role?: string; content?: unknown; tool_calls?: unknown; name?: string }
type ChatThreads = {
  threads?: { thread_id?: string; title?: string; message_count?: number }[]
  active_thread_messages?: ChatMessage[]
}
type GhidraDoc = {
  sha256?: string
  requested_at?: string
  started_at?: string
  completed_at?: string
  exit_status?: string
  error?: string
  functions?: GFunction[]
  strings?: string[]
  imports?: string[]
  findcrypt?: CryptoHit[]
  functions_deepened?: number
  functions_deepened_truncated?: boolean
  types?: GType[]
  globals?: GGlobal[]
  annotations?: Annotations | null
  memory_map?: MemoryBlock[]
  call_graph_svg?: string
  ai_triage?: Triage | null
  fuzzy_hashes?: FuzzyHashes | null
  lief?: Lief | null
  capa?: Capa | null
  floss?: Floss | null
  revdeck?: RevDeck | null
  revdeck_chat_threads?: ChatThreads | null
  revdeck_recovery?: { index?: unknown; symbols?: unknown } | null
}

const fetchRun = createServerFn({ method: 'GET' })
  .inputValidator((input: { sha: string }) => input)
  .handler(async ({ data }): Promise<Run | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Run>(`/api/v1/ghidra/${encodeURIComponent(data.sha)}`)
  })

type SubmitResult = { ok: boolean; error?: string }

// Same admin-gated submission seam as payload-analysis.$hash.tsx's
// submitGhidra — the detail page's Re-analyze button posts the same marker.
const submitReanalysis = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<SubmitResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      '/api/v1/ghidra/submit',
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hash: data.hash }) },
      { mounted: true },
    )
    const body = await response.json().catch(() => null)
    if (response.ok && body?.queued) return { ok: true }
    return { ok: false, error: body?.error || 'Ghidra submission failed.' }
  })

export const Route = createFileRoute('/ghidra/$sha')({
  loader: async ({ params }) => ({ first: fetchRun({ data: { sha: params.sha } }) }),
  component: GhidraDetail,
})

// Page-level numbered tab strip — theme.css's .tabs/.tab vocabulary
// (ghidra.html:106-111), same inlined roving-tabindex pattern as
// sandbox.$job.tsx's PageTabs (the shared Tabs component speaks
// .segmented and can't emit the numbered .tab markup).
function PageTabs({
  tabs,
  active,
  onSelect,
  label,
}: {
  tabs: { id: string; label: string }[]
  active: string
  onSelect: (id: string) => void
  label: string
}) {
  const move = (event: React.KeyboardEvent, index: number) => {
    let target: number | null = null
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') target = (index + 1) % tabs.length
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') target = (index - 1 + tabs.length) % tabs.length
    else if (event.key === 'Home') target = 0
    else if (event.key === 'End') target = tabs.length - 1
    if (target === null) return
    event.preventDefault()
    onSelect(tabs[target].id)
    document.getElementById(`gh-tab-${tabs[target].id}`)?.focus()
  }
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((tab, index) => (
        <button
          key={tab.id}
          id={`gh-tab-${tab.id}`}
          className={tab.id === active ? 'tab active' : 'tab'}
          type="button"
          role="tab"
          aria-selected={tab.id === active}
          aria-controls={`gh-panel-${tab.id}`}
          tabIndex={tab.id === active ? 0 : -1}
          onClick={() => onSelect(tab.id)}
          onKeyDown={(event) => move(event, index)}
        >
          <span>0{index + 1}</span>
          {tab.label}
        </button>
      ))}
    </div>
  )
}

function Panel({ id, active, children }: { id: string; active: string; children: React.ReactNode }) {
  return (
    <div
      className="dashboard-panel"
      id={`gh-panel-${id}`}
      role="tabpanel"
      aria-labelledby={`gh-tab-${id}`}
      hidden={id !== active}
    >
      {children}
    </div>
  )
}

function KV({ label, value, mono = true }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="card__row">
      <span className="card__label">{label}</span>
      <span className={mono ? 'card__value card__value--mono' : 'card__value'}>{value}</span>
    </div>
  )
}

function SectionHeading({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="section-heading">
      <div>
        <h2>{title}</h2>
        <p>{sub}</p>
      </div>
    </div>
  )
}

// ghidra.html's AI-assessment advisory box (ghidra.html:125/136).
function AIAdvisory({ children }: { children: React.ReactNode }) {
  return <div className="alert alert--warning">{children}</div>
}

// chatMessageText's port (ghidra.go #1286): a user/assistant content is a
// bare string; tool shapes are richer and rendered raw rather than parsed
// field-by-field (same "don't fail the document over an unanticipated
// variant" lesson as ghidraRevDeckCitation's typing).
function rawText(value: unknown): string {
  if (value == null) return ''
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2)
}

function TriageCard({ triage }: { triage: Triage | null | undefined }) {
  return (
    <div className="card wide" id="ghidra-triage">
      <h2>Automated triage</h2>
      {triage ? (
        <>
          <AIAdvisory>
            <strong>AI-generated assessment.</strong> Produced by a language model ({triage.model || 'model not recorded'}) reading
            the disassembly. It is a starting point for an analyst, not a finding. Treat every claim below as unverified until you
            have checked it against the functions, imports, and strings in the other tabs.
          </AIAdvisory>
          <KV label="workflow" value={triage.workflow} />
          <KV label="family guess" value={triage.family_guess || 'none offered'} />
          <KV label="risk level" value={triage.risk_level || 'not rated'} />
          {triage.evidence_shown ? <KV label="evidence shown" value={triage.evidence_shown} mono={false} /> : null}
          {triage.behaviors?.length ? (
            <>
              <p className="note">Suggested behaviors:</p>
              <ul className="">
                {triage.behaviors.map((behavior, index) => (
                  <li key={index}>{behavior}</li>
                ))}
              </ul>
            </>
          ) : null}
          {triage.evidence_shown ? (
            <p className="note">
              The model saw only the subset listed above, not the whole binary. A claim it did not make may simply be something it
              was never shown.
            </p>
          ) : null}
        </>
      ) : (
        <p className="empty">
          No AI triage was produced for this analysis — either the local model was unavailable when it ran, or triage is switched
          off on this host. Everything else on this page is raw Ghidra output and unaffected.
        </p>
      )}
    </div>
  )
}

function RevDeckCard({ revdeck }: { revdeck: RevDeck | null | undefined }) {
  return (
    <div className="card wide" id="ghidra-revdeck">
      <h2>Rev·Deck automated triage</h2>
      {revdeck ? (
        <>
          <AIAdvisory>
            <strong>AI-generated assessment.</strong> A second, independent AI aid: Rev·Deck's own bounded autonomous tool-calling
            loop against the Ghidra service, distinct from the automated triage above. Treat every claim below as unverified until
            you have checked it against the functions, imports, and strings in the other tabs.
          </AIAdvisory>
          <KV label="workflow" value={revdeck.workflow} />
          <KV
            label="status"
            mono={false}
            value={
              <>
                {revdeck.status}
                {revdeck.status === 'max_turns'
                  ? ' — the step budget ran out before the model finished; this is its best-effort synthesis, not a completed analysis'
                  : ''}
              </>
            }
          />
          {revdeck.steps != null ? <KV label="steps" value={revdeck.steps} /> : null}
          <KV label="tool calls" value={revdeck.tool_calls ?? 0} />
          {revdeck.answer ? (
            <div className="hp-ai-report">
              <p className="note">Answer:</p>
              {/* ghidra.html rendered this markdown via marked.js+DOMPurify
                  (hp-ghidra-markdown.js, #1285); its own documented no-JS
                  fallback is literal markdown text, which is what this port
                  renders — safe, legible, and dependency-free. */}
              <div className="hp-ai-report__body" style={{ whiteSpace: 'pre-wrap' }}>
                {revdeck.answer}
              </div>
            </div>
          ) : null}
          {revdeck.citations && (revdeck.citations.valid?.length || revdeck.citations.invalid?.length) ? (
            <div className="hp-ai-citations">
              {revdeck.citations.valid?.length ? (
                <div className="hp-ai-citations__group">
                  <p className="hp-ai-citations__label hp-ai-citations__label--valid">Citations</p>
                  <ul className="hp-ai-citations__list">
                    {revdeck.citations.valid.map((citation, index) => (
                      <li key={index} className="hp-ai-citations__item hp-ai-citations__item--valid">
                        <code>{citation.raw}</code>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {revdeck.citations.invalid?.length ? (
                <div className="hp-ai-citations__group">
                  <p className="hp-ai-citations__label hp-ai-citations__label--invalid">
                    Unverified — referenced by the model but not matched against the analysis
                  </p>
                  <ul className="hp-ai-citations__list">
                    {revdeck.citations.invalid.map((citation, index) => (
                      <li key={index} className="hp-ai-citations__item hp-ai-citations__item--invalid">
                        <code>{citation.raw}</code>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}
          {revdeck.warnings?.length ? (
            <>
              <p className="note">Warnings from the run:</p>
              <ul className="">
                {revdeck.warnings.map((warning, index) => (
                  <li key={index}>{warning}</li>
                ))}
              </ul>
            </>
          ) : null}
        </>
      ) : (
        <p className="empty">
          No Rev·Deck triage was produced for this analysis — either REVDECK_API_BASE is unset on this host, the Rev·Deck sidecar
          was unreachable, or the run produced no usable answer. Everything else on this page is raw Ghidra output and unaffected.
        </p>
      )}
    </div>
  )
}

function OverviewPanel({ sha, g }: { sha: string; g: GhidraDoc }) {
  const floss = g.floss
  return (
    <>
      <SectionHeading title="What this binary is" sub="Analysis identity, and any automated assessment of what the code does." />
      <div className="card wide">
        <h2>Analysis identity</h2>
        <KV label="SHA-256" value={sha} />
        <KV label="requested" value={formatTimestamp(g.requested_at)} />
        <KV label="started" value={formatTimestamp(g.started_at)} />
        <KV label="completed" value={formatTimestamp(g.completed_at)} />
        <KV label="exit status" value={g.exit_status} />
        <KV label="analysis method" mono={false} value="Ghidra headless decompilation — the binary is read, never executed" />
      </div>

      <TriageCard triage={g.ai_triage} />
      <RevDeckCard revdeck={g.revdeck} />

      <div className="card wide">
        <h2>Cryptographic constants</h2>
        {g.findcrypt?.length ? (
          <>
            <p className="note">
              Constant tables matching known cipher implementations. Their presence indicates the algorithm is compiled in; it does
              not by itself show the binary uses it maliciously. Addresses are file offsets, not virtual addresses.
            </p>
            <div className="card__scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>address</th>
                    <th>constant</th>
                    <th>algorithm</th>
                  </tr>
                </thead>
                <tbody>
                  {g.findcrypt.map((hit, index) => (
                    <tr key={index}>
                      <td className="v">{hit.address}</td>
                      <td className="v">{hit.constant}</td>
                      <td>{hit.algorithm}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <p className="empty">No known cryptographic constants were found.</p>
        )}
      </div>

      <div className="card wide">
        <h2>Fuzzy hashes</h2>
        {g.fuzzy_hashes ? (
          <>
            <p className="note">
              Similarity hashes for family clustering — two samples with close hashes share large runs of bytes, which exact
              SHA-256 dedup cannot show. Paste into a search that supports the matching algorithm to find related captures.
            </p>
            <KV
              label="ssdeep"
              mono={Boolean(g.fuzzy_hashes.ssdeep)}
              value={g.fuzzy_hashes.ssdeep || `not available${g.fuzzy_hashes.ssdeep_error ? ` — ${g.fuzzy_hashes.ssdeep_error}` : ''}`}
            />
            <KV
              label="TLSH"
              mono={Boolean(g.fuzzy_hashes.tlsh)}
              value={g.fuzzy_hashes.tlsh || `not available${g.fuzzy_hashes.tlsh_error ? ` — ${g.fuzzy_hashes.tlsh_error}` : ''}`}
            />
          </>
        ) : (
          <p className="empty">
            No fuzzy hashes were computed — either the statictools sidecar was unavailable when this ran, or it is switched off on
            this host.
          </p>
        )}
      </div>

      <div className="card wide">
        <h2>Structural analysis</h2>
        {g.lief ? (
          <>
            <p className="note">
              Parsed by lief independently of Ghidra's own loader — a second read of the same header/section data, useful as a
              cross-check.
            </p>
            <KV label="format" value={g.lief.format} />
            {g.lief.architecture ? <KV label="architecture" value={g.lief.architecture} /> : null}
            <KV label="entry point" value={g.lief.entrypoint} />
            <KV label="PIE" value={String(g.lief.is_pie ?? false)} />
            {g.lief.stripped != null ? <KV label="stripped" value={String(g.lief.stripped)} /> : null}
            {g.lief.is_dll != null ? <KV label="DLL" value={String(g.lief.is_dll)} /> : null}
            {g.lief.compile_timestamp != null ? (
              <KV
                label="declared compile time"
                mono={false}
                value={`${g.lief.compile_timestamp} — declared by the binary, not verified; malware routinely sets a false one`}
              />
            ) : null}
            <KV label="sections" value={`${g.lief.section_count ?? 0}${g.lief.sections_truncated ? ' (truncated in this report)' : ''}`} />
            {g.lief.libraries?.length ? <KV label="libraries" mono={false} value={g.lief.libraries.join(' ')} /> : null}
          </>
        ) : (
          <p className="empty">
            No structural data was recovered — either the statictools sidecar was unavailable, this host has it switched off, or
            lief did not recognise this file's format.
          </p>
        )}
      </div>

      <div className="card wide">
        <h2>Capabilities (capa)</h2>
        {g.capa ? (
          g.capa.unsupported ? (
            <p className="empty">
              Not applicable: {g.capa.unsupported}. This is capa declining the sample, not a sidecar failure — its default backend
              covers x86/amd64/arm64 only, so MIPS/ARM32 samples (common in this honeypot's IoT catch) land here on every run.
            </p>
          ) : (
            <>
              <p className="note">
                MITRE ATT&CK/MBC-tagged capabilities matched by rule — a capability being tagged here means code implementing it
                was found, not that it necessarily ran. capa's default backend covers x86/amd64/arm64 only.
              </p>
              <KV label="architecture" value={g.capa.arch} />
              <KV label="OS" value={g.capa.os} />
              <KV label="format" value={g.capa.format} />
              {g.capa.capabilities?.length ? (
                <>
                  <p className="note">
                    {g.capa.capabilities.length} capabilit{g.capa.capabilities.length === 1 ? 'y' : 'ies'} matched
                    {g.capa.capabilities_truncated ? ' (truncated in this view)' : ''}.
                  </p>
                  <div className="card__scroll" aria-label="Full capability list">
                    <pre className="code">
                      {g.capa.capabilities.map((c) => `${c.name}  [${c.namespace}]  matches=${c.matches}`).join('\n')}
                    </pre>
                  </div>
                </>
              ) : null}
              {g.capa.attack?.length ? (
                <>
                  <p className="note">MITRE ATT&CK techniques:</p>
                  <ul className="">
                    {g.capa.attack.map((a, index) => (
                      <li key={index}>
                        {a.id} — {a.tactic}
                        {a.technique ? ` :: ${a.technique}` : ''}
                        {a.subtechnique ? ` :: ${a.subtechnique}` : ''}
                      </li>
                    ))}
                  </ul>
                </>
              ) : null}
              {g.capa.mbc?.length ? (
                <>
                  <p className="note">Malware Behavior Catalog:</p>
                  <ul className="">
                    {g.capa.mbc.map((m, index) => (
                      <li key={index}>
                        {m.id} — {m.objective}
                        {m.behavior ? ` :: ${m.behavior}` : ''}
                        {m.method ? ` :: ${m.method}` : ''}
                      </li>
                    ))}
                  </ul>
                </>
              ) : null}
            </>
          )
        ) : (
          <p className="empty">
            No capa data — the statictools sidecar was unavailable, or this host has capa switched off. A genuinely unsupported
            architecture reports a distinct message instead of this one.
          </p>
        )}
      </div>

      <div className="card wide">
        <h2>Obfuscated strings (floss)</h2>
        {floss ? (
          floss.unsupported ? (
            <p className="empty">
              Not applicable: {floss.unsupported}. This is floss declining the sample, not a sidecar failure — its decoding/
              stack-string analysis covers PE and raw shellcode only, so the ELF samples common in this honeypot's catch land here
              on every run.
            </p>
          ) : (
            <>
              <p className="note">
                Decoded/stack/tight strings are recovered by emulating the sample, not by scanning raw bytes — they surface strings
                a plain strings dump on the binary itself would miss entirely.
              </p>
              <KV label="decoded strings" value={floss.decoded_strings_total ?? 0} />
              <KV label="stack strings" value={floss.stack_strings_total ?? 0} />
              <KV label="tight strings" value={floss.tight_strings_total ?? 0} />
              <KV label="static strings" value={floss.static_strings_total ?? 0} />
              {floss.truncated ? <p className="note">One or more of the lists above were truncated in this view.</p> : null}
              <div className="card__scroll" aria-label="Recovered FLOSS strings">
                <h3>Decoded strings</h3>
                <pre className="code">{(floss.decoded_strings ?? []).join('\n')}</pre>
                <h3>Stack strings</h3>
                <pre className="code">{(floss.stack_strings ?? []).join('\n')}</pre>
                <h3>Tight strings</h3>
                <pre className="code">{(floss.tight_strings ?? []).join('\n')}</pre>
                <h3>Static strings</h3>
                <pre className="code">{(floss.static_strings ?? []).join('\n')}</pre>
              </div>
            </>
          )
        ) : (
          <p className="empty">
            No floss data — the statictools sidecar was unavailable, or this host has floss switched off. A genuinely unsupported
            format reports a distinct message instead of this one.
          </p>
        )}
      </div>
    </>
  )
}

function CodePanel({ sha, g }: { sha: string; g: GhidraDoc }) {
  const deepened = g.functions_deepened ?? 0
  return (
    <>
      <SectionHeading title="What the code contains" sub="Recovered functions and the imported APIs they can reach." />
      <div className="card wide">
        <h2>Imports</h2>
        {g.imports?.length ? (
          <>
            <p className="note">
              {g.imports.length} imported symbol{g.imports.length === 1 ? '' : 's'}. What a binary imports bounds what it can do
              without further tricks.
            </p>
            <div className="card__scroll" aria-label="Full import list">
              <pre className="code">{g.imports.join('\n')}</pre>
            </div>
          </>
        ) : (
          <p className="empty">No imports were recovered.</p>
        )}
      </div>
      <div className="card wide">
        <h2>Interactive call graph</h2>
        {deepened > 0 ? (
          <>
            {/* GhidraCallGraph carries its own filter box and click-to-focus
                note; only the labels-safety caveat from ghidra.html:204 is
                added here. */}
            <p className="note">
              Node labels are names recovered from the sample and are untrusted — they are drawn to canvas, not the DOM, so they
              cannot execute script.
            </p>
            <GhidraCallGraph sha={sha} />
          </>
        ) : (
          <p className="empty">
            No caller/callee cross-references were recovered to graph — this analysis's deep-dive budget (#1167) didn't cover any
            function, or predates it.
          </p>
        )}
      </div>
      <div className="card wide">
        <h2>Call graph (static image)</h2>
        {g.call_graph_svg ? (
          <>
            <p className="note">
              Assembled from the largest functions outward. A plain, script-free fallback for the interactive graph above — always
              available even with JavaScript disabled, and downloadable on its own.
            </p>
            <a
              href={`/api/artifact/ghidra/${encodeURIComponent(sha)}/${encodeURIComponent(g.call_graph_svg)}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              <img
                src={`/api/artifact/ghidra/${encodeURIComponent(sha)}/${encodeURIComponent(g.call_graph_svg)}`}
                alt="Call graph of the analysed binary"
                style={{ maxWidth: '100%', background: '#fff', borderRadius: 'var(--radius-control)' }}
              />
            </a>
          </>
        ) : (
          <p className="empty">
            No call graph was rendered. This needs graphviz (<code>dot</code>) on the analysis host; without it the worker still
            writes the raw <code>.dot</code> beside the result.
          </p>
        )}
      </div>
      <div className="card wide">
        <h2>Functions</h2>
        {g.functions?.length ? (
          <>
            <p className="note">
              {g.functions.length} recovered function{g.functions.length === 1 ? '' : 's'}
              {deepened > 0
                ? `, ${deepened} with decompiled pseudocode and callers/callees${
                    g.functions_deepened_truncated ? ' (the largest functions only — the deep-dive budget did not cover the whole list)' : ''
                  }`
                : ' — none were decompiled for this analysis'}
              .
            </p>
            <div className="card__scroll" aria-label="Full function list">
              {g.functions.map((fn, index) => (
                <div key={index}>
                  <pre className="code">
                    {`${fn.address}  ${fn.name}  ${fn.signature}`}
                    {fn.callers?.length ? `\n  callers: ${fn.callers.map((x) => `${x.name}@${x.addr}`).join(' ')}` : ''}
                    {fn.callees?.length ? `\n  callees: ${fn.callees.map((x) => `${x.name}@${x.addr}`).join(' ')}` : ''}
                  </pre>
                  {/* ghidra.html:209-222 ran Prism over this pseudocode
                      (page-scoped prism.js/prism.css, #1288/#1532); this port
                      renders it as a plain pre.code — pulling in a highlighter
                      dependency for one card isn't worth it, at the cost of
                      losing token colors on the decompiled C. */}
                  {fn.pseudocode ? <pre className="code">{fn.pseudocode}</pre> : null}
                </div>
              ))}
            </div>
          </>
        ) : (
          <p className="empty">No functions were recovered. For a packed or corrupt binary this is itself the finding.</p>
        )}
      </div>
    </>
  )
}

function DataPanel({ g }: { g: GhidraDoc }) {
  return (
    <>
      <SectionHeading title="What the code references" sub="The string table, which is where hostnames, paths, and commands usually surface." />
      <div className="card wide">
        <h2>Strings</h2>
        {g.strings?.length ? (
          <>
            <p className="note">
              {g.strings.length} extracted string{g.strings.length === 1 ? '' : 's'}. Strings come from the sample and are
              untrusted input: they are rendered as text and never as markup.
            </p>
            <div className="card__scroll" aria-label="Full string table">
              <pre className="code">{g.strings.join('\n')}</pre>
            </div>
          </>
        ) : (
          <p className="empty">No strings were extracted.</p>
        )}
      </div>
    </>
  )
}

// ghidra.html:181's card, restored by #1735. Its three "nothing to show"
// states are kept apart deliberately: telling "no sandbox run exists" from
// "a run exists but floss declined the sample" from "both ran and agree on
// nothing" is most of the card's diagnostic value, and collapsing them into
// one empty message would throw that away.
function IocEvidence({ kind }: { kind: IocKind | undefined }) {
  const block = (label: string, values: string[] | undefined) => (
    <>
      <p className="note">{label}:</p>
      <pre className="code">{(values ?? []).join('\n')}</pre>
    </>
  )
  return (
    <>
      {block('floss-only', kind?.floss_only)}
      {block('sandbox-static-only', kind?.sandbox_static_only)}
      {block('confirmed at runtime', kind?.confirmed_at_runtime)}
    </>
  )
}

function IocCorrelationCard({ correlation }: { correlation: IocCorrelation | null }) {
  const rows: Array<{ label: string; kind: IocKind | undefined; dynamic: boolean }> = [
    { label: 'IP addresses', kind: correlation?.ips, dynamic: true },
    { label: 'Domains', kind: correlation?.domains, dynamic: true },
    { label: 'URLs', kind: correlation?.urls, dynamic: true },
    { label: 'UNC/SMB paths', kind: correlation?.unc_paths, dynamic: false },
  ]
  const count = (values: string[] | undefined) => (values ?? []).length
  return (
    <div className="card wide">
      <h2>Floss / Windows-sandbox IOC correlation</h2>
      {!correlation?.has_sandbox_run ? (
        <p className="empty">
          No Windows-sandbox run exists yet for this SHA-256 — nothing to correlate floss&apos;s decoded strings against.
        </p>
      ) : !correlation.has_floss_data ? (
        <p className="empty">
          A Windows-sandbox run exists for this sample, but floss declined it or the sidecar was unavailable for this
          analysis — see Obfuscated strings above.
        </p>
      ) : correlation.is_empty ? (
        <p className="empty">
          A Windows-sandbox run exists for this sample, but floss&apos;s decoded strings and the sandbox&apos;s own IOC sets
          share nothing in common.
        </p>
      ) : (
        <>
          <p className="note">
            Cross-references floss&apos;s decoded/static/stack/tight strings against this sample&apos;s Windows-sandbox
            run(s), by the same IP/URL/domain/UNC patterns <code>extract_iocs.py</code> uses. &ldquo;Confirmed at
            runtime&rdquo; is the strongest signal here: a value floss decoded from the binary that a sandbox run also
            actually observed happening.
          </p>
          <div className="card__scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>kind</th>
                  <th>floss-only</th>
                  <th>sandbox-static-only</th>
                  <th>confirmed at runtime</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.label}>
                    <td>{row.label}</td>
                    <td className="v">{count(row.kind?.floss_only)}</td>
                    <td className="v">{count(row.kind?.sandbox_static_only)}</td>
                    <td className={count(row.kind?.confirmed_at_runtime) > 0 ? 'v text-secondary' : 'v'}>
                      {row.dynamic ? count(row.kind?.confirmed_at_runtime) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="note">
            UNC/SMB paths have no dynamic counterpart — the sandbox&apos;s own parsers have no SMB/UNC observation path,
            only the static binary scan does.
          </p>
          <div className="card__scroll" aria-label="Full IOC correlation lists">
            {rows.map((row) => (
              <div key={row.label}>
                <h3>{row.label}</h3>
                <IocEvidence kind={row.kind} />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function DeepDivePanel({ g, correlation }: { g: GhidraDoc; correlation: IocCorrelation | null }) {
  const chat = g.revdeck_chat_threads
  const recovery = g.revdeck_recovery
  return (
    <>
      <SectionHeading
        title="Deep dive"
        sub="Everything the Ghidra REST v1 surface recovered beyond the functions/imports/strings above: recovered types, non-string globals, any analyst annotations, and the program's memory layout."
      />
      <IocCorrelationCard correlation={correlation} />
      <div className="card wide">
        <h2>Recovered types</h2>
        {g.types?.length ? (
          <>
            <p className="note">{g.types.length} struct/union/enum/typedef recovered from the program's own type database.</p>
            <div className="card__scroll" aria-label="Full type list">
              <pre className="code">
                {g.types
                  .map((type) =>
                    [
                      `${type.name}  [${type.kind}]  size=${type.size}`,
                      ...(type.fields ?? []).map((field) => `    ${field.name} : ${field.type}  offset=${field.offset} size=${field.size}`),
                      ...(type.base_type ? [`    base: ${type.base_type}`] : []),
                    ].join('\n'),
                  )
                  .join('\n')}
              </pre>
            </div>
          </>
        ) : (
          <p className="empty">
            No types were recovered — either the sample has no debug/type info Ghidra could reconstruct, or this analysis predates
            the deep-dive worker (#1167).
          </p>
        )}
      </div>
      <div className="card wide">
        <h2>Globals</h2>
        {g.globals?.length ? (
          <>
            <p className="note">
              {g.globals.length} non-string global data symbol{g.globals.length === 1 ? '' : 's'}. Distinct from the string table —
              these are named/typed data locations, not text.
            </p>
            <div className="card__scroll" aria-label="Full globals list">
              <pre className="code">{g.globals.map((global) => `${global.addr}  ${global.name}  ${global.type}  size=${global.size}`).join('\n')}</pre>
            </div>
          </>
        ) : (
          <p className="empty">No globals were recovered.</p>
        )}
      </div>
      <div className="card wide">
        <h2>Annotations</h2>
        {g.annotations ? (
          Object.keys(g.annotations.entries ?? {}).length ? (
            <>
              <p className="note">
                {Object.keys(g.annotations.entries ?? {}).length} analyst-authored annotation
                {Object.keys(g.annotations.entries ?? {}).length === 1 ? '' : 's'} (revision {g.annotations.revision}), written
                through the analysis workbench and mirrored here read-only.
              </p>
              <div className="card__scroll" aria-label="Full annotation list">
                <pre className="code">
                  {Object.entries(g.annotations.entries ?? {})
                    .map(([addr, entry]) =>
                      [
                        `${addr}  ${entry.display_name || '(no display name)'}`,
                        ...(entry.comment ? [`    ${entry.comment}`] : []),
                        ...(entry.tags?.length ? [`    tags: ${entry.tags.join(' ')}`] : []),
                      ].join('\n'),
                    )
                    .join('\n')}
                </pre>
              </div>
            </>
          ) : (
            <p className="empty">No annotations have been added for this analysis yet.</p>
          )
        ) : (
          <p className="empty">
            No annotation data was mirrored for this analysis — either it predates the deep-dive worker (#1167), or the annotation
            store was unreachable when it ran.
          </p>
        )}
      </div>
      <div className="card wide">
        <h2>Memory map</h2>
        {g.memory_map?.length ? (
          <>
            <p className="note">
              {g.memory_map.length} initialized memory block{g.memory_map.length === 1 ? '' : 's'}, each with a bounded preview of
              its opening bytes.
            </p>
            <div className="card__scroll" aria-label="Memory map">
              <pre className="code">
                {g.memory_map
                  .map((block) =>
                    [
                      `${block.start}-${block.end}  ${block.name}  size=${block.size}`,
                      ...(block.hexdump_preview ? [`    ${block.hexdump_preview.hex}`, `    ${block.hexdump_preview.ascii}`] : []),
                    ].join('\n'),
                  )
                  .join('\n')}
              </pre>
            </div>
          </>
        ) : (
          <p className="empty">
            No memory map was recovered — either this analysis predates the deep-dive worker (#1167), or the sample had no
            initialized memory blocks within the export budget.
          </p>
        )}
      </div>
      <div className="card wide">
        <h2>Chat threads</h2>
        {chat ? (
          <>
            <p className="note">
              {chat.threads?.length ?? 0} thread{(chat.threads?.length ?? 0) === 1 ? '' : 's'},{' '}
              {chat.active_thread_messages?.length ?? 0} message{(chat.active_thread_messages?.length ?? 0) === 1 ? '' : 's'}{' '}
              mirrored from the currently-active thread — the analyst's actual back-and-forth with the RevDeck assistant, distinct
              from the one-shot triage answer above.
            </p>
            <div className="card__scroll" aria-label="Chat history">
              <h3>Threads</h3>
              <pre className="code">
                {(chat.threads ?? [])
                  .map((thread) => `${thread.thread_id}  ${thread.title}  (${thread.message_count} message${thread.message_count === 1 ? '' : 's'})`)
                  .join('\n')}
              </pre>
              <div className="hp-chat">
                {(chat.active_thread_messages ?? []).map((message, index) => (
                  <div key={index} className={`hp-chat-msg hp-chat-msg--${message.role}`}>
                    <div className="hp-chat-msg__meta">
                      <span className="hp-chat-msg__role">{message.role}</span>
                      {message.name ? <span className="hp-chat-msg__name">{message.name}</span> : null}
                    </div>
                    {message.content != null ? (
                      <div className="hp-chat-msg__content" style={{ whiteSpace: 'pre-wrap' }}>
                        {rawText(message.content)}
                      </div>
                    ) : null}
                    {message.tool_calls != null ? (
                      <>
                        <p className="note">Tool calls</p>
                        <pre className="code">{rawText(message.tool_calls)}</pre>
                      </>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          </>
        ) : (
          <p className="empty">
            No chat threads were mirrored for this analysis — either it predates the chat-mirroring worker (#1193), the triage chat
            itself never completed, or no analyst has opened a chat session for this job yet.
          </p>
        )}
      </div>
      <div className="card wide">
        <h2>Symbol recovery</h2>
        {recovery ? (
          <>
            <p className="note">
              RevDeck's own symbol/type-recovery model for this job — recovered function names, renamed symbols, and
              class/type-layout candidates, distinct from the Ghidra-native types/globals above.
            </p>
            <div className="card__scroll" aria-label="Symbol recovery data">
              <pre className="code">{`--- index ---\n${rawText(recovery.index)}\n\n--- symbols ---\n${rawText(recovery.symbols)}`}</pre>
            </div>
          </>
        ) : (
          <p className="empty">
            No recovery-pipeline data was mirrored for this analysis — either it predates the recovery-mirroring worker (#1193), or
            the triage chat itself never completed.
          </p>
        )}
      </div>
    </>
  )
}

function GhidraDetail() {
  const { first } = Route.useLoaderData()
  const { sha } = Route.useParams()
  const resolved = useResolved(first)
  const run: Run | null | 'missing' = resolved === undefined ? null : resolved ?? 'missing'
  const [tab, setTab] = useState('overview')
  const [queued, setQueued] = useState(false)

  if (run === 'missing') {
    return <InvestigateHeader label="Evidence" title={sha.slice(0, 24)} subtitle="No Ghidra analysis found for this hash." />
  }
  const doc = run === null ? null : run
  const g: GhidraDoc = doc ? ((doc.ghidra ?? {}) as GhidraDoc) : {}
  const failed = doc !== null && g.exit_status === 'error'
  const correlation = (doc?.ioc_correlation as IocCorrelation | undefined) ?? null

  // ghidra.html:95's Re-analyze confirm — same data-hp-confirm-* copy.
  const reanalyze = () =>
    confirmAction({
      title: 'Re-run Ghidra analysis?',
      description:
        'This queues a fresh headless decompilation of the same capture. Nothing is executed; the existing result is replaced when the new run completes.',
      warning: 'The existing analysis for this payload is replaced when the new run finishes. Nothing is executed.',
      confirmLabel: 'Queue re-analysis',
      onConfirm: async () => {
        const result = await submitReanalysis({ data: { hash: sha } })
        if (!result.ok) throw new Error(result.error || 'Ghidra submission failed.')
        setQueued(true)
        return 'Re-analysis queued. The refreshed result replaces this one once the host worker finishes.'
      },
    })

  return (
    <>
      <InvestigateHeader
        label="Static analysis"
        title={`Ghidra — ${sha.slice(0, 24)}…`}
        subtitle="Headless decompilation of one captured payload. Nothing here is executed."
        chips={
          doc ? (
            <>
              <span className={failed ? 'badge badge--danger' : 'badge badge--muted'}>exit {g.exit_status || 'n/a'}</span>
              <Link className="chip" to="/payload-workbench/results" search={{ hash: sha }} hash="workbench-builder">
                unified analysis workbench →
              </Link>
              <Link className="chip" to="/payload-analysis/$hash" params={{ hash: sha }}>
                static analysis
              </Link>
              <Link className="chip" to="/events" search={{ shasum: sha }}>
                related events
              </Link>
              <a
                className="chip"
                href={`https://www.virustotal.com/gui/file/${encodeURIComponent(sha)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                VirusTotal ↗
              </a>
              <Link className="chip" to="/payload-workbench/results" hash="ghidra">
                ← all Ghidra results
              </Link>
              <button className="btn btn-sm btn-secondary" type="button" onClick={reanalyze} title="Queue a fresh Ghidra analysis of this capture">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <polyline points="23 4 23 10 17 10" />
                  <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
                </svg>{' '}
                Re-analyze
              </button>
            </>
          ) : undefined
        }
      />

      {doc === null ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : (
        <>
          {queued ? (
            <div className="alert alert--success" role="status">
              Re-analysis queued. The refreshed result replaces this one once the host worker finishes.
            </div>
          ) : null}
          {failed ? (
            <div className="alert alert--danger" role="alert">
              <strong>This analysis did not complete.</strong> {g.error || 'The worker reported a failure with no detail.'} The
              empty sections below are an infrastructure failure, not a clean result for this binary.
            </div>
          ) : null}

          <div className="metric-grid" id="ghidra-detail-stats">
            <div className="metric">
              <div className="metric__value">{g.functions?.length ?? 0}</div>
              <div className="metric__label">Functions</div>
            </div>
            <div className="metric">
              <div className="metric__value">{g.imports?.length ?? 0}</div>
              <div className="metric__label">Imports</div>
            </div>
            <div className="metric">
              <div className="metric__value">{g.strings?.length ?? 0}</div>
              <div className="metric__label">Strings</div>
            </div>
            <div className="metric">
              <div className={`metric__value${g.findcrypt?.length ? ' text-secondary' : ''}`}>{g.findcrypt?.length ?? 0}</div>
              <div className="metric__label">Crypto constants</div>
            </div>
          </div>

          <PageTabs
            tabs={[
              { id: 'overview', label: 'Overview' },
              { id: 'code', label: 'Code' },
              { id: 'data', label: 'Data' },
              { id: 'deepdive', label: 'Deep dive' },
              { id: 'raw', label: 'Raw' },
            ]}
            active={tab}
            onSelect={setTab}
            label="Ghidra analysis sections"
          />

          <Panel id="overview" active={tab}>
            <OverviewPanel sha={sha} g={g} />
          </Panel>
          <Panel id="code" active={tab}>
            <CodePanel sha={sha} g={g} />
          </Panel>
          <Panel id="data" active={tab}>
            <DataPanel g={g} />
          </Panel>
          <Panel id="deepdive" active={tab}>
            <DeepDivePanel g={g} correlation={correlation} />
          </Panel>
          <Panel id="raw" active={tab}>
            <div className="card wide">
              <h2>Report artifacts</h2>
              <ArtifactList kind="ghidra" artifactKey={sha} />
            </div>
            <div className="card wide">
              <h2>Analysis record</h2>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(doc, null, 2)}</pre>
              </div>
            </div>
          </Panel>
        </>
      )}
    </>
  )
}
