// Sandbox detonation detail — one job's structured behavior report,
// restored to the Go dashboard's layout (#1653; ui/sandbox.html:99-259):
// KPI tiles, Verdict/Behavior/Network/File forensics/Diagnostics tabs,
// inline evidence blocks, and the confirmed re-analyze action. The raw ES
// document stays on a Raw tab so nothing the old JSON dump exposed is
// lost. Submission of new jobs lands with #1612's mounted worker role.
// Live read-only VNC viewing of a currently-running Windows-sandbox
// detonation (SANDBOX_VNC_BRIDGE_WS) is a separate page, not this one —
// see sandbox.vnc.tsx.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { ArtifactList } from '../components/ArtifactList'
import { confirmAction } from '../components/ConfirmDialog'
import { InvestigateHeader } from '../components/Investigate'
import { useResolved } from '../lib/hooks'
import type { Json, JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'

type Run = JsonRecord

const fetchRun = createServerFn({ method: 'GET' })
  .inputValidator((input: { job: string }) => input)
  .handler(async ({ data }): Promise<Run | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Run>(`/api/v1/sandbox/${encodeURIComponent(data.job)}`)
  })

// Re-analysis queues a request marker via sandbox_submit.rs, identical to
// payload-analysis.$hash.tsx's submitSandbox — admin-gated at the BFF, the
// Rust tier's own trust boundary being the service token.
const resubmitSandbox = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      '/api/v1/sandbox/submit',
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hash: data.hash }) },
      { mounted: true },
    )
    const body = (await response.json().catch(() => null)) as { queued?: boolean; error?: string } | null
    if (response.ok && body?.queued) return { ok: true }
    return { ok: false, error: body?.error || 'Sandbox re-submission failed.' }
  })

export const Route = createFileRoute('/sandbox/$job')({
  loader: async ({ params }) => ({ first: fetchRun({ data: { job: params.job } }) }),
  component: SandboxDetail,
})

// ── JSON accessors over the raw ES doc ────────────────────────────────
const rec = (value: Json | undefined): JsonRecord => (value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {})
const str = (value: Json | undefined): string => (typeof value === 'string' ? value : typeof value === 'number' ? String(value) : '')
const num = (value: Json | undefined): number => (typeof value === 'number' ? value : 0)
const flag = (value: Json | undefined): boolean => value === true
const lines = (value: Json | undefined): string[] =>
  Array.isArray(value) ? value.map((entry) => (typeof entry === 'string' ? entry : typeof entry === 'number' ? String(entry) : '')) : []
const recList = (value: Json | undefined): JsonRecord[] => (Array.isArray(value) ? value.map((entry) => rec(entry)) : [])
const countMap = (value: Json | undefined): [string, number][] =>
  Object.entries(rec(value)).map(([name, count]) => [name, num(count)] as [string, number])

// ── Derivations ported from sandbox.go's normalizeSandboxResult ───────
type Diff = { added: string[]; removed: string[] }

// sandbox.go's normalizeSandboxLine: collapse whitespace runs.
const normalizeLine = (line: string) => line.split(/\s+/).filter(Boolean).join(' ')

// sandbox.go's normalizeSandboxProcess: keep user + command from a ps
// line, dropping the header, volatile PID/resource columns and kernel
// workers ([bracketed] commands).
function normalizeProcess(line: string): string {
  const fields = line.split(/\s+/).filter(Boolean)
  if (fields.length < 11 || (fields[0] === 'USER' && fields[1] === 'PID')) return ''
  const command = fields.slice(10).join(' ')
  if (command.startsWith('[') && command.endsWith(']')) return ''
  return `${fields[0]} ${command}`
}

function lineDifference(before: string[], after: string[], normalize: (line: string) => string): Diff {
  const beforeSet = new Set(before.map(normalize).filter(Boolean))
  const afterSet = new Set(after.map(normalize).filter(Boolean))
  return {
    added: [...afterSet].filter((entry) => !beforeSet.has(entry)).sort(),
    removed: [...beforeSet].filter((entry) => !afterSet.has(entry)).sort(),
  }
}

// ── Small presentational helpers ──────────────────────────────────────
function Row({ label, value, mono = true, danger = false }: { label: string; value: React.ReactNode; mono?: boolean; danger?: boolean }) {
  return (
    <div className="card__row">
      <span className="card__label">{label}</span>
      <span className={`card__value${mono ? ' card__value--mono' : ''}${danger ? ' text-danger' : ''}`}>{value}</span>
    </div>
  )
}

// Inline evidence viewer — the port of sandbox.html's data-hp-evidence
// buttons + "Complete evidence" section (hp-evidence.js): each long log or
// list renders on demand inside a bounded card__scroll, no modal.
function Evidence({ title, note, body }: { title: string; note?: string; body: string }) {
  if (!body.trim()) return null
  return (
    <details className="hp-flow">
      <summary>{title}</summary>
      {note ? <p className="note hp-flow">{note}</p> : null}
      <div className="card__scroll">
        <pre className="code">{body}</pre>
      </div>
    </details>
  )
}

function DiffDetails({ diff, emptyAdded, emptyRemoved }: { diff: Diff; emptyAdded: string; emptyRemoved: string }) {
  return (
    <>
      {diff.added.length ? (
        <details open>
          <summary>Added ({diff.added.length})</summary>
          <pre className="code hp-flow">{diff.added.map((entry) => `+ ${entry}`).join('\n')}</pre>
        </details>
      ) : (
        <p className="empty">{emptyAdded}</p>
      )}
      {diff.removed.length ? (
        <details open className="hp-flow">
          <summary>Removed ({diff.removed.length})</summary>
          <pre className="code hp-flow">{diff.removed.map((entry) => `- ${entry}`).join('\n')}</pre>
        </details>
      ) : (
        <p className="empty">{emptyRemoved}</p>
      )}
    </>
  )
}

// Page-level numbered tab strip — theme.css's .tabs/.tab vocabulary
// (sandbox.html:26-32), same inlined roving-tabindex pattern as
// payload-analysis.$hash.tsx's PageTabs (the shared Tabs component speaks
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
    document.getElementById(`sb-tab-${tabs[target].id}`)?.focus()
  }
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((tab, index) => (
        <button
          key={tab.id}
          id={`sb-tab-${tab.id}`}
          className={tab.id === active ? 'tab active' : 'tab'}
          type="button"
          role="tab"
          aria-selected={tab.id === active}
          aria-controls={`sb-panel-${tab.id}`}
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
      id={`sb-panel-${id}`}
      role="tabpanel"
      aria-labelledby={`sb-tab-${id}`}
      hidden={id !== active}
    >
      {children}
    </div>
  )
}

function SandboxDetail() {
  const { first } = Route.useLoaderData()
  const { job } = Route.useParams()
  const resolved = useResolved(first)
  const [tab, setTab] = useState('verdict')
  const run: Run | null | 'missing' = resolved === undefined ? null : resolved ?? 'missing'

  if (run === 'missing') {
    return <InvestigateHeader label="Evidence" title={job} subtitle="No sandbox run found for this job id." />
  }
  const doc = run === null ? null : run
  // es_importer.rs's build_document nests the result file under "sandbox";
  // legacy documents kept the payload at top level (detail.rs's query
  // matches both `sandbox.job` and `job`).
  const detail = doc === null ? null : Object.keys(rec(doc.sandbox)).length ? rec(doc.sandbox) : doc

  // sandbox.go normalizeSandboxResult: derive incompleteness, default the
  // run status/failure reason, and zero the risk rating for a broken run.
  const timeoutReason = str(detail?.timeout_reason)
  const exitStatusRaw = str(detail?.exit_status)
  const incomplete =
    detail !== null &&
    (str(detail.run_status) === 'failed' ||
      timeoutReason !== '' ||
      exitStatusRaw === 'unknown' ||
      exitStatusRaw === 'guest-no-result' ||
      exitStatusRaw === 'host-timeout')
  const runStatus = str(detail?.run_status) || (incomplete ? 'failed' : 'completed')
  const failureReason =
    str(detail?.failure_reason) ||
    (timeoutReason === 'host deadline' ? 'The virtual machine did not reach the guest analysis service before the host deadline.' : '')
  const exitStatus = incomplete && exitStatusRaw === 'unknown' && timeoutReason === 'host deadline' ? 'host-timeout' : exitStatusRaw
  const riskScore = incomplete ? 0 : num(detail?.risk_score)
  const riskLevel = incomplete ? 'unrated' : str(detail?.risk_level)

  const classification = rec(detail?.classification)
  const hashes = rec(detail?.hashes)
  const network = rec(detail?.network_summary)
  const iocs = rec(detail?.iocs)
  const windows = rec(detail?.windows_forensics)
  const artifacts = rec(detail?.artifacts)
  const techniques = recList(detail?.techniques)
  const topSyscalls = recList(detail?.top_syscalls)
  const changedFiles = lines(detail?.changed_files)
  const sha256 = str(detail?.sha256) || str(rec(rec(doc?.file).hash).sha256)
  const route = str(detail?.route) || (str(detail?.platform) === 'Windows' ? 'windows' : 'linux')
  const windowsDetected = flag(windows.detected)

  const processDiff = lineDifference(lines(artifacts.processes_before), lines(artifacts.processes_after), normalizeProcess)
  const socketDiff = lineDifference(lines(detail?.sockets_before), lines(detail?.sockets_after), normalizeLine)

  const tabs = [
    { id: 'verdict', label: 'Verdict' },
    { id: 'behavior', label: 'Behavior' },
    { id: 'network', label: 'Network' },
    ...(windowsDetected ? [{ id: 'file', label: 'File forensics' }] : []),
    { id: 'diagnostics', label: 'Diagnostics' },
    { id: 'raw', label: 'Raw' },
  ]

  const reanalyze = () =>
    confirmAction({
      title: 'Detonate this payload again?',
      description:
        'This queues a fresh isolated run of the same capture. The existing result stays on file; the new run appears as a separate job.',
      confirmLabel: 'Queue re-analysis',
      onConfirm: async () => {
        const result = await resubmitSandbox({ data: { hash: sha256 } })
        if (!result.ok) throw new Error(result.error || 'Sandbox re-submission failed.')
        return 'Re-analysis queued. The new run appears in the sandbox queue once the host watcher picks it up.'
      },
    })

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title={`Sandbox — ${job.slice(0, 40)}`}
        subtitle="One detonation's full behavior record: verdict, platform, and every exported artifact."
        chips={
          detail ? (
            <>
              <span
                className={
                  riskLevel === 'high' || riskLevel === 'critical'
                    ? 'badge badge--danger'
                    : riskLevel === 'medium'
                      ? 'badge badge--warning'
                      : 'badge badge--muted'
                }
              >
                {riskLevel || 'n/a'} {incomplete ? '' : riskScore}
              </span>
              <span className="badge badge--muted">{str(detail.platform)}</span>
              <span className="chip">exit {exitStatus}</span>
            </>
          ) : undefined
        }
      />
      {detail === null ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : (
        <>
          <div className="filters">
            <Link className="chip" to="/payload-workbench/results">← all sandbox results</Link>
            {sha256 ? (
              <>
                <Link className="chip" to="/payload-analysis/$hash" params={{ hash: sha256 }}>static analysis</Link>
                <Link className="chip" to="/events" search={{ shasum: sha256 }}>related events</Link>
                <a className="chip" href={`https://www.virustotal.com/gui/file/${sha256}`} target="_blank" rel="noopener noreferrer">
                  VirusTotal ↗
                </a>
                <button className="btn btn-sm btn-danger" type="button" title="Queue a fresh sandbox run of this capture" onClick={reanalyze}>
                  Re-analyze
                </button>
              </>
            ) : null}
          </div>

          {incomplete ? (
            <div className="alert alert--danger" role="alert">
              <strong>Analysis did not run to completion.</strong> {failureReason || 'The guest returned no usable analysis artifacts.'} The
              empty evidence sections below are an infrastructure failure, not a clean payload result. Re-submit only after the sandbox
              health check passes.
            </div>
          ) : null}

          <div className="metric-grid">
            <div className="metric">
              <div className="metric__value text-danger">{incomplete ? 'not rated' : `${riskScore} / 100 • ${riskLevel}`}</div>
              <div className="metric__label">Dynamic risk</div>
            </div>
            <div className="metric">
              <div className="metric__value">{num(detail.duration_seconds)} seconds</div>
              <div className="metric__label">Duration</div>
            </div>
            <div className="metric">
              <div className="metric__value">{num(network.packets)}</div>
              <div className="metric__label">Captured packets</div>
            </div>
            <div className="metric">
              <div className="metric__value">{changedFiles.length}</div>
              <div className="metric__label">Changed paths</div>
            </div>
          </div>

          <PageTabs tabs={tabs} active={tab} onSelect={setTab} label="Sandbox run views" />

          <Panel id="verdict" active={tab}>
            <div className="section-heading">
              <div>
                <h2>What this run concluded</h2>
                <p>The identified payload, how static indicators compare with observed behavior, and the techniques the run demonstrated.</p>
              </div>
            </div>
            <div className="card wide">
              <h2>Run identity and analysis route</h2>
              <Row label="job" value={str(detail.job)} />
              <Row
                label="identified payload"
                mono={false}
                value={
                  <>
                    <strong>{str(classification.label)}</strong>{' '}
                    {str(classification.code) ? <span className="badge badge--muted">{str(classification.code)}</span> : null}
                  </>
                }
              />
              <Row label="platform / category" value={`${str(classification.platform)} / ${str(classification.category)}`} />
              <Row label="selected analysis path" value={str(detail.analysis_path) || str(classification.analysis_path)} />
              <Row label="execution mode" value={str(detail.execution_mode)} />
              <Row label="file(1) result" mono={false} value={str(detail.file_type)} />
              <Row label="capture source" value={`${str(detail.source)} / ${str(detail.capture_name)}`} />
              <Row label="SHA-256" value={sha256} />
              <Row label="SHA-1" value={str(hashes.sha1)} />
              <Row label="MD5" value={str(hashes.md5)} />
              <Row label="requested" value={formatTimestamp(str(detail.requested_at))} />
              <Row label="started" value={formatTimestamp(str(detail.started_at))} />
              <Row label="completed" value={formatTimestamp(str(detail.completed_at))} />
              <Row label="exit status" value={exitStatus} />
              {timeoutReason ? <Row label="timeout" mono={false} danger value={timeoutReason} /> : null}
              <Row
                label="isolation"
                mono={false}
                value={
                  route === 'windows-ghosts' ? (
                    <>
                      <span className="badge badge--warning">WAN-permitted</span> fresh transient KVM guest, disposable overlay — real
                      internet egress, LAN/RFC1918 blocked by host firewall policy, not air-gapped
                    </>
                  ) : (
                    'fresh transient KVM guest, disposable overlay, no forwarding, strict libvirt NIC filter'
                  )
                }
              />
            </div>
            <div className="card half">
              <h2>Static versus dynamic</h2>
              <Row label="dynamic ATT&CK behaviors" value={techniques.length} />
              <Row label="system calls recorded" value={topSyscalls.length} />
              <Row label="filesystem changes" value={changedFiles.length} />
              <Row label="network packets" value={num(network.packets)} />
              <p className="note">Static indicators show what the file contains; dynamic evidence shows what this bounded run actually attempted.</p>
            </div>
            <div className="card half">
              <h2>ATT&CK behavior mapping</h2>
              {techniques.length ? (
                <div className="card__scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>technique</th>
                        <th>evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {techniques.map((technique, index) => (
                        <tr key={`${str(technique.id)}-${index}`}>
                          <td>
                            <a href={`https://attack.mitre.org/techniques/${encodeURIComponent(str(technique.id))}/`} target="_blank" rel="noopener noreferrer">
                              {str(technique.id)} {str(technique.name)}
                            </a>
                          </td>
                          <td className="v">{str(technique.evidence)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="empty">No mapped behavior in this run.</p>
              )}
              <p className="note">Behavior context only; never actor attribution.</p>
            </div>
          </Panel>

          <Panel id="behavior" active={tab}>
            <div className="section-heading">
              <div>
                <h2>What the payload did</h2>
                <p>System calls, filesystem changes, and the process and socket state before and after detonation.</p>
              </div>
            </div>
            <div className="card half">
              <h2>Top system calls</h2>
              {topSyscalls.length ? (
                <div className="card__scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>call</th>
                        <th>count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topSyscalls.map((syscall, index) => (
                        <tr key={`${str(syscall.name)}-${index}`}>
                          <td className="v">{str(syscall.name)}</td>
                          <td className="n">{num(syscall.count)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="empty">No syscall trace was exported.</p>
              )}
            </div>
            <div className="card half">
              <h2>Created or changed paths</h2>
              {changedFiles.length ? (
                <>
                  <p className="note">
                    {changedFiles.length} tracked path{changedFiles.length === 1 ? '' : 's'} changed.
                  </p>
                  <Evidence
                    title="Open the full list"
                    note="Filesystem paths the run created or modified inside the disposable guest."
                    body={changedFiles.join('\n')}
                  />
                </>
              ) : (
                <p className="empty">No tracked path changes.</p>
              )}
            </div>
            <div className="card half">
              <h2>Process difference</h2>
              <p className="note">
                Userspace commands added or removed between the pre- and post-execution snapshots. Volatile PID/resource columns and
                kernel-worker churn are ignored.
              </p>
              <DiffDetails diff={processDiff} emptyAdded="No added processes." emptyRemoved="No removed processes." />
            </div>
            <div className="card half">
              <h2>Sockets difference</h2>
              <p className="note">Socket rows added or removed between the pre- and post-execution snapshots.</p>
              <DiffDetails diff={socketDiff} emptyAdded="No added sockets." emptyRemoved="No removed sockets." />
              <Evidence title="Sockets before detonation" body={lines(detail.sockets_before).join('\n')} />
              <Evidence title="Sockets after detonation" body={lines(detail.sockets_after).join('\n')} />
            </div>
            <div className="card wide">
              <h2>Process output</h2>
              <p className="note">
                Everything the payload wrote to its standard streams inside the guest. Guest-produced text is untrusted and size-bounded.
              </p>
              <Evidence title="Standard output" body={str(detail.stdout)} />
              <Evidence title="Standard error" body={str(detail.stderr)} />
              {!str(detail.stdout).trim() && !str(detail.stderr).trim() ? <p className="empty">No stream output was captured.</p> : null}
            </div>
          </Panel>

          <Panel id="network" active={tab}>
            <div className="section-heading">
              <div>
                <h2>What it reached for</h2>
                <p>Captured traffic on the host bridge and inside the guest, including loopback DNS.</p>
              </div>
            </div>
            <div className="card wide">
              <h2>Network and DNS capture</h2>
              <div className="card__scroll">
                <Row label="host bridge packets" value={num(network.packets)} />
                <Row label="host PCAP bytes" value={num(network.bytes)} />
                <Row label="guest packets, including loopback DNS" value={num(network.guest_packets)} />
                <Row label="guest PCAP bytes" value={num(network.guest_pcap_bytes)} />
                <Row label="unique DNS queries" value={lines(network.dns_queries).length} />
                {countMap(network.protocols).map(([name, count]) => (
                  <Row key={`host-${name}`} label={`host ${name}`} value={count} />
                ))}
                {countMap(network.guest_protocols).map(([name, count]) => (
                  <Row key={`guest-${name}`} label={`guest ${name}`} value={count} />
                ))}
              </div>
              <Evidence title={`Captured DNS names (${lines(network.dns_queries).length})`} body={lines(network.dns_queries).join('\n')} />
              <Evidence title={`DNS queries and responses (${lines(network.dns_events).length})`} body={lines(network.dns_events).join('\n')} />
              <p className="note">
                Raw captures are administrator-only and can be opened directly in Wireshark or tshark. PCAPs begin at guest boot and may
                include Ubuntu service traffic; captured presence alone does not prove payload attribution. Dynamic risk and ATT&CK
                network behavior require a matching syscall from the traced payload process tree. In controlled mode, DNS answers are real
                and logged while downloads must pass the allowlisted proxy; direct guest routing remains blocked.
              </p>
            </div>
            <div className="card half">
              <h2>Host bridge events</h2>
              {lines(network.events).length ? (
                <>
                  <p className="note">
                    {lines(network.events).length} decoded packet event{lines(network.events).length === 1 ? '' : 's'}.
                  </p>
                  <Evidence title="Open the packet log" body={lines(network.events).join('\n')} />
                </>
              ) : (
                <p className="empty">No packets were emitted during this run.</p>
              )}
              {lines(network.attempts).length ? (
                <>
                  <p className="note hp-flow">
                    {lines(network.attempts).length} IPv4/IPv6 connect attempt{lines(network.attempts).length === 1 ? '' : 's'} observed by
                    strace.
                  </p>
                  <Evidence title="Open connect attempts" body={lines(network.attempts).join('\n')} />
                </>
              ) : null}
            </div>
            <div className="card half">
              <h2>Guest and loopback packet events</h2>
              {lines(network.guest_events).length ? (
                <>
                  <p className="note">
                    {lines(network.guest_events).length} decoded guest-side event{lines(network.guest_events).length === 1 ? '' : 's'}.
                  </p>
                  <Evidence title="Open the guest packet log" body={lines(network.guest_events).join('\n')} />
                </>
              ) : (
                <p className="empty">No guest-side packets were decoded.</p>
              )}
            </div>
            <div className="card wide">
              <h2>IOCs: static versus dynamic</h2>
              <Row label="remote IPs observed at runtime" value={lines(network.remote_ips).length} />
              <Row label="download URLs observed at runtime" value={lines(iocs.download_urls).length} />
              <Row label="PowerShell download cradles" value={num(iocs.download_cradle_count)} />
              <Row label="remote IPs embedded in the binary" value={lines(iocs.static_remote_ips).length} />
              <Row label="UNC/SMB paths embedded in the binary" value={lines(iocs.static_unc_paths).length} />
              <Row label="binary IPs never observed at runtime (dormant)" value={lines(iocs.static_only_remote_ips).length} />
              <Row label="binary domains never observed at runtime (dormant)" value={lines(iocs.static_only_dns_domains).length} />
              <Evidence title={`Remote IPs (${lines(network.remote_ips).length})`} body={lines(network.remote_ips).join('\n')} />
              <Evidence title={`Download URLs (${lines(iocs.download_urls).length})`} body={lines(iocs.download_urls).join('\n')} />
              <Evidence title={`UNC/SMB paths (${lines(iocs.static_unc_paths).length})`} body={lines(iocs.static_unc_paths).join('\n')} />
              <Evidence title={`Dormant IPs (${lines(iocs.static_only_remote_ips).length})`} body={lines(iocs.static_only_remote_ips).join('\n')} />
              <Evidence
                title={`Dormant domains (${lines(iocs.static_only_dns_domains).length})`}
                body={lines(iocs.static_only_dns_domains).join('\n')}
              />
              <p className="note">
                Static IOCs come from a printable-string scan of the sample binary itself. "Dormant" entries are present in the sample but
                were never observed during this run's bounded observation window — a backup C2/exfil address, or a code path this run's
                trigger conditions never reached.
              </p>
            </div>
          </Panel>

          {windowsDetected ? (
            <Panel id="file" active={tab}>
              <div className="section-heading">
                <div>
                  <h2>What the file is</h2>
                  <p>Windows PE structure, imports, and signing, parsed inside the analysis guest.</p>
                </div>
              </div>
              <div className="card wide">
                <h2>Windows PE forensics</h2>
                <Row label="format / machine" value={`${str(windows.pe_type)} / ${str(windows.machine)}`} />
                <Row label="DLL" value={String(flag(windows.dll))} />
                <Row label="compile timestamp" value={str(windows.compile_timestamp)} />
                <Row label="entry point" value={num(windows.entry_point)} />
                <Row label="image base" value={num(windows.image_base)} />
                <Row label="subsystem" value={num(windows.subsystem)} />
                <Row label="import hash" value={str(windows.imphash)} />
                <Row label="embedded signature" value={String(flag(windows.signature_present))} />
                <p className="note">
                  Parsed with pefile inside the powered-off-after-use analysis guest. Wine execution is behavioral emulation, not a perfect
                  replacement for native Windows.
                </p>
              </div>
              <div className="card half">
                <h2>Suspicious Windows API imports</h2>
                {Object.keys(rec(windows.suspicious_imports)).length ? (
                  <div className="card__scroll">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>behavior</th>
                          <th>imports</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(rec(windows.suspicious_imports)).map(([group, names]) => (
                          <tr key={group}>
                            <td>{group}</td>
                            <td className="v">
                              {lines(names).map((name) => (
                                <span key={name} className="chip">
                                  {name}
                                </span>
                              ))}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="empty">No categorized high-signal imports found.</p>
                )}
              </div>
              <div className="card half">
                <h2>PE sections</h2>
                {recList(windows.sections).length ? (
                  <div className="card__scroll">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>name</th>
                          <th>virtual</th>
                          <th>raw</th>
                          <th>entropy</th>
                          <th>flags</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recList(windows.sections).map((section, index) => (
                          <tr key={`${str(section.name)}-${index}`}>
                            <td className="v">{str(section.name)}</td>
                            <td className="n">{num(section.virtual_size)}</td>
                            <td className="n">{num(section.raw_size)}</td>
                            <td className="n">{num(section.entropy)}</td>
                            <td className="v">{str(section.characteristics)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="empty">No PE sections parsed.</p>
                )}
              </div>
              <div className="card wide">
                <h2>Imported libraries and symbols</h2>
                {recList(windows.imports).length ? (
                  <div className="card__scroll">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>library</th>
                          <th>symbols</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recList(windows.imports).map((entry, index) => (
                          <tr key={`${str(entry.dll)}-${index}`}>
                            <td className="v">{str(entry.dll)}</td>
                            <td className="v">
                              {lines(entry.symbols).map((symbol) => (
                                <span key={symbol} className="chip">
                                  {symbol}
                                </span>
                              ))}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="empty">No imports parsed.</p>
                )}
              </div>
              <div className="card half">
                <h2>Exports, warnings, and metadata</h2>
                <p className="note">Parser output and the metadata tools run against the sample.</p>
                <Evidence title={`Exports (${lines(windows.exports).length})`} body={lines(windows.exports).join('\n')} />
                <Evidence title={`Warnings (${lines(windows.warnings).length})`} body={lines(windows.warnings).join('\n')} />
                <Evidence title="ExifTool" body={str(artifacts.exiftool)} />
                <Evidence title="objdump -x" body={str(artifacts.pe_objdump)} />
                {!lines(windows.exports).length && !lines(windows.warnings).length ? (
                  <p className="note hp-flow">No exported symbols or parser warnings.</p>
                ) : null}
              </div>
              <div className="card half">
                <h2>Signing and strings</h2>
                <p className="note">Authenticode result and the printable sequences extracted from the sample.</p>
                <Evidence title="Authenticode inspection" body={str(windows.authenticode)} />
                <Evidence
                  title={`ASCII strings (${lines(windows.ascii_strings).length})`}
                  note="Printable sequences extracted from the sample."
                  body={lines(windows.ascii_strings).join('\n')}
                />
                <Evidence
                  title={`UTF-16LE strings (${lines(windows.utf16_strings).length})`}
                  note="Wide-character sequences extracted from the sample."
                  body={lines(windows.utf16_strings).join('\n')}
                />
              </div>
            </Panel>
          ) : null}

          <Panel id="diagnostics" active={tab}>
            <div className="section-heading">
              <div>
                <h2>How the run itself went</h2>
                <p>Guest and collection state — read this when the evidence above looks thin, to tell an empty result from a broken one.</p>
              </div>
            </div>
            <div className="card wide">
              <h2>Runtime and collection diagnostics</h2>
              <Row label="run status" danger={incomplete} value={runStatus} />
              <Row label="guest service started" value={String(flag(detail.guest_started))} />
              <Row label="last host phase" value={str(artifacts.host_phase)} />
              <Row
                label="processes before / after"
                value={`${lines(artifacts.processes_before).length} / ${lines(artifacts.processes_after).length}`}
              />
              <p className="note hp-flow">Collected artifacts:</p>
              <Evidence title="Guest kernel" body={str(artifacts.kernel)} />
              <Evidence title={`Processes before (${lines(artifacts.processes_before).length})`} body={lines(artifacts.processes_before).join('\n')} />
              <Evidence title={`Processes after (${lines(artifacts.processes_after).length})`} body={lines(artifacts.processes_after).join('\n')} />
              <Evidence title="Host tcpdump log" body={str(artifacts.host_tcpdump_log)} />
              <Evidence title="Guest tcpdump log" body={str(artifacts.guest_tcpdump_log)} />
              <Evidence title="Classifier error" body={str(artifacts.classification_error)} />
              <Evidence title="PE parser error" body={str(artifacts.pe_forensics_error)} />
            </div>
            {incomplete ? (
              <div className="card wide">
                <h2>Sandbox infrastructure diagnostics</h2>
                <Row label="run status" danger value={runStatus} />
                <Row label="exit status" value={exitStatus} />
                <Row label="last host phase" value={str(artifacts.host_phase)} />
                <Row label="guest service started" value={String(flag(detail.guest_started))} />
                <Evidence title="Guest serial console" body={str(artifacts.console_log)} />
                <Evidence title="QEMU log" body={str(artifacts.qemu_log)} />
                <Evidence title="Domain state" body={`${str(artifacts.domain_state)}\n${str(artifacts.qemu_status)}`.trim()} />
              </div>
            ) : null}
          </Panel>

          <Panel id="raw" active={tab}>
            <div className="card wide">
              <h2>Behavior record</h2>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(doc, null, 2)}</pre>
              </div>
            </div>
          </Panel>

          <p className="note hp-flow">
            Guest-produced text is untrusted and size-bounded. Complete raw result directories and syscall traces remain root-only on the
            homeserver.
          </p>
        </>
      )}
      <div className="card wide">
        <h2>Exported artifacts</h2>
        <ArtifactList kind="sandbox" artifactKey={job} />
      </div>
    </>
  )
}
