package main

const pageSandbox = `
{{define "sandbox"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot &mdash; sandbox results</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="sandbox-header">
          <div>
            <div class="eyebrow">Dynamic analysis</div>
            <h1>Isolated Linux sandbox</h1>
            <p class="subtitle">Bounded summaries exported from disposable, network-isolated KVM guests.</p>
          </div>
          <div class="live-panel">
            <span class="gen">generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span>
          </div>
        </header>

        {{if .Detail}}
        <div class="filters" id="sandbox-detail-actions"><a class="chip" href="/sandbox">&larr; all sandbox results</a><a class="chip" href="/payload-analysis/{{.Detail.SHA256}}">static analysis</a><a class="chip" href="/events?shasum={{.Detail.SHA256}}">related events</a><a class="chip" href="https://www.virustotal.com/gui/file/{{.Detail.SHA256}}" target="_blank" rel="noopener noreferrer">VirusTotal &nearr;</a><a class="chip" href="/export/sandbox/{{.Detail.Job}}.json">sanitized JSON &darr;</a>{{if .Detail.HostPCAPURL}}<a class="chip" href="{{.Detail.HostPCAPURL}}" title="Raw host-bridge packet capture for Wireshark">host PCAP ({{.Detail.HostPCAPSize}} bytes) &darr;</a>{{end}}{{if .Detail.GuestPCAPURL}}<a class="chip" href="{{.Detail.GuestPCAPURL}}" title="Raw guest capture including loopback DNS for Wireshark">guest PCAP ({{.Detail.GuestPCAPSize}} bytes) &darr;</a>{{end}}{{if .Detail.DiagnosticsURL}}<a class="chip" href="{{.Detail.DiagnosticsURL}}" title="Bounded administrator evidence bundle">diagnostics ZIP ({{.Detail.DiagnosticsSize}} bytes) &darr;</a>{{end}}{{if .Detail.CaptureAvailable}}<form method="post" action="/sandbox/submit" data-hp-confirm-title="Detonate this payload again?" data-hp-confirm-description="This queues a fresh isolated run of the same capture. The existing result stays on file; the new run appears as a separate job." data-hp-confirm-label="Queue re-analysis"><input type="hidden" name="hash" value="{{.Detail.SHA256}}"><input type="hidden" name="return" value="/sandbox/{{.Detail.Job | urlquery}}"><button class="btn btn-sm btn-danger" type="submit" title="Queue a fresh sandbox run of this capture"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Re-analyze</button></form>{{end}}</div>
        {{if not .Detail.CaptureAvailable}}<p class="note">The original capture is no longer in a payload directory, so this run cannot be repeated from the dashboard.</p>{{end}}
        {{if eq .Analysis "queued"}}<div class="alert alert--success" role="status">Re-analysis queued. The new run appears in the sandbox queue below once the host watcher picks it up.</div>{{end}}
        {{if .Detail.Incomplete}}<div class="tw:mb-6 tw:rounded-lg tw:border tw:border-red tw:bg-red-subtle tw:px-4 tw:py-4 tw:text-red" role="alert"><strong>Analysis did not run to completion.</strong> {{if .Detail.FailureReason}}{{.Detail.FailureReason}}{{else}}The guest returned no usable analysis artifacts.{{end}} The empty evidence sections below are an infrastructure failure, not a clean payload result. Re-submit only after the sandbox health check passes.</div>{{end}}

        <div class="tw:grid tw:grid-cols-2 tw:sm:grid-cols-4 tw:gap-3 tw:mb-6" id="sandbox-detail-stats">
          <div class="hp-stat"><span class="hp-stat-value tw:text-red">{{if .Detail.Incomplete}}not rated{{else}}{{.Detail.RiskScore}} / 100 &bull; {{.Detail.RiskLevel}}{{end}}</span><span class="hp-stat-label">Dynamic risk</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.Detail.Duration}} seconds</span><span class="hp-stat-label">Duration</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.Detail.NetworkSummary.Packets}}</span><span class="hp-stat-label">Captured packets</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{len .Detail.ChangedFiles}}</span><span class="hp-stat-label">Changed paths</span></div>
        </div>

        <div class="dashboard-tabs" role="tablist" aria-label="Sandbox run views">
          <button class="dashboard-tab active" type="button" role="tab" aria-selected="true" aria-controls="panel-verdict" data-dashboard-tab="verdict"><span>01</span>Verdict</button>
          <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-behavior" data-dashboard-tab="behavior"><span>02</span>Behavior</button>
          <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-network" data-dashboard-tab="network"><span>03</span>Network</button>
          {{if .Detail.Windows.Detected}}<button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-file" data-dashboard-tab="file"><span>04</span>File forensics</button>{{end}}
          <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-diagnostics" data-dashboard-tab="diagnostics"><span>{{if .Detail.Windows.Detected}}05{{else}}04{{end}}</span>Diagnostics</button>
        </div>

        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-verdict" role="tabpanel" data-dashboard-panel="verdict">
          <div class="section-heading"><div><h2>What this run concluded</h2><p>The identified payload, how static indicators compare with observed behavior, and the techniques the run demonstrated.</p></div></div>
          <div class="card wide"><h2>Run identity and analysis route</h2><table><tbody><tr><td>job</td><td class="v">{{.Detail.Job}}</td></tr><tr><td>identified payload</td><td class="v"><strong>{{.Detail.Classification.Label}}</strong> {{if .Detail.Classification.Code}}<span class="badge badge--muted">{{.Detail.Classification.Code}}</span>{{end}}</td></tr><tr><td>platform / category</td><td class="v">{{.Detail.Classification.Platform}} / {{.Detail.Classification.Category}}</td></tr><tr><td>selected analysis path</td><td class="v">{{if .Detail.AnalysisPath}}{{.Detail.AnalysisPath}}{{else}}{{.Detail.Classification.AnalysisPath}}{{end}}</td></tr><tr><td>execution mode</td><td class="v">{{.Detail.ExecutionMode}}</td></tr><tr><td>file(1) result</td><td class="v">{{.Detail.FileType}}</td></tr><tr><td>capture source</td><td class="v">{{.Detail.Source}} / {{.Detail.CaptureName}}</td></tr><tr><td>MD5</td><td class="v">{{.Detail.Hashes.MD5}}</td></tr><tr><td>SHA-1</td><td class="v">{{.Detail.Hashes.SHA1}}</td></tr><tr><td>SHA-256</td><td class="v">{{.Detail.SHA256}}</td></tr><tr><td>requested</td><td class="v">{{.Detail.RequestedAt}}</td></tr><tr><td>started</td><td class="v">{{.Detail.StartedAt}}</td></tr><tr><td>completed</td><td class="v">{{.Detail.CompletedAt}}</td></tr><tr><td>exit status</td><td class="v">{{.Detail.ExitStatus}}</td></tr>{{if .Detail.TimeoutReason}}<tr><td>timeout</td><td class="v tw:text-red">{{.Detail.TimeoutReason}}</td></tr>{{end}}<tr><td>isolation</td><td class="v">fresh transient KVM guest, disposable overlay, no forwarding, strict libvirt NIC filter</td></tr></tbody></table></div>
          <div class="card half"><h2>Static versus dynamic</h2><table><tbody><tr><td>static YARA matches</td><td class="n">{{len .StaticYARA}}</td></tr><tr><td>dynamic ATT&amp;CK behaviors</td><td class="n">{{len .Detail.Techniques}}</td></tr><tr><td>system calls recorded</td><td class="n">{{len .Detail.TopSyscalls}}</td></tr><tr><td>filesystem changes</td><td class="n">{{len .Detail.ChangedFiles}}</td></tr><tr><td>network packets</td><td class="n">{{.Detail.NetworkSummary.Packets}}</td></tr></tbody></table>{{if .StaticYARA}}<p class="note">YARA: {{range .StaticYARA}}<span class="chip">{{.}}</span> {{end}}</p>{{end}}<p class="note">Static indicators show what the file contains; dynamic evidence shows what this bounded run actually attempted.</p></div>
          <div class="card half"><h2>ATT&amp;CK behavior mapping</h2>{{if .Detail.Techniques}}<table><thead><tr><th>technique</th><th>evidence</th></tr></thead><tbody>{{range .Detail.Techniques}}<tr><td><a href="https://attack.mitre.org/techniques/{{.ID}}/" target="_blank" rel="noopener noreferrer">{{.ID}} {{.Name}}</a></td><td class="v">{{.Evidence}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No mapped behavior in this run.</p>{{end}}<p class="note">Behavior context only; never actor attribution.</p></div>
        </div>

        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-behavior" role="tabpanel" data-dashboard-panel="behavior" hidden>
          <div class="section-heading"><div><h2>What the payload did</h2><p>System calls, filesystem changes, and the process and socket state before and after detonation.</p></div></div>
          <div class="card half"><h2>Top system calls</h2>{{if .Detail.TopSyscalls}}<table><thead><tr><th>call</th><th>count</th></tr></thead><tbody>{{range .Detail.TopSyscalls}}<tr><td class="v">{{.Name}}</td><td class="n">{{.Count}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No syscall trace was exported.</p>{{end}}</div>
          <div class="card half"><h2>Created or changed paths</h2>{{if .Detail.ChangedFiles}}<p class="note">{{len .Detail.ChangedFiles}} tracked path{{if ne (len .Detail.ChangedFiles) 1}}s{{end}} changed.</p><button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-changed-paths">Open the full list</button>{{else}}<p class="empty">No tracked path changes.</p>{{end}}</div>
          <div class="card half"><h2>Process difference</h2><p class="note">Userspace commands added or removed between the pre- and post-execution snapshots. Volatile PID/resource columns and kernel-worker churn are ignored.</p>{{if .Detail.ProcessDiff.Added}}<details open><summary>Added ({{len .Detail.ProcessDiff.Added}})</summary><pre class="code tw:mt-2">{{range .Detail.ProcessDiff.Added}}+ {{.}}
{{end}}</pre></details>{{else}}<p class="empty">No added processes.</p>{{end}}{{if .Detail.ProcessDiff.Removed}}<details open class="tw:mt-3"><summary>Removed ({{len .Detail.ProcessDiff.Removed}})</summary><pre class="code tw:mt-2">{{range .Detail.ProcessDiff.Removed}}- {{.}}
{{end}}</pre></details>{{else}}<p class="empty">No removed processes.</p>{{end}}</div>
          <div class="card half"><h2>Sockets difference</h2><p class="note">Socket rows added or removed between the pre- and post-execution snapshots.</p>{{if .Detail.SocketDiff.Added}}<details open><summary>Added ({{len .Detail.SocketDiff.Added}})</summary><pre class="code tw:mt-2">{{range .Detail.SocketDiff.Added}}+ {{.}}
{{end}}</pre></details>{{else}}<p class="empty">No added sockets.</p>{{end}}{{if .Detail.SocketDiff.Removed}}<details open class="tw:mt-3"><summary>Removed ({{len .Detail.SocketDiff.Removed}})</summary><pre class="code tw:mt-2">{{range .Detail.SocketDiff.Removed}}- {{.}}
{{end}}</pre></details>{{else}}<p class="empty">No removed sockets.</p>{{end}}<p class="note tw:mt-3">Full snapshots: <button class="lnk" type="button" data-hp-evidence="sb-sockets-before">sockets before</button> &bull; <button class="lnk" type="button" data-hp-evidence="sb-sockets-after">sockets after</button></p></div>
          <div class="card wide"><h2>Process output</h2><p class="note">Everything the payload wrote to its standard streams inside the guest. Guest-produced text is untrusted, HTML-escaped, and size-bounded.</p><button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-stdout">Standard output</button> <button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-stderr">Standard error</button></div>
        </div>

        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-network" role="tabpanel" data-dashboard-panel="network" hidden>
          <div class="section-heading"><div><h2>What it reached for</h2><p>Captured traffic on the host bridge and inside the guest, including loopback DNS.</p></div></div>
          <div class="card wide"><h2>Network and DNS capture</h2><table><tbody><tr><td>host bridge packets</td><td class="n">{{.Detail.NetworkSummary.Packets}}</td></tr><tr><td>host PCAP bytes</td><td class="n">{{.Detail.NetworkSummary.Bytes}}</td></tr><tr><td>guest packets, including loopback DNS</td><td class="n">{{.Detail.NetworkSummary.GuestPackets}}</td></tr><tr><td>guest PCAP bytes</td><td class="n">{{.Detail.NetworkSummary.GuestPCAPBytes}}</td></tr><tr><td>unique DNS queries</td><td class="n">{{len .Detail.NetworkSummary.DNSQueries}}</td></tr>{{range $name,$count := .Detail.NetworkSummary.Protocols}}<tr><td>host {{$name}}</td><td class="n">{{$count}}</td></tr>{{end}}{{range $name,$count := .Detail.NetworkSummary.GuestProtocols}}<tr><td>guest {{$name}}</td><td class="n">{{$count}}</td></tr>{{end}}</tbody></table>{{if .Detail.HostPCAPURL}}<a class="btn btn-sm btn-primary tw:mt-3" href="{{.Detail.HostPCAPURL}}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Raw host PCAP</a>{{end}} {{if .Detail.GuestPCAPURL}}<a class="btn btn-sm btn-primary tw:mt-3" href="{{.Detail.GuestPCAPURL}}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Raw guest + DNS PCAP</a>{{end}}{{if .Detail.NetworkSummary.DNSQueries}} <button class="btn btn-sm btn-secondary tw:mt-3" type="button" data-hp-evidence="sb-dns-names">Captured DNS names ({{len .Detail.NetworkSummary.DNSQueries}})</button>{{end}}{{if .Detail.NetworkSummary.DNSEvents}} <button class="btn btn-sm btn-secondary tw:mt-3" type="button" data-hp-evidence="sb-dns-events">DNS queries and responses ({{len .Detail.NetworkSummary.DNSEvents}})</button>{{end}}<p class="note">Raw captures are administrator-only and can be opened directly in Wireshark or tshark. PCAPs begin at guest boot and may include Ubuntu service traffic; captured presence alone does not prove payload attribution. Dynamic risk and ATT&amp;CK network behavior require a matching syscall from the traced payload process tree. In controlled mode, DNS answers are real and logged while downloads must pass the allowlisted proxy; direct guest routing remains blocked.</p></div>
          <div class="card half"><h2>Host bridge events</h2>{{if .Detail.NetworkSummary.Events}}<p class="note">{{len .Detail.NetworkSummary.Events}} decoded packet event{{if ne (len .Detail.NetworkSummary.Events) 1}}s{{end}}.</p><button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-net-events">Open the packet log</button>{{else}}<p class="empty">No packets were emitted during this run.</p>{{end}}{{if .Detail.NetworkSummary.Attempts}}<p class="note tw:mt-3">{{len .Detail.NetworkSummary.Attempts}} IPv4/IPv6 connect attempt{{if ne (len .Detail.NetworkSummary.Attempts) 1}}s{{end}} observed by strace.</p><button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-net-attempts">Open connect attempts</button>{{end}}</div>
          <div class="card half"><h2>Guest and loopback packet events</h2>{{if .Detail.NetworkSummary.GuestEvents}}<p class="note">{{len .Detail.NetworkSummary.GuestEvents}} decoded guest-side event{{if ne (len .Detail.NetworkSummary.GuestEvents) 1}}s{{end}}.</p><button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-guest-events">Open the guest packet log</button>{{else}}<p class="empty">No guest-side packets were decoded.</p>{{end}}</div>
        </div>

        {{if .Detail.Windows.Detected}}
        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-file" role="tabpanel" data-dashboard-panel="file" hidden>
          <div class="section-heading"><div><h2>What the file is</h2><p>Windows PE structure, imports, and signing, parsed inside the analysis guest.</p></div></div>
          <div class="card wide"><h2>Windows PE forensics</h2><table><tbody><tr><td>format / machine</td><td class="v">{{.Detail.Windows.PEType}} / {{.Detail.Windows.Machine}}</td></tr><tr><td>DLL</td><td class="v">{{.Detail.Windows.DLL}}</td></tr><tr><td>compile timestamp</td><td class="v">{{.Detail.Windows.CompileTimestamp}}</td></tr><tr><td>entry point</td><td class="v">{{.Detail.Windows.EntryPoint}}</td></tr><tr><td>image base</td><td class="v">{{.Detail.Windows.ImageBase}}</td></tr><tr><td>subsystem</td><td class="v">{{.Detail.Windows.Subsystem}}</td></tr><tr><td>import hash</td><td class="v">{{.Detail.Windows.ImpHash}}</td></tr><tr><td>embedded signature</td><td class="v">{{.Detail.Windows.SignaturePresent}}</td></tr></tbody></table><p class="note">Parsed with pefile inside the powered-off-after-use analysis guest. Wine execution is behavioral emulation, not a perfect replacement for native Windows.</p></div>
          <div class="card half"><h2>Suspicious Windows API imports</h2>{{if .Detail.Windows.SuspiciousImports}}<table><thead><tr><th>behavior</th><th>imports</th></tr></thead><tbody>{{range $group,$names := .Detail.Windows.SuspiciousImports}}<tr><td>{{$group}}</td><td class="v">{{range $names}}<span class="chip">{{.}}</span> {{end}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No categorized high-signal imports found.</p>{{end}}</div>
          <div class="card half"><h2>PE sections</h2>{{if .Detail.Windows.Sections}}<table><thead><tr><th>name</th><th>virtual</th><th>raw</th><th>entropy</th><th>flags</th></tr></thead><tbody>{{range .Detail.Windows.Sections}}<tr><td class="v">{{.Name}}</td><td class="n">{{.VirtualSize}}</td><td class="n">{{.RawSize}}</td><td class="n">{{.Entropy}}</td><td class="v">{{.Characteristics}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No PE sections parsed.</p>{{end}}</div>
          <div class="card wide"><h2>Imported libraries and symbols</h2>{{if .Detail.Windows.Imports}}<table><thead><tr><th>library</th><th>symbols</th></tr></thead><tbody>{{range .Detail.Windows.Imports}}<tr><td class="v">{{.DLL}}</td><td class="v">{{range .Symbols}}<span class="chip">{{.}}</span> {{end}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No imports parsed.</p>{{end}}</div>
          <div class="card half"><h2>Exports, warnings, and metadata</h2><p class="note">Parser output and the metadata tools run against the sample.</p>{{if .Detail.Windows.Exports}}<button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-pe-exports">Exports ({{len .Detail.Windows.Exports}})</button> {{end}}{{if .Detail.Windows.Warnings}}<button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-pe-warnings">Warnings ({{len .Detail.Windows.Warnings}})</button> {{end}}<button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-exiftool">ExifTool</button> <button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-objdump">objdump -x</button>{{if not .Detail.Windows.Exports}}{{if not .Detail.Windows.Warnings}}<p class="note tw:mt-3">No exported symbols or parser warnings.</p>{{end}}{{end}}</div>
          <div class="card half"><h2>Signing and strings</h2><p class="note">Authenticode result and the printable sequences extracted from the sample.</p><button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-authenticode">Authenticode inspection</button> <button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-ascii-strings">ASCII strings ({{len .Detail.Windows.ASCIIStrings}})</button> <button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-utf16-strings">UTF-16LE strings ({{len .Detail.Windows.UTF16Strings}})</button></div>
        </div>
        {{end}}

        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-diagnostics" role="tabpanel" data-dashboard-panel="diagnostics" hidden>
          <div class="section-heading"><div><h2>How the run itself went</h2><p>Guest and collection state — read this when the evidence above looks thin, to tell an empty result from a broken one.</p></div></div>
          <div class="card wide"><h2>Runtime and collection diagnostics</h2><table><tbody><tr><td>run status</td><td class="v{{if .Detail.Incomplete}} tw:text-red{{end}}">{{.Detail.RunStatus}}</td></tr><tr><td>guest service started</td><td class="v">{{.Detail.GuestStarted}}</td></tr><tr><td>last host phase</td><td class="v">{{.Detail.Artifacts.HostPhase}}</td></tr><tr><td>processes before / after</td><td class="v">{{len .Detail.Artifacts.ProcessesBefore}} / {{len .Detail.Artifacts.ProcessesAfter}}</td></tr></tbody></table><p class="note tw:mt-3">Collected artifacts:</p><button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-kernel">Guest kernel</button> <button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-proc-before">Processes before ({{len .Detail.Artifacts.ProcessesBefore}})</button> <button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-proc-after">Processes after ({{len .Detail.Artifacts.ProcessesAfter}})</button> <button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-host-tcpdump">Host tcpdump log</button> <button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-guest-tcpdump">Guest tcpdump log</button>{{if .Detail.Artifacts.ClassificationError}} <button class="btn btn-sm btn-danger" type="button" data-hp-evidence="sb-classifier-error">Classifier error</button>{{end}}{{if .Detail.Artifacts.PEForensicsError}} <button class="btn btn-sm btn-danger" type="button" data-hp-evidence="sb-pe-error">PE parser error</button>{{end}}</div>
          {{if .Detail.Incomplete}}<div class="card wide"><h2>Sandbox infrastructure diagnostics</h2><table><tbody><tr><td>run status</td><td class="v tw:text-red">{{.Detail.RunStatus}}</td></tr><tr><td>exit status</td><td class="v">{{.Detail.ExitStatus}}</td></tr><tr><td>last host phase</td><td class="v">{{.Detail.Artifacts.HostPhase}}</td></tr><tr><td>guest service started</td><td class="v">{{.Detail.GuestStarted}}</td></tr></tbody></table><p class="note tw:mt-3">{{if .Detail.Artifacts.ConsoleLog}}<button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-console">Guest serial console</button> {{end}}{{if .Detail.Artifacts.QEMULog}}<button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-qemu">QEMU log</button> {{end}}{{if .Detail.Artifacts.DomainState}}<button class="btn btn-sm btn-secondary" type="button" data-hp-evidence="sb-domain">Domain state</button>{{end}}</p></div>{{end}}
        </div>

        <!-- Evidence bodies: raw analysis output the viewer opens on demand.
             They stay in the page so the record is complete without JavaScript. -->
        <div class="hp-evidence-source" hidden>
          <div data-hp-evidence-body="sb-changed-paths" data-hp-evidence-title="Created or changed paths" data-hp-evidence-note="Filesystem paths the run created or modified inside the disposable guest."><pre class="code">{{range .Detail.ChangedFiles}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-stdout" data-hp-evidence-title="Standard output" data-hp-evidence-note="Untrusted guest output, HTML-escaped and size-bounded."><pre class="code">{{.Detail.Stdout}}</pre></div>
          <div data-hp-evidence-body="sb-stderr" data-hp-evidence-title="Standard error" data-hp-evidence-note="Untrusted guest output, HTML-escaped and size-bounded."><pre class="code">{{.Detail.Stderr}}</pre></div>
          <div data-hp-evidence-body="sb-sockets-before" data-hp-evidence-title="Sockets before detonation"><pre class="code">{{range .Detail.SocketsBefore}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-sockets-after" data-hp-evidence-title="Sockets after detonation"><pre class="code">{{range .Detail.SocketsAfter}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-net-events" data-hp-evidence-title="Host bridge packet events"><pre class="code">{{range .Detail.NetworkSummary.Events}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-net-attempts" data-hp-evidence-title="Connect attempts observed by strace"><pre class="code">{{range .Detail.NetworkSummary.Attempts}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-guest-events" data-hp-evidence-title="Guest and loopback packet events"><pre class="code">{{range .Detail.NetworkSummary.GuestEvents}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-dns-names" data-hp-evidence-title="Captured DNS names"><pre class="code">{{range .Detail.NetworkSummary.DNSQueries}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-dns-events" data-hp-evidence-title="DNS queries and responses"><pre class="code">{{range .Detail.NetworkSummary.DNSEvents}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-kernel" data-hp-evidence-title="Guest kernel"><pre class="code">{{.Detail.Artifacts.Kernel}}</pre></div>
          <div data-hp-evidence-body="sb-proc-before" data-hp-evidence-title="Processes before detonation"><pre class="code">{{range .Detail.Artifacts.ProcessesBefore}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-proc-after" data-hp-evidence-title="Processes after detonation"><pre class="code">{{range .Detail.Artifacts.ProcessesAfter}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-host-tcpdump" data-hp-evidence-title="Host tcpdump log"><pre class="code">{{.Detail.Artifacts.HostTCPDumpLog}}</pre></div>
          <div data-hp-evidence-body="sb-guest-tcpdump" data-hp-evidence-title="Guest tcpdump log"><pre class="code">{{.Detail.Artifacts.GuestTCPDumpLog}}</pre></div>
          {{if .Detail.Artifacts.ClassificationError}}<div data-hp-evidence-body="sb-classifier-error" data-hp-evidence-title="Classifier error"><pre class="code">{{.Detail.Artifacts.ClassificationError}}</pre></div>{{end}}
          {{if .Detail.Artifacts.PEForensicsError}}<div data-hp-evidence-body="sb-pe-error" data-hp-evidence-title="PE parser error"><pre class="code">{{.Detail.Artifacts.PEForensicsError}}</pre></div>{{end}}
          {{if .Detail.Incomplete}}
          <div data-hp-evidence-body="sb-console" data-hp-evidence-title="Guest serial console"><pre class="code">{{.Detail.Artifacts.ConsoleLog}}</pre></div>
          <div data-hp-evidence-body="sb-qemu" data-hp-evidence-title="QEMU log"><pre class="code">{{.Detail.Artifacts.QEMULog}}</pre></div>
          <div data-hp-evidence-body="sb-domain" data-hp-evidence-title="Domain state"><pre class="code">{{.Detail.Artifacts.DomainState}}
{{.Detail.Artifacts.QEMUStatus}}</pre></div>
          {{end}}
          {{if .Detail.Windows.Detected}}
          <div data-hp-evidence-body="sb-pe-exports" data-hp-evidence-title="PE exports"><pre class="code">{{range .Detail.Windows.Exports}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-pe-warnings" data-hp-evidence-title="PE parser warnings"><pre class="code">{{range .Detail.Windows.Warnings}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-exiftool" data-hp-evidence-title="ExifTool metadata"><pre class="code">{{.Detail.Artifacts.ExifTool}}</pre></div>
          <div data-hp-evidence-body="sb-objdump" data-hp-evidence-title="objdump -x"><pre class="code">{{.Detail.Artifacts.PEObjdump}}</pre></div>
          <div data-hp-evidence-body="sb-authenticode" data-hp-evidence-title="Authenticode inspection"><pre class="code">{{.Detail.Windows.Authenticode}}</pre></div>
          <div data-hp-evidence-body="sb-ascii-strings" data-hp-evidence-title="Extracted ASCII strings" data-hp-evidence-note="Printable sequences extracted from the sample. Filter to find a specific indicator."><pre class="code">{{range .Detail.Windows.ASCIIStrings}}{{.}}
{{end}}</pre></div>
          <div data-hp-evidence-body="sb-utf16-strings" data-hp-evidence-title="Extracted UTF-16LE strings" data-hp-evidence-note="Wide-character sequences extracted from the sample."><pre class="code">{{range .Detail.Windows.UTF16Strings}}{{.}}
{{end}}</pre></div>
          {{end}}
        </div>
        <p class="note tw:mt-3">Guest-produced text is untrusted, HTML-escaped, and size-bounded. Raw PCAP and diagnostics downloads require the administrator role; complete raw result directories and syscall traces remain root-only on the homeserver.</p>
        {{else}}
        <div class="tw:grid tw:grid-cols-2 tw:sm:grid-cols-3 tw:xl:grid-cols-5 tw:gap-3 tw:mb-6" id="sandbox-status-stats">
          <div class="hp-stat"><span class="hp-stat-value">{{.Status.WorkerState}}</span><span class="hp-stat-label">Worker</span></div>
          <div class="hp-stat"><span class="hp-stat-value{{if .Status.HandoffOld}} tw:text-red{{else}}{{end}}">{{.Status.Handoff}}</span><span class="hp-stat-label">Awaiting handoff</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.Status.Counts.Queued}}</span><span class="hp-stat-label">KVM queued</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.Status.Counts.Running}}</span><span class="hp-stat-label">Running</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.Status.Counts.Failed}}</span><span class="hp-stat-label">Failed</span></div>
        </div>
        <form class="filters" id="sandbox-filters" method="get" action="/sandbox"><a class="chip" href="/payloads">&larr; captured payloads</a><input class="hp-input" name="q" value="{{.Query}}" placeholder="hash, source, file type, risk or job" aria-label="Search sandbox results"><button class="copy" type="submit">search</button>{{if .Query}}<a class="chip" href="/sandbox">clear</a>{{end}}<span class="chip">{{len .Rows}} retained runs</span><span class="chip">status {{.Status.UpdatedAt}}</span></form>
        {{if .Status.Jobs}}<div class="card wide" id="sandbox-jobs"><h2>Active and failed queue jobs</h2><table><thead><tr><th>state</th><th>requested</th><th>source</th><th>SHA-256</th></tr></thead><tbody>{{range .Status.Jobs}}<tr><td><span class="badge badge--muted">{{.State}}</span></td><td>{{.RequestedAt}}</td><td>{{.Source}}</td><td class="v">{{.SHA256}}</td></tr>{{end}}</tbody></table></div>{{end}}
        <div class="card wide" id="sandbox-results"><p class="note">Authenticated administrators submit captures with the <strong>Analyze</strong> button. “Awaiting handoff” means the dashboard request has not reached the root-owned host watcher; “KVM queued” means it is staged for the isolated worker. CLI fallback: <code>sudo honeypot-sandbox-submit &lt;hash&gt;</code>.</p>{{if .Status.HandoffOld}}<div class="tw:mb-4 tw:rounded-md tw:border tw:border-red tw:bg-red-subtle tw:px-4 tw:py-3 tw:text-red"><strong>Sandbox handoff stalled.</strong> Requests have waited over five minutes. Check <code>honeypot-sandbox-web-requests.path</code> and its service.</div>{{end}}{{if .Rows}}<table><thead><tr><th>completed</th><th>source</th><th>SHA-256</th><th>risk</th><th>duration</th><th>packets</th><th>exit</th><th>details</th></tr></thead><tbody>{{range .Rows}}<tr><td>{{.CompletedAt}}</td><td><span class="badge badge--muted">{{.Source}}</span></td><td class="v"><a href="/payload-analysis/{{.SHA256}}">{{.SHA256}}</a></td><td>{{.RiskScore}} / {{.RiskLevel}}</td><td class="n">{{.Duration}}s</td><td class="n">{{.NetworkSummary.Packets}}</td><td class="n">{{.ExitStatus}}</td><td><a class="lnk" href="/sandbox/{{.Job | urlquery}}">investigate &rarr;</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No completed sandbox exports match this view.</p>{{end}}</div>
        {{end}}

        <footer id="sandbox-footer">xore//honeypot &bull; isolated KVM dynamic analysis &bull; summaries only</footer>
      </div>
    </main>
</div>
</body>
</html>
{{end}}

`
