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
        <div class="filters" id="sandbox-detail-actions"><a class="chip" href="/sandbox">&larr; all sandbox results</a><a class="chip" href="/payload-analysis/{{.Detail.SHA256}}">static analysis</a><a class="chip" href="/events?shasum={{.Detail.SHA256}}">related events</a><a class="chip" href="/export/sandbox/{{.Detail.Job}}.json">sanitized JSON &darr;</a>{{if .Detail.HostPCAPURL}}<a class="chip" href="{{.Detail.HostPCAPURL}}" title="Raw host-bridge packet capture for Wireshark">host PCAP ({{.Detail.HostPCAPSize}} bytes) &darr;</a>{{end}}{{if .Detail.GuestPCAPURL}}<a class="chip" href="{{.Detail.GuestPCAPURL}}" title="Raw guest capture including loopback DNS for Wireshark">guest PCAP ({{.Detail.GuestPCAPSize}} bytes) &darr;</a>{{end}}{{if .Detail.DiagnosticsURL}}<a class="chip" href="{{.Detail.DiagnosticsURL}}" title="Bounded administrator evidence bundle">diagnostics ZIP ({{.Detail.DiagnosticsSize}} bytes) &darr;</a>{{end}}</div>
        {{if .Detail.Incomplete}}<div class="tw:mb-6 tw:rounded-lg tw:border tw:border-red tw:bg-red-subtle tw:px-4 tw:py-4 tw:text-red" role="alert"><strong>Analysis did not run to completion.</strong> {{if .Detail.FailureReason}}{{.Detail.FailureReason}}{{else}}The guest returned no usable analysis artifacts.{{end}} The empty evidence sections below are an infrastructure failure, not a clean payload result. Re-submit only after the sandbox health check passes.</div>{{end}}

        <div class="tw:grid tw:grid-cols-2 tw:sm:grid-cols-4 tw:gap-3 tw:mb-6" id="sandbox-detail-stats">
          <div class="hp-stat"><span class="hp-stat-value tw:text-red">{{if .Detail.Incomplete}}not rated{{else}}{{.Detail.RiskScore}} / 100 &bull; {{.Detail.RiskLevel}}{{end}}</span><span class="hp-stat-label">Dynamic risk</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.Detail.Duration}} seconds</span><span class="hp-stat-label">Duration</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.Detail.NetworkSummary.Packets}}</span><span class="hp-stat-label">Captured packets</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{len .Detail.ChangedFiles}}</span><span class="hp-stat-label">Changed paths</span></div>
        </div>

        {{if .Detail.Incomplete}}<div class="card wide tw:mb-4"><h2>Sandbox infrastructure diagnostics</h2><table><tbody><tr><td>run status</td><td class="v tw:text-red">{{.Detail.RunStatus}}</td></tr><tr><td>exit status</td><td class="v">{{.Detail.ExitStatus}}</td></tr><tr><td>last host phase</td><td class="v">{{.Detail.Artifacts.HostPhase}}</td></tr><tr><td>guest service started</td><td class="v">{{.Detail.GuestStarted}}</td></tr></tbody></table>{{if .Detail.Artifacts.ConsoleLog}}<details open class="tw:mt-3"><summary>Guest serial console</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.ConsoleLog}}</pre></details>{{end}}{{if .Detail.Artifacts.QEMULog}}<details open class="tw:mt-3"><summary>QEMU log</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.QEMULog}}</pre></details>{{end}}{{if .Detail.Artifacts.DomainState}}<details class="tw:mt-3"><summary>Domain state</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.DomainState}}
{{.Detail.Artifacts.QEMUStatus}}</pre></details>{{end}}</div>{{end}}

        <div class="tw:grid tw:grid-cols-12 tw:gap-3.5" id="sandbox-detail-cards">
        <div class="card wide"><h2>Run identity and analysis route</h2><table><tbody><tr><td>job</td><td class="v">{{.Detail.Job}}</td></tr><tr><td>identified payload</td><td class="v"><strong>{{.Detail.Classification.Label}}</strong> {{if .Detail.Classification.Code}}<span class="badge badge--muted">{{.Detail.Classification.Code}}</span>{{end}}</td></tr><tr><td>platform / category</td><td class="v">{{.Detail.Classification.Platform}} / {{.Detail.Classification.Category}}</td></tr><tr><td>selected analysis path</td><td class="v">{{if .Detail.AnalysisPath}}{{.Detail.AnalysisPath}}{{else}}{{.Detail.Classification.AnalysisPath}}{{end}}</td></tr><tr><td>execution mode</td><td class="v">{{.Detail.ExecutionMode}}</td></tr><tr><td>file(1) result</td><td class="v">{{.Detail.FileType}}</td></tr><tr><td>capture source</td><td class="v">{{.Detail.Source}} / {{.Detail.CaptureName}}</td></tr><tr><td>MD5</td><td class="v">{{.Detail.Hashes.MD5}}</td></tr><tr><td>SHA-1</td><td class="v">{{.Detail.Hashes.SHA1}}</td></tr><tr><td>SHA-256</td><td class="v">{{.Detail.SHA256}}</td></tr><tr><td>requested</td><td class="v">{{.Detail.RequestedAt}}</td></tr><tr><td>started</td><td class="v">{{.Detail.StartedAt}}</td></tr><tr><td>completed</td><td class="v">{{.Detail.CompletedAt}}</td></tr><tr><td>exit status</td><td class="v">{{.Detail.ExitStatus}}</td></tr>{{if .Detail.TimeoutReason}}<tr><td>timeout</td><td class="v tw:text-red">{{.Detail.TimeoutReason}}</td></tr>{{end}}<tr><td>isolation</td><td class="v">fresh transient KVM guest, disposable overlay, no forwarding, strict libvirt NIC filter</td></tr></tbody></table></div>
        <div class="card half"><h2>Static versus dynamic</h2><table><tbody><tr><td>static YARA matches</td><td class="n">{{len .StaticYARA}}</td></tr><tr><td>dynamic ATT&amp;CK behaviors</td><td class="n">{{len .Detail.Techniques}}</td></tr><tr><td>system calls recorded</td><td class="n">{{len .Detail.TopSyscalls}}</td></tr><tr><td>filesystem changes</td><td class="n">{{len .Detail.ChangedFiles}}</td></tr><tr><td>network packets</td><td class="n">{{.Detail.NetworkSummary.Packets}}</td></tr></tbody></table>{{if .StaticYARA}}<p class="note">YARA: {{range .StaticYARA}}<span class="chip">{{.}}</span> {{end}}</p>{{end}}<p class="note">Static indicators show what the file contains; dynamic evidence shows what this bounded run actually attempted.</p></div>
        <div class="card half"><h2>ATT&amp;CK behavior mapping</h2>{{if .Detail.Techniques}}<table><thead><tr><th>technique</th><th>evidence</th></tr></thead><tbody>{{range .Detail.Techniques}}<tr><td><a href="https://attack.mitre.org/techniques/{{.ID}}/" target="_blank" rel="noopener noreferrer">{{.ID}} {{.Name}}</a></td><td class="v">{{.Evidence}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No mapped behavior in this run.</p>{{end}}<p class="note">Behavior context only; never actor attribution.</p></div>
        <div class="card half"><h2>Network and DNS capture</h2><table><tbody><tr><td>host bridge packets</td><td class="n">{{.Detail.NetworkSummary.Packets}}</td></tr><tr><td>host PCAP bytes</td><td class="n">{{.Detail.NetworkSummary.Bytes}}</td></tr><tr><td>guest packets, including loopback DNS</td><td class="n">{{.Detail.NetworkSummary.GuestPackets}}</td></tr><tr><td>guest PCAP bytes</td><td class="n">{{.Detail.NetworkSummary.GuestPCAPBytes}}</td></tr><tr><td>unique DNS queries</td><td class="n">{{len .Detail.NetworkSummary.DNSQueries}}</td></tr>{{range $name,$count := .Detail.NetworkSummary.Protocols}}<tr><td>host {{$name}}</td><td class="n">{{$count}}</td></tr>{{end}}{{range $name,$count := .Detail.NetworkSummary.GuestProtocols}}<tr><td>guest {{$name}}</td><td class="n">{{$count}}</td></tr>{{end}}</tbody></table>{{if .Detail.HostPCAPURL}}<a class="btn btn-sm btn-primary tw:mt-3" href="{{.Detail.HostPCAPURL}}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Raw host PCAP</a>{{end}} {{if .Detail.GuestPCAPURL}}<a class="btn btn-sm btn-primary tw:mt-3" href="{{.Detail.GuestPCAPURL}}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Raw guest + DNS PCAP</a>{{end}}{{if .Detail.NetworkSummary.DNSQueries}}<details class="tw:mt-3"><summary>Captured DNS names</summary><pre class="code tw:mt-2">{{range .Detail.NetworkSummary.DNSQueries}}{{.}}
{{end}}</pre></details>{{end}}{{if .Detail.NetworkSummary.DNSEvents}}<details class="tw:mt-3"><summary>DNS queries and responses ({{len .Detail.NetworkSummary.DNSEvents}})</summary><pre class="code tw:mt-2">{{range .Detail.NetworkSummary.DNSEvents}}{{.}}
{{end}}</pre></details>{{end}}<p class="note">Raw captures are administrator-only and can be opened directly in Wireshark or tshark. PCAPs begin at guest boot and may include Ubuntu service traffic; captured presence alone does not prove payload attribution. Dynamic risk and ATT&amp;CK network behavior require a matching syscall from the traced payload process tree. In controlled mode, DNS answers are real and logged while downloads must pass the allowlisted proxy; direct guest routing remains blocked.</p></div>
        {{if .Detail.Windows.Detected}}
        <div class="card wide"><h2>Windows PE forensics</h2><table><tbody><tr><td>format / machine</td><td class="v">{{.Detail.Windows.PEType}} / {{.Detail.Windows.Machine}}</td></tr><tr><td>DLL</td><td class="v">{{.Detail.Windows.DLL}}</td></tr><tr><td>compile timestamp</td><td class="v">{{.Detail.Windows.CompileTimestamp}}</td></tr><tr><td>entry point</td><td class="v">{{.Detail.Windows.EntryPoint}}</td></tr><tr><td>image base</td><td class="v">{{.Detail.Windows.ImageBase}}</td></tr><tr><td>subsystem</td><td class="v">{{.Detail.Windows.Subsystem}}</td></tr><tr><td>import hash</td><td class="v">{{.Detail.Windows.ImpHash}}</td></tr><tr><td>embedded signature</td><td class="v">{{.Detail.Windows.SignaturePresent}}</td></tr></tbody></table><p class="note">Parsed with pefile inside the powered-off-after-use analysis guest. Wine execution is behavioral emulation, not a perfect replacement for native Windows.</p></div>
        <div class="card half"><h2>Suspicious Windows API imports</h2>{{if .Detail.Windows.SuspiciousImports}}<table><thead><tr><th>behavior</th><th>imports</th></tr></thead><tbody>{{range $group,$names := .Detail.Windows.SuspiciousImports}}<tr><td>{{$group}}</td><td class="v">{{range $names}}<span class="chip">{{.}}</span> {{end}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No categorized high-signal imports found.</p>{{end}}</div>
        <div class="card half"><h2>PE sections</h2>{{if .Detail.Windows.Sections}}<table><thead><tr><th>name</th><th>virtual</th><th>raw</th><th>entropy</th><th>flags</th></tr></thead><tbody>{{range .Detail.Windows.Sections}}<tr><td class="v">{{.Name}}</td><td class="n">{{.VirtualSize}}</td><td class="n">{{.RawSize}}</td><td class="n">{{.Entropy}}</td><td class="v">{{.Characteristics}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No PE sections parsed.</p>{{end}}</div>
        <div class="card wide"><h2>Imported libraries and symbols</h2>{{if .Detail.Windows.Imports}}<table><thead><tr><th>library</th><th>symbols</th></tr></thead><tbody>{{range .Detail.Windows.Imports}}<tr><td class="v">{{.DLL}}</td><td class="v">{{range .Symbols}}<span class="chip">{{.}}</span> {{end}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No imports parsed.</p>{{end}}</div>
        <div class="card half"><h2>PE exports and parser warnings</h2>{{if .Detail.Windows.Exports}}<details open><summary>Exports ({{len .Detail.Windows.Exports}})</summary><pre class="code tw:mt-2">{{range .Detail.Windows.Exports}}{{.}}
{{end}}</pre></details>{{else}}<p class="empty">No exported symbols parsed.</p>{{end}}{{if .Detail.Windows.Warnings}}<details class="tw:mt-3" open><summary>Warnings ({{len .Detail.Windows.Warnings}})</summary><pre class="code tw:mt-2">{{range .Detail.Windows.Warnings}}{{.}}
{{end}}</pre></details>{{end}}</div>
        <div class="card half"><h2>PE metadata tools</h2><details open><summary>ExifTool</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.ExifTool}}</pre></details><details class="tw:mt-3"><summary>objdump -x</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.PEObjdump}}</pre></details></div>
        <div class="card half"><h2>Authenticode inspection</h2><pre class="code">{{.Detail.Windows.Authenticode}}</pre></div>
        <div class="card half"><h2>Extracted Windows strings</h2><details><summary>ASCII strings ({{len .Detail.Windows.ASCIIStrings}})</summary><pre class="code tw:mt-2">{{range .Detail.Windows.ASCIIStrings}}{{.}}
{{end}}</pre></details><details class="tw:mt-3"><summary>UTF-16LE strings ({{len .Detail.Windows.UTF16Strings}})</summary><pre class="code tw:mt-2">{{range .Detail.Windows.UTF16Strings}}{{.}}
{{end}}</pre></details></div>
        {{end}}
        <div class="card half"><h2>Network events</h2>{{if .Detail.NetworkSummary.Events}}<pre class="code">{{range .Detail.NetworkSummary.Events}}{{.}}
{{end}}</pre>{{else}}<p class="empty">No packets were emitted during this run.</p>{{end}}{{if .Detail.NetworkSummary.Attempts}}<p class="note">IPv4/IPv6 connect attempts observed by strace</p><pre class="code">{{range .Detail.NetworkSummary.Attempts}}{{.}}
{{end}}</pre>{{end}}</div>
        <div class="card half"><h2>Guest and loopback packet events</h2>{{if .Detail.NetworkSummary.GuestEvents}}<pre class="code">{{range .Detail.NetworkSummary.GuestEvents}}{{.}}
{{end}}</pre>{{else}}<p class="empty">No guest-side packets were decoded.</p>{{end}}</div>
        <div class="card half"><h2>Top system calls</h2>{{if .Detail.TopSyscalls}}<table><thead><tr><th>call</th><th>count</th></tr></thead><tbody>{{range .Detail.TopSyscalls}}<tr><td class="v">{{.Name}}</td><td class="n">{{.Count}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No syscall trace was exported.</p>{{end}}</div>
        <div class="card half"><h2>Created or changed paths</h2>{{if .Detail.ChangedFiles}}<pre class="code">{{range .Detail.ChangedFiles}}{{.}}
{{end}}</pre>{{else}}<p class="empty">No tracked path changes.</p>{{end}}</div>
        <div class="card half"><h2>Standard output</h2><pre class="code">{{.Detail.Stdout}}</pre></div>
        <div class="card half"><h2>Standard error</h2><pre class="code">{{.Detail.Stderr}}</pre></div>
        <div class="card half"><h2>Process difference</h2><p class="note">Userspace commands added or removed between the pre- and post-execution snapshots. Volatile PID/resource columns and kernel-worker churn are ignored.</p>{{if .Detail.ProcessDiff.Added}}<details open><summary>Added ({{len .Detail.ProcessDiff.Added}})</summary><pre class="code tw:mt-2">{{range .Detail.ProcessDiff.Added}}+ {{.}}
{{end}}</pre></details>{{else}}<p class="empty">No added processes.</p>{{end}}{{if .Detail.ProcessDiff.Removed}}<details open class="tw:mt-3"><summary>Removed ({{len .Detail.ProcessDiff.Removed}})</summary><pre class="code tw:mt-2">{{range .Detail.ProcessDiff.Removed}}- {{.}}
{{end}}</pre></details>{{else}}<p class="empty">No removed processes.</p>{{end}}</div>
        <div class="card half"><h2>Sockets difference</h2><p class="note">Socket rows added or removed between the pre- and post-execution snapshots.</p>{{if .Detail.SocketDiff.Added}}<details open><summary>Added ({{len .Detail.SocketDiff.Added}})</summary><pre class="code tw:mt-2">{{range .Detail.SocketDiff.Added}}+ {{.}}
{{end}}</pre></details>{{else}}<p class="empty">No added sockets.</p>{{end}}{{if .Detail.SocketDiff.Removed}}<details open class="tw:mt-3"><summary>Removed ({{len .Detail.SocketDiff.Removed}})</summary><pre class="code tw:mt-2">{{range .Detail.SocketDiff.Removed}}- {{.}}
{{end}}</pre></details>{{else}}<p class="empty">No removed sockets.</p>{{end}}</div>
        <div class="card half"><h2>Sockets before</h2><pre class="code">{{range .Detail.SocketsBefore}}{{.}}
{{end}}</pre></div><div class="card half"><h2>Sockets after</h2><pre class="code">{{range .Detail.SocketsAfter}}{{.}}
{{end}}</pre></div>
        <div class="card wide"><h2>Runtime and collection diagnostics</h2><details open><summary>Guest kernel</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.Kernel}}</pre></details><details class="tw:mt-3"><summary>Processes before detonation ({{len .Detail.Artifacts.ProcessesBefore}})</summary><pre class="code tw:mt-2">{{range .Detail.Artifacts.ProcessesBefore}}{{.}}
{{end}}</pre></details><details class="tw:mt-3"><summary>Processes after detonation ({{len .Detail.Artifacts.ProcessesAfter}})</summary><pre class="code tw:mt-2">{{range .Detail.Artifacts.ProcessesAfter}}{{.}}
{{end}}</pre></details><details class="tw:mt-3"><summary>Host tcpdump log</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.HostTCPDumpLog}}</pre></details><details class="tw:mt-3"><summary>Guest tcpdump log</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.GuestTCPDumpLog}}</pre></details>{{if .Detail.Artifacts.ClassificationError}}<details class="tw:mt-3" open><summary>Classifier error</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.ClassificationError}}</pre></details>{{end}}{{if .Detail.Artifacts.PEForensicsError}}<details class="tw:mt-3" open><summary>PE parser error</summary><pre class="code tw:mt-2">{{.Detail.Artifacts.PEForensicsError}}</pre></details>{{end}}</div>
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
