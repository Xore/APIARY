package main

// ioc_correlation.go — #680: cross-references a sample's floss-decoded
// static strings (analysis/ghidra/statictools/server.py's /v1/floss,
// surfaced via ghidraResult.Floss) against the same sample's Windows-sandbox
// run(s) (sandboxResult, keyed by the same SHA-256), split off from #482
// because a sample analyzed by *both* pipelines has two independent
// static-string sources with no cross-referencing between them.
//
// The regexes below are a direct port of
// sandbox/windows/orchestrate/extract_iocs.py's RE_IP/RE_URL/RE_DOMAIN/
// RE_UNC/PRIVATE -- same patterns, so a floss-decoded string and a sandbox
// static string that both spell the same IOC are recognized as the same
// value, not two near-misses. Go's regexp (RE2) supports \b and the
// character-class escapes used here identically to Python's re for these
// patterns.
//
// Three buckets per IOC kind, matching the issue's own wording:
//   - FlossOnly: floss decoded it; no sandbox run (static or dynamic) for
//     this sample ever saw it. floss's emulation-based decoding is the only
//     reason this is visible at all -- extract_iocs.py's plain
//     printable-string scan over the sample's raw bytes cannot find an
//     obfuscated/decoded value.
//   - SandboxStaticOnly: the sandbox's own static scan found it; floss's
//     decoded/static/stack/tight strings never surfaced the same value.
//   - ConfirmedAtRuntime: floss decoded it, AND some sandbox run actually
//     observed it happening (a DNS query, a network connection, a download)
//     -- the strongest signal this correlation can produce.
import (
	"regexp"
	"sort"
)

var (
	iocReIP        = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	iocReURL       = regexp.MustCompile(`https?://[^\s'"<>)\]]+`)
	iocReDomain    = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)
	iocReUNC       = regexp.MustCompile(`\\\\[a-zA-Z0-9_.-]+\\[^\s\\"'<>|*?]+(?:\\[^\s\\"'<>|*?]+)*`)
	iocRePrivateIP = regexp.MustCompile(`^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255)`)
)

// iocKindCorrelation is one IOC kind's (IP/domain/URL/UNC path) three-way
// split for a single sample. ConfirmedAtRuntime is always empty for UNC
// paths -- extract_iocs.py's dynamic parsers (Sysmon/PowerShell/FakeNet-NG)
// have no SMB/UNC observation path, only the static binary scan does.
type iocKindCorrelation struct {
	FlossOnly          []string
	SandboxStaticOnly  []string
	ConfirmedAtRuntime []string
}

// Empty is exported (unlike a plain empty()) so the ghidra.html template
// can call it via reflection -- text/template only sees exported methods.
func (c iocKindCorrelation) Empty() bool {
	return len(c.FlossOnly) == 0 && len(c.SandboxStaticOnly) == 0 && len(c.ConfirmedAtRuntime) == 0
}

// iocCorrelation is ghidraResult.IOCCorrelation's value -- nil whenever
// there is no Windows-sandbox run at all for this SHA-256 (nothing to
// correlate against), computed fresh on every read in ghidraData() rather
// than stored, since either side's result set can change independently.
type iocCorrelation struct {
	HasSandboxRun bool
	HasFlossData  bool
	IPs           iocKindCorrelation
	Domains       iocKindCorrelation
	URLs          iocKindCorrelation
	UNCPaths      iocKindCorrelation
}

// Empty is exported for the same reason iocKindCorrelation.Empty is above.
func (c *iocCorrelation) Empty() bool {
	return c == nil || (c.IPs.Empty() && c.Domains.Empty() && c.URLs.Empty() && c.UNCPaths.Empty())
}

// extractIOCPatterns applies the same IOC patterns extract_iocs.py's
// parse_sample_binary() runs against printable strings, over floss's
// already-decoded string categories instead of a raw byte scan.
func extractIOCPatterns(strs []string) (ips, domains, urls, uncs map[string]bool) {
	ips, domains, urls, uncs = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range strs {
		for _, ip := range iocReIP.FindAllString(s, -1) {
			if !iocRePrivateIP.MatchString(ip) {
				ips[ip] = true
			}
		}
		for _, u := range iocReURL.FindAllString(s, -1) {
			urls[u] = true
		}
		for _, d := range iocReDomain.FindAllString(s, -1) {
			domains[d] = true
		}
		for _, unc := range iocReUNC.FindAllString(s, -1) {
			uncs[unc] = true
		}
	}
	return
}

func correlateIOCSet(flossSet, sandboxStatic, sandboxDynamic map[string]bool) iocKindCorrelation {
	var out iocKindCorrelation
	for v := range flossSet {
		switch {
		case sandboxDynamic[v]:
			out.ConfirmedAtRuntime = append(out.ConfirmedAtRuntime, v)
		case !sandboxStatic[v]:
			out.FlossOnly = append(out.FlossOnly, v)
		}
	}
	for v := range sandboxStatic {
		if !flossSet[v] {
			out.SandboxStaticOnly = append(out.SandboxStaticOnly, v)
		}
	}
	sort.Strings(out.FlossOnly)
	sort.Strings(out.SandboxStaticOnly)
	sort.Strings(out.ConfirmedAtRuntime)
	return out
}

// matchingSandboxRuns returns every Windows-sandbox result for the given
// SHA-256, across every run (a sample can be re-detonated), same in-memory
// scan ghidraData() already uses to find its own Detail row.
func matchingSandboxRuns(sha256 string) []sandboxResult {
	var out []sandboxResult
	for _, r := range loadSandboxResults() {
		if r.SHA256 == sha256 {
			out = append(out, r)
		}
	}
	return out
}

// correlateFlossSandboxIOCs is #680's entry point, called from ghidraData()
// for the currently-viewed Detail row. nil when no sandbox run exists for
// this sample at all.
func correlateFlossSandboxIOCs(floss *ghidraFloss, sandboxRuns []sandboxResult) *iocCorrelation {
	if len(sandboxRuns) == 0 {
		return nil
	}
	c := &iocCorrelation{HasSandboxRun: true}
	if floss == nil || floss.Unsupported != "" {
		return c
	}
	c.HasFlossData = true

	var allStrings []string
	allStrings = append(allStrings, floss.DecodedStrings...)
	allStrings = append(allStrings, floss.StaticStrings...)
	allStrings = append(allStrings, floss.StackStrings...)
	allStrings = append(allStrings, floss.TightStrings...)
	flossIPs, flossDomains, flossURLs, flossUNCs := extractIOCPatterns(allStrings)

	sandboxStaticIPs := map[string]bool{}
	sandboxStaticDomains := map[string]bool{}
	sandboxStaticURLs := map[string]bool{}
	sandboxStaticUNCs := map[string]bool{}
	sandboxDynamicIPs := map[string]bool{}
	sandboxDynamicDomains := map[string]bool{}
	sandboxDynamicURLs := map[string]bool{}
	for _, run := range sandboxRuns {
		for _, v := range run.IOCs.StaticRemoteIPs {
			sandboxStaticIPs[v] = true
		}
		for _, v := range run.IOCs.StaticDNSDomains {
			sandboxStaticDomains[v] = true
		}
		for _, v := range run.IOCs.StaticDownloadURLs {
			sandboxStaticURLs[v] = true
		}
		for _, v := range run.IOCs.StaticUNCPaths {
			sandboxStaticUNCs[v] = true
		}
		for _, v := range run.NetworkSummary.RemoteIPs {
			sandboxDynamicIPs[v] = true
		}
		for _, v := range run.NetworkSummary.DNSQueries {
			sandboxDynamicDomains[v] = true
		}
		for _, v := range run.IOCs.DownloadURLs {
			sandboxDynamicURLs[v] = true
		}
	}

	c.IPs = correlateIOCSet(flossIPs, sandboxStaticIPs, sandboxDynamicIPs)
	c.Domains = correlateIOCSet(flossDomains, sandboxStaticDomains, sandboxDynamicDomains)
	c.URLs = correlateIOCSet(flossURLs, sandboxStaticURLs, sandboxDynamicURLs)
	c.UNCPaths = correlateIOCSet(flossUNCs, sandboxStaticUNCs, nil)
	return c
}

// confirmedMaliciousIPs (#914) scans every Ghidra result with a real
// Windows-sandbox run and returns the union of every ConfirmedAtRuntime IP
// across all of them -- the same per-sample floss/sandbox correlation
// ghidraData() already computes for a single Detail row, run over the whole
// result set instead. Purely informational context on /investigate/ip/{ip}
// (docs/dashboard-manual-ip-block-design.md decision 1: the manual block
// action itself is not gated on this, an operator's own judgment is), not
// hot-path code, so it is computed fresh on every call rather than cached --
// same reasoning correlateFlossSandboxIOCs' own doc comment already gives.
//
// loadSandboxResults() once, not matchingSandboxRuns() per result: that
// helper is written for ghidraData()'s single-Detail-row case, where it
// runs exactly once per page view and its own full reload is the
// established cost of that page. Calling it from inside this function's
// own loop over every Ghidra result would mean N full reloads of the
// entire sandbox corpus (each itself an ES query against
// sandbox-analysis-v1, up to 10000 docs) for N Ghidra results -- an N+1
// query pattern that gets slower on every single /investigate/ip/{ip} page
// view as the corpus grows, not a one-time cost. Group once instead.
func confirmedMaliciousIPs() map[string]bool {
	bySHA256 := map[string][]sandboxResult{}
	for _, run := range loadSandboxResults() {
		bySHA256[run.SHA256] = append(bySHA256[run.SHA256], run)
	}
	out := map[string]bool{}
	for _, res := range loadGhidraResults() {
		runs := bySHA256[res.SHA256]
		if len(runs) == 0 {
			continue
		}
		c := correlateFlossSandboxIOCs(res.Floss, runs)
		if c == nil {
			continue
		}
		for _, ip := range c.IPs.ConfirmedAtRuntime {
			out[ip] = true
		}
	}
	return out
}

func ipIsConfirmedMalicious(ip string) bool {
	return confirmedMaliciousIPs()[ip]
}
