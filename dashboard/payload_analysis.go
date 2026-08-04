package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

const analysisReadCap = 16 << 20

// hashPathMissTTL (#516) bounds how long payloadPathBySHA256 trusts a
// "scanned every payloadDir, found nothing" result before paying for another
// full content-hash scan. Without this, a hash that will never resolve --
// deleted, pruned, or (as in the bug report) a sandbox smoke-test sample
// that was never captured to begin with -- re-triggers the full scan (#364:
// confirmed live as a 45s+ hang for one real payload) on every single page
// view that references it: the sandbox report page, static analysis, the
// workbench, every submission route. Short enough that a payload captured
// moments after a failed lookup becomes visible again within one browsing
// session, long enough that repeatedly reloading the same still-missing
// page (the exact reported pattern) stays fast.
const hashPathMissTTL = 5 * time.Minute

type decodedArtifact struct {
	Kind    string
	Source  string
	Preview string
}

type ruleMatch struct {
	Name, Severity, Description string
}

type binaryAnalysis struct {
	pageMeta
	Hash           string
	Size           string
	MIME           string
	Magic          string
	Classification payloadClassification
	MD5            string
	SHA1           string
	SHA256         string
	Entropy        string
	EntropyValue   float64
	PackedLikely   bool
	RiskScore      int
	RiskLevel      string
	Truncated      bool
	Hexdump        string
	ASCII          []string
	UTF16          []string
	FormatInfo     []string
	Decoded        []decodedArtifact
	ScriptType     string
	Indicators     []string
	IOCs           []string
	Rules          []ruleMatch
	YARAMatches    []string
	YARAScanned    string
	YARAError      string
	SandboxRuns    []sandboxResult
	GitHubAnalysis *githubAnalysisResult
	VT             string
	// OriginLabel/OriginLink mirror capturedFile's fields of the same name
	// (payloads_data.go) -- see earliestEventByShasum for how these are
	// recovered from the event feed rather than stored with the capture.
	OriginLabel string
	OriginLink  string
	// Family/FamilyLink mirror capturedFile's fields of the same name (#149):
	// Family is GitHubAnalysis.Family bounded for display (the template
	// renders this, not GitHubAnalysis.Family directly, so a pathological
	// upstream value can't blow out the card); FamilyLink is the
	// /events?family= pivot to every other session that delivered this
	// attribution.
	Family     string
	FamilyLink string
	// Correlation is #354's "ask the backend if this hash is known" answer
	// -- notably including Ghidra, which nothing else on this page surfaces
	// today (SandboxRuns/GitHubAnalysis above are each queried ad hoc;
	// Correlation is the first place all three, plus Elasticsearch sighting
	// history, are checked together). Advisory only: never blocks anything,
	// just tells the operator what already exists before they submit a new
	// analysis run.
	Correlation hashCorrelation
}

// payloadStaticAnalysis is the subset of binaryAnalysis that is a pure
// function of one file's bytes -- hashes, entropy, extracted artifacts,
// static risk scoring -- as opposed to YARA/sandbox/GitHub-analysis/origin
// data, which can change over time for the same file and must always be
// read fresh. #352: computing this static half means reading the full file
// (MD5/SHA1/SHA256 over the whole thing) plus regex-based artifact and IOC
// extraction over up to 4-16 MiB -- real, bounded work, but wasted when the
// exact same file is viewed again, which is the common case (a payload
// looked at more than once across the workbench, reports, and events
// pages). Cached by store.staticAnalysisFor, keyed on a cheap path+size+
// mtime fingerprint rather than content hash, since the hash itself is part
// of what this computes.
type payloadStaticAnalysis struct {
	Size, MIME, Magic       string
	Classification          payloadClassification
	MD5, SHA1, SHA256       string
	Entropy                 string
	EntropyValue            float64
	PackedLikely, Truncated bool
	Hexdump                 string
	ASCII, UTF16            []string
	VT                      string
	FormatInfo              []string
	Decoded                 []decodedArtifact
	ScriptType              string
	Indicators, IOCs        []string
	Rules                   []ruleMatch
	StaticRiskScore         int
	StaticRiskLevel         string
}

// staticAnalysisIndex (#494-pattern, no local fallback) replaces the
// previous per-process staticAnalysisCache map: two dashboard instances (or
// one restarting) used to each recompute the same hashing/entropy/strings/
// IOC work from scratch. Keyed by the payload's own hash (the filename
// capture already enforces via hashName, not a freshly recomputed SHA256 --
// see the comment on staticAnalysisFor below for why that matters for
// cross-instance cache hits), not by filesystem path: two instances can
// mount the same logical capture under different paths, and keying by path
// would silently never hit across them. The document only ever holds the
// bounded-size analysis summary (hex dump preview capped at 512 bytes,
// capped string/IOC lists) -- never raw payload bytes, enforced structurally
// by docIndex's own size guard.
const staticAnalysisIndex = "dashboard-static-analysis-v1"

type staticAnalysisCacheDoc struct {
	Fingerprint string
	Analysis    payloadStaticAnalysis
}

func fileFingerprint(fi os.FileInfo) string {
	return fmt.Sprintf("%d-%d", fi.Size(), fi.ModTime().UnixNano())
}

func (s *store) staticAnalysisFor(path string) (payloadStaticAnalysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return payloadStaticAnalysis{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return payloadStaticAnalysis{}, errors.New("payload is not a regular file")
	}
	fingerprint := fileFingerprint(fi)
	// The capture pipeline names every payload file by its own hash
	// (hashName enforces this everywhere else that resolves a payload path,
	// e.g. analyzePayload/payloadPath) -- using that name as the cache key
	// means two dashboard instances with the same payload under different
	// mount paths still share one cache entry, unlike a path-keyed cache.
	hash := strings.ToLower(filepath.Base(path))
	cacheable := s != nil && s.es != nil && hashName.MatchString(hash)
	var seqNo, primaryTerm int64
	var cacheFound bool
	if cacheable {
		if hit, found, err := s.es.docGet(staticAnalysisIndex, hash); err == nil {
			cacheFound, seqNo, primaryTerm = found, hit.SeqNo, hit.PrimaryTerm
			if found {
				var cached staticAnalysisCacheDoc
				if json.Unmarshal(hit.Source, &cached) == nil && cached.Fingerprint == fingerprint {
					return cached.Analysis, nil
				}
			}
		}
	}
	h1, h2, h3 := md5.New(), sha1.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(h1, h2, h3), f); err != nil {
		return payloadStaticAnalysis{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return payloadStaticAnalysis{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, analysisReadCap))
	if err != nil {
		return payloadStaticAnalysis{}, err
	}
	preview := data
	if len(preview) > 512 {
		preview = preview[:512]
	}
	entropy := shannonEntropy(data)
	classification := classifyPayload(data)
	a := payloadStaticAnalysis{
		Size: humanBytes(fi.Size()), MIME: http.DetectContentType(data), Magic: magicName(data),
		Classification: classification,
		MD5:            hex.EncodeToString(h1.Sum(nil)), SHA1: hex.EncodeToString(h2.Sum(nil)), SHA256: hex.EncodeToString(h3.Sum(nil)),
		Entropy: fmt.Sprintf("%.3f bits/byte", entropy), EntropyValue: entropy, PackedLikely: entropy >= 7.2, Truncated: fi.Size() > analysisReadCap,
		Hexdump: hex.Dump(preview), ASCII: extractASCII(data, 4, 160), UTF16: extractUTF16LE(data, 4, 80),
		VT: "https://www.virustotal.com/gui/file/" + hex.EncodeToString(h3.Sum(nil)),
	}
	a.FormatInfo = executableMetadata(data)
	a.Decoded = decodeArtifacts(data, append(append([]string{}, a.ASCII...), a.UTF16...))
	a.ScriptType, a.Indicators = scriptMetadata(data)
	if a.ScriptType == "" && classification.Category == "script" {
		a.ScriptType = classification.Label
	}
	a.IOCs = extractIOCs(data)
	a.Rules, a.StaticRiskScore, a.StaticRiskLevel = payloadRules(a, data)
	if cacheable {
		if body, err := json.Marshal(staticAnalysisCacheDoc{Fingerprint: fingerprint, Analysis: a}); err == nil {
			// Best-effort: a lost race against a concurrent analysis of the
			// same file (or a write that exceeds docIndexMaxBytes on some
			// unusually artifact-heavy sample) just means the next call
			// recomputes and tries again -- this is a disposable cache, not
			// state anything else depends on being durable.
			_ = s.es.docIndex(staticAnalysisIndex, hash, body, !cacheFound, seqNo, primaryTerm)
		}
	}
	return a, nil
}

func (s *store) analyzePayload(name string) (binaryAnalysis, error) {
	if len(s.payloadDirs) == 0 || !hashName.MatchString(name) {
		return binaryAnalysis{}, errors.New("invalid or unavailable payload")
	}
	path, err := s.payloadPath(name)
	if err != nil {
		return binaryAnalysis{}, err
	}
	static, err := s.staticAnalysisFor(path)
	if err != nil {
		return binaryAnalysis{}, err
	}
	a := binaryAnalysis{
		Hash: name, Size: static.Size, MIME: static.MIME, Magic: static.Magic, Classification: static.Classification,
		MD5: static.MD5, SHA1: static.SHA1, SHA256: static.SHA256,
		Entropy: static.Entropy, EntropyValue: static.EntropyValue, PackedLikely: static.PackedLikely, Truncated: static.Truncated,
		Hexdump: static.Hexdump, ASCII: static.ASCII, UTF16: static.UTF16, VT: static.VT,
		FormatInfo: static.FormatInfo, Decoded: static.Decoded, ScriptType: static.ScriptType, Indicators: static.Indicators, IOCs: static.IOCs,
		Rules: static.Rules, RiskScore: static.StaticRiskScore, RiskLevel: static.StaticRiskLevel,
	}
	yara := s.yaraFor(name)
	a.YARAMatches, a.YARAScanned, a.YARAError = yara.Matches, yara.ScannedAt, yara.Error
	for _, run := range loadSandboxResults() {
		if strings.EqualFold(run.SHA256, a.SHA256) {
			a.SandboxRuns = append(a.SandboxRuns, run)
		}
	}
	for _, result := range loadGitHubAnalysisResults() {
		if strings.EqualFold(result.SHA256, a.SHA256) {
			row := result
			a.GitHubAnalysis = &row
			if row.Family != "" {
				a.Family = boundedFamily(row.Family)
				a.FamilyLink = eventsURL(url.Values{"family": {row.Family}})
			}
			break
		}
	}
	if origin, ok := earliestEventByShasum(s.getEvents())[a.SHA256]; ok {
		a.OriginLabel = origin.Sensor + " · " + origin.Time
		if origin.Session != "" {
			a.OriginLink = "/sessions/" + url.PathEscape(origin.Session)
		}
	}
	// a.Hash is whatever identifier addressed this payload on disk -- for a
	// Dionaea capture that's an MD5 (#364), distinct from a.SHA256 (the true
	// content hash computed above, what Ghidra/sandbox/GitHub-analysis key
	// their own results by). Passing both lets the Elasticsearch side match
	// on either; local-store matching only ever uses the true SHA-256.
	a.Correlation = s.correlateHash(a.SHA256, a.Hash)
	if len(a.YARAMatches) > 0 {
		boost := 25
		for _, match := range a.YARAMatches {
			if strings.Contains(strings.ToLower(match), "reverse_shell") || strings.Contains(strings.ToLower(match), "encoded_execution") {
				boost = 40
				break
			}
		}
		a.RiskScore = min(100, a.RiskScore+boost)
		a.RiskLevel = riskLevel(a.RiskScore)
	}
	return a, nil
}

func riskLevel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

func payloadRules(a payloadStaticAnalysis, data []byte) ([]ruleMatch, int, string) {
	lower := strings.ToLower(string(data[:min(len(data), 2<<20)]))
	var rules []ruleMatch
	score := 0
	add := func(name, severity, description string, points int) {
		rules = append(rules, ruleMatch{name, severity, description})
		score += points
	}
	if strings.Contains(a.Magic, "executable") || strings.Contains(a.Magic, "ELF") {
		add("executable_payload", "high", "Native PE or ELF executable content", 35)
	}
	if a.PackedLikely {
		add("high_entropy_content", "medium", "Entropy is consistent with compressed, encrypted, or packed content", 20)
	}
	if strings.Contains(lower, "powershell") && (strings.Contains(lower, "-enc") || strings.Contains(lower, "frombase64string")) {
		add("powershell_obfuscation", "high", "PowerShell with encoded or Base64-decoded content", 30)
	}
	if strings.Contains(lower, "wget ") || strings.Contains(lower, "curl ") || strings.Contains(lower, "invoke-webrequest") || strings.Contains(lower, "downloadstring") {
		add("network_downloader", "high", "Script retrieves additional content from the network", 25)
	}
	if strings.Contains(lower, "/dev/tcp/") || strings.Contains(lower, "nc -e") || strings.Contains(lower, "bash -i") || strings.Contains(lower, "socket.tcpclient") {
		add("reverse_shell_pattern", "critical", "Common reverse-shell primitives are present", 45)
	}
	if strings.Contains(lower, "authorized_keys") || strings.Contains(lower, "/etc/cron") || strings.Contains(lower, "schtasks") || strings.Contains(lower, "reg add ") {
		add("persistence_pattern", "high", "Persistence-related paths or commands are present", 30)
	}
	if len(a.Decoded) > 0 {
		add("encoded_embedded_content", "medium", "Decodable Base64 or hexadecimal content is embedded", 15)
	}
	if score > 100 {
		score = 100
	}
	return rules, score, riskLevel(score)
}

func extractIOCs(data []byte) []string {
	text := string(data[:min(len(data), 4<<20)])
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)https?://[^\s'"<>]{4,300}`),
		regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
		regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b`),
	}
	var out []string
	for _, pattern := range patterns {
		out = append(out, pattern.FindAllString(text, 80)...)
	}
	return uniqueStrings(out, 120)
}

func (s *store) payloadPath(name string) (string, error) {
	if !hashName.MatchString(name) {
		return "", errors.New("invalid payload id")
	}
	for _, dir := range s.payloadDirs {
		path := filepath.Join(dir, name)
		if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
			return path, nil
		}
		var found string
		filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.EqualFold(entry.Name(), name) {
				return nil
			}
			if fi, err := entry.Info(); err == nil && fi.Mode().IsRegular() {
				found = path
				return fs.SkipAll
			}
			return nil
		})
		if found != "" {
			return found, nil
		}
	}
	// A 64-char request is shaped like a SHA-256. Dionaea keeps its own
	// on-disk naming convention (MD5), unrelated to this pipeline, so a
	// SHA-256 -- the hash every other source and GitHub-analysis's own
	// report use -- never matches a Dionaea capture by filename alone
	// (#255's 404 report). resolve-sample.sh (analysis/github/) already
	// falls back to a full-content hash scan for exactly this case; only
	// worth the cost here for a request long enough to actually be one,
	// since a 32-char (MD5-length) request already matched above if it
	// exists at all.
	if len(name) == 64 {
		if path, err := s.payloadPathBySHA256(strings.ToLower(name)); err == nil {
			return path, nil
		}
	}
	return "", os.ErrNotExist
}

// payloadPathBySHA256 is the fallback for payload sources (Dionaea) that
// name captured files by MD5 rather than SHA-256, so a SHA-256-addressed
// lookup can never match by filename alone (#255). Resolving one means
// reading and hashing the full content of every file under every
// s.payloadDirs entry until a match turns up -- unbounded by size or count,
// and paid fresh on every uncached call. #364: for a Dionaea capture this
// fallback is not a rare edge case, it is the ONLY path, so every request
// for that payload (the workbench page, static analysis, ghidra/sandbox/
// GitHub-analysis submission, ...) paid the full scan -- confirmed live as
// a 45s+ hang for one real captured PE/DLL. Cache successful resolutions so
// repeat requests for the same hash -- exactly the reported pattern,
// clicking into the same result more than once -- are instant. A cache hit
// is still verified with a cheap stat before being trusted, since the
// underlying file can move or be pruned between requests.
//
// #516: a hash that will *never* resolve -- deleted, pruned, or never
// captured in the first place (e.g. a sandbox job seeded from a smoke-test
// sample rather than a real capture) -- has no successful resolution to
// cache, so every request paid the full scan again with no cache to ever
// break the cycle. hashPathMiss records "scanned, found nothing" for
// hashPathMissTTL so repeated requests for the same still-missing hash are
// cheap too, not just repeated requests for a found one.
func (s *store) payloadPathBySHA256(want string) (string, error) {
	if s != nil {
		s.hashPathMu.Lock()
		cached, ok := s.hashPathCache[want]
		missedAt, missed := s.hashPathMiss[want]
		s.hashPathMu.Unlock()
		if ok {
			if fi, err := os.Stat(cached); err == nil && fi.Mode().IsRegular() {
				return cached, nil
			}
			s.hashPathMu.Lock()
			delete(s.hashPathCache, want)
			s.hashPathMu.Unlock()
		}
		if missed && time.Since(missedAt) < hashPathMissTTL {
			return "", os.ErrNotExist
		}
	}
	var found string
	for _, dir := range s.payloadDirs {
		filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
			if found != "" {
				return fs.SkipAll
			}
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			fi, err := entry.Info()
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				return nil
			}
			if hex.EncodeToString(h.Sum(nil)) == want {
				found = path
				return fs.SkipAll
			}
			return nil
		})
		if found != "" {
			if s != nil {
				s.hashPathMu.Lock()
				if s.hashPathCache == nil {
					s.hashPathCache = make(map[string]string)
				}
				s.hashPathCache[want] = found
				delete(s.hashPathMiss, want)
				s.hashPathMu.Unlock()
			}
			return found, nil
		}
	}
	if s != nil {
		s.hashPathMu.Lock()
		if s.hashPathMiss == nil {
			s.hashPathMiss = make(map[string]time.Time)
		}
		s.hashPathMiss[want] = time.Now()
		s.hashPathMu.Unlock()
	}
	return "", os.ErrNotExist
}

func scriptMetadata(data []byte) (string, []string) {
	text := strings.TrimSpace(string(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	lower := strings.ToLower(text)
	kind := ""
	switch {
	case strings.HasPrefix(text, "#!") && (strings.Contains(lower[:min(len(lower), 100)], "sh") || strings.Contains(lower[:min(len(lower), 100)], "bash")):
		kind = "POSIX shell script"
	case strings.Contains(lower, ".sh") || regexp.MustCompile(`\b(?:ba|da|z|k)?sh\s+-c\b`).MatchString(lower):
		kind = "POSIX shell command/script"
	case strings.Contains(lower, "powershell") || strings.Contains(lower, "invoke-webrequest") || strings.Contains(lower, "new-object net.webclient") || strings.Contains(lower, "-encodedcommand"):
		kind = "PowerShell"
	case strings.Contains(lower, "createobject(") || strings.Contains(lower, "wscript.") || strings.Contains(lower, "cscript.exe"):
		kind = "VBScript"
	case strings.HasPrefix(text, "#!") && strings.Contains(lower[:min(len(lower), 100)], "python"):
		kind = "Python script"
	case strings.Contains(lower, "<?php"):
		kind = "PHP script"
	case strings.Contains(lower, "function(") || strings.Contains(lower, "require(") || strings.Contains(lower, "eval("):
		kind = "JavaScript-like script"
	}
	checks := []struct{ needle, label string }{
		{"curl ", "network downloader (curl)"}, {"wget ", "network downloader (wget)"},
		{"invoke-webrequest", "PowerShell web download"}, {"downloadstring", "PowerShell in-memory download"},
		{"frombase64string", "Base64 decoding"}, {"base64 -d", "Base64 decoding"},
		{"eval(", "dynamic code evaluation"}, {"iex ", "PowerShell Invoke-Expression"},
		{"/etc/cron", "cron persistence"}, {"authorized_keys", "SSH key persistence"},
		{"reg add ", "Windows registry modification"}, {"schtasks", "Windows scheduled-task persistence"},
		{"chmod +x", "marks downloaded file executable"}, {"rm -rf", "destructive file removal"},
	}
	var findings []string
	for _, c := range checks {
		if strings.Contains(lower, c.needle) {
			findings = append(findings, c.label)
		}
	}
	return kind, uniqueStrings(findings, 30)
}

func magicName(b []byte) string {
	switch {
	case len(b) >= 2 && string(b[:2]) == "MZ":
		return "Windows PE/DOS executable"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF executable/shared object"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{'P', 'K', 3, 4}):
		return "ZIP/JAR/Office archive (not unpacked)"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x7f, 0x45, 0x4c, 0x46}):
		return "ELF"
	case len(b) >= 2 && string(b[:2]) == "#!":
		return "script with interpreter shebang"
	case len(b) >= 4 && bytes.Equal(b[:4], []byte{0x89, 'P', 'N', 'G'}):
		return "PNG image"
	default:
		return "unknown/raw data"
	}
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / float64(len(b))
		h -= p * math.Log2(p)
	}
	return h
}

func extractASCII(b []byte, minLen, limit int) []string {
	var out []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minLen && len(out) < limit {
			out = append(out, string(b[start:end]))
		}
		start = -1
	}
	for i, c := range b {
		if c >= 0x20 && c <= 0x7e {
			if start < 0 {
				start = i
			}
		} else {
			flush(i)
		}
	}
	flush(len(b))
	return uniqueStrings(out, limit)
}

func extractUTF16LE(b []byte, minLen, limit int) []string {
	var out []string
	for offset := 0; offset < 2; offset++ {
		var run []uint16
		flush := func() {
			if len(run) >= minLen && len(out) < limit {
				out = append(out, string(utf16.Decode(run)))
			}
			run = nil
		}
		for i := offset; i+1 < len(b); i += 2 {
			u := uint16(b[i]) | uint16(b[i+1])<<8
			if u >= 0x20 && u <= 0x7e {
				run = append(run, u)
			} else {
				flush()
			}
		}
		flush()
	}
	return uniqueStrings(out, limit)
}

func uniqueStrings(in []string, limit int) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) == limit {
			break
		}
	}
	return out
}

func executableMetadata(data []byte) []string {
	var out []string
	if f, err := pe.NewFile(bytes.NewReader(data)); err == nil {
		out = append(out, fmt.Sprintf("PE machine: %#x", f.Machine), fmt.Sprintf("PE sections: %d", len(f.Sections)))
		for _, s := range f.Sections {
			out = append(out, fmt.Sprintf("section %s: virtual=%d raw=%d", s.Name, s.VirtualSize, s.Size))
		}
		if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
			sort.Strings(libs)
			out = append(out, "imports: "+strings.Join(libs, ", "))
		}
		return out
	}
	if f, err := elf.NewFile(bytes.NewReader(data)); err == nil {
		out = append(out, fmt.Sprintf("ELF class: %s", f.Class), fmt.Sprintf("ELF machine: %s", f.Machine), fmt.Sprintf("entry: 0x%x", f.Entry))
		for _, s := range f.Sections {
			if len(out) >= 40 {
				break
			}
			out = append(out, fmt.Sprintf("section %s: size=%d", s.Name, s.Size))
		}
	}
	return out
}

var (
	b64Pattern = regexp.MustCompile(`(?i)(?:[A-Za-z0-9+/]{4}){5,}(?:==|=)?`)
	hexPattern = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}){8,}\b`)
)

func decodeArtifacts(raw []byte, stringsFound []string) []decodedArtifact {
	joined := strings.Join(stringsFound, "\n")
	var out []decodedArtifact
	add := func(kind, source string, decoded []byte) {
		if len(decoded) == 0 || len(out) >= 40 {
			return
		}
		preview := printablePreview(decoded, 1000)
		if preview == "" {
			return
		}
		if len(source) > 120 {
			source = source[:120] + "…"
		}
		out = append(out, decodedArtifact{Kind: kind, Source: source, Preview: preview})
	}
	for _, token := range b64Pattern.FindAllString(joined, 30) {
		if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
			add("base64", token, decoded)
			if len(decoded)%2 == 0 {
				var units []uint16
				for i := 0; i+1 < len(decoded); i += 2 {
					units = append(units, uint16(decoded[i])|uint16(decoded[i+1])<<8)
				}
				add("base64 → UTF-16LE (PowerShell-compatible)", token, []byte(string(utf16.Decode(units))))
			}
		}
	}
	for _, token := range hexPattern.FindAllString(joined, 30) {
		if decoded, err := hex.DecodeString(token); err == nil {
			add("hex", token, decoded)
		}
	}
	if bytes.Contains(raw, []byte{'%'}) {
		for _, line := range stringsFound {
			if strings.Contains(line, "%") {
				if decoded, err := url.QueryUnescape(line); err == nil && decoded != line {
					add("URL percent encoding", line, []byte(decoded))
				}
			}
		}
	}
	return out
}

func printablePreview(b []byte, limit int) string {
	if len(b) > limit {
		b = b[:limit]
	}
	var out strings.Builder
	printable := 0
	for _, c := range b {
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			out.WriteByte(c)
			printable++
		case c >= 0x20 && c <= 0x7e:
			out.WriteByte(c)
			printable++
		default:
			out.WriteRune('·')
		}
	}
	if len(b) == 0 || printable*100/len(b) < 55 {
		return ""
	}
	return out.String()
}
