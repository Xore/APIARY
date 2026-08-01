package main

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// capturedFile is one unique artifact from any configured payload source.
type capturedFile struct {
	Hash         string
	Size         int64
	SizeH        string
	Mtime        string
	MIME         string
	Kind         string
	KindCode     string
	Platform     string
	AnalysisPath string
	Dynamic      bool
	Sources      []string
	Copies       int
	// Preview and PreviewTruncated back the /payloads list "Preview" action
	// (#59): a hex dump of the same file head already read for MIME
	// sniffing below, capped further to payloadPreviewCap so the row stays
	// cheap to render. The byte read here is real (this is not the deeper
	// io.ReadAll(analysisReadCap) analyzePayload does for /payload-analysis/),
	// it is just bounded much smaller because every visible row pays this
	// cost on every scan, not one file on demand.
	Preview          string
	PreviewTruncated bool
}

// payloadPreviewCap bounds the /payloads list preview action -- distinct
// from and much smaller than analysisReadCap (payload_analysis.go), which
// backs the deliberate, one-file-at-a-time /payload-analysis/ detail page.
const payloadPreviewCap = 512

type payloadSourceStat struct {
	Name   string
	Count  int
	Link   string
	Active bool
}

type payloadsPage struct {
	pageMeta
	Generated   time.Time
	Enabled     bool
	Loading     bool
	Files       []capturedFile
	Sources     []payloadSourceStat
	Filter      string
	ResultTotal int
	UniqueTotal int
	TotalH      string
	Notice      string
}

func payloadSourceName(dir string) string {
	lower := strings.ToLower(filepath.ToSlash(dir))
	switch {
	case strings.Contains(lower, "dionaea"):
		return "dionaea"
	case strings.Contains(lower, "cowrie"):
		return "cowrie"
	case strings.Contains(lower, "script"):
		return "scripts"
	default:
		name := strings.TrimSpace(filepath.Base(filepath.Clean(dir)))
		if name == "" || name == "." || name == string(filepath.Separator) {
			return "payloads"
		}
		return name
	}
}

// payloadsData inventories all configured capture directories recursively,
// merges identical hash-addressed artifacts, and preserves every contributing
// source. Dionaea binaries, Cowrie transfers, and retained inline scripts are
// therefore visible in one page instead of being presented as Dionaea-only.
func (s *store) payloadsData(filter string) payloadsPage {
	filter = strings.ToLower(strings.TrimSpace(filter))
	s.refreshPayloadCacheAsync()
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	base := s.payloadCache
	p := payloadsPage{
		Generated: time.Now(), Enabled: len(s.payloadDirs) != 0,
		Loading: s.payloadCacheAt.IsZero() && s.payloadRefreshing,
		Filter:  filter, UniqueTotal: base.UniqueTotal,
		Sources: append([]payloadSourceStat(nil), base.Sources...),
	}
	for i := range p.Sources {
		p.Sources[i].Active = p.Sources[i].Name == filter
	}
	var total int64
	for _, file := range base.Files {
		if filter != "" {
			matched := false
			for _, source := range file.Sources {
				if source == filter {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		p.Files = append(p.Files, file)
		total += file.Size
	}
	p.ResultTotal = len(p.Files)
	p.TotalH = humanBytes(total)
	return p
}

const payloadCacheTTL = 2 * time.Minute

// refreshPayloadCacheAsync keeps slow volume walks off the HTTP request path.
// Existing inventory remains available while a refresh is running.
func (s *store) refreshPayloadCacheAsync() {
	s.payloadMu.Lock()
	if s.payloadRefreshing || (!s.payloadCacheAt.IsZero() && time.Since(s.payloadCacheAt) < payloadCacheTTL) {
		s.payloadMu.Unlock()
		return
	}
	s.payloadRefreshing = true
	s.payloadMu.Unlock()
	go func() {
		fresh := s.scanPayloads()
		s.payloadMu.Lock()
		s.payloadCache = fresh
		s.payloadCacheAt = time.Now()
		s.payloadRefreshing = false
		s.payloadMu.Unlock()
	}()
}

func (s *store) payloadInventoryLoop() {
	s.refreshPayloadCacheAsync()
	ticker := time.NewTicker(payloadCacheTTL)
	defer ticker.Stop()
	for range ticker.C {
		s.refreshPayloadCacheAsync()
	}
}

func (s *store) scanPayloads() payloadsPage {
	p := payloadsPage{Generated: time.Now(), Enabled: len(s.payloadDirs) != 0}
	if len(s.payloadDirs) == 0 {
		return p
	}
	files := map[string]*capturedFile{}
	sourceSets := map[string]map[string]bool{}
	sourceCounts := map[string]int{}
	for _, dir := range s.payloadDirs {
		source := payloadSourceName(dir)
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || !hashName.MatchString(d.Name()) {
				return nil
			}
			fi, err := d.Info()
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			hash := strings.ToLower(d.Name())
			if sourceSets[hash] == nil {
				sourceSets[hash] = map[string]bool{}
			}
			if !sourceSets[hash][source] {
				sourceSets[hash][source] = true
				sourceCounts[source]++
			}
			if existing := files[hash]; existing != nil {
				existing.Copies++
				if modified := fi.ModTime().Format("2006-01-02 15:04"); modified > existing.Mtime {
					existing.Mtime = modified
				}
				return nil
			}
			mime := "application/octet-stream"
			classification := classifyPayload(nil)
			var preview string
			if f, err := os.Open(path); err == nil {
				head := make([]byte, 64<<10)
				n, _ := f.Read(head)
				f.Close()
				head = head[:n]
				mime = http.DetectContentType(head)
				classification = classifyPayload(head)
				previewBytes := head
				if len(previewBytes) > payloadPreviewCap {
					previewBytes = previewBytes[:payloadPreviewCap]
				}
				preview = hex.Dump(previewBytes)
			}
			files[hash] = &capturedFile{
				Hash: hash, Size: fi.Size(), SizeH: humanBytes(fi.Size()),
				Mtime: fi.ModTime().Format("2006-01-02 15:04"), MIME: mime,
				Kind: classification.Label, KindCode: classification.Code,
				Platform: classification.Platform, AnalysisPath: classification.AnalysisPath,
				Dynamic: classification.Dynamic, Copies: 1,
				Preview: preview, PreviewTruncated: fi.Size() > payloadPreviewCap,
			}
			return nil
		})
	}
	var total int64
	for hash, file := range files {
		for source := range sourceSets[hash] {
			file.Sources = append(file.Sources, source)
		}
		sort.Strings(file.Sources)
		p.UniqueTotal++
		total += file.Size
		p.Files = append(p.Files, *file)
	}
	for source, count := range sourceCounts {
		p.Sources = append(p.Sources, payloadSourceStat{
			Name: source, Count: count, Link: "/payloads?source=" + url.QueryEscape(source),
		})
	}
	sort.Slice(p.Sources, func(i, j int) bool { return p.Sources[i].Name < p.Sources[j].Name })
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Mtime > p.Files[j].Mtime })
	p.TotalH = humanBytes(total)
	return p
}

// servePayload streams one captured binary as a download. The hash is validated
// against hashName so the path can never escape binDir.
func (s *store) servePayload(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if len(s.payloadDirs) == 0 {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/payload/")
	if !hashName.MatchString(name) {
		http.Error(w, "invalid payload id", http.StatusBadRequest)
		return
	}
	path, err := s.payloadPath(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	// Force a download of an inert blob — never let a browser sniff/run it.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.malware.bin"`)
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
