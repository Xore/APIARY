package main

// Local GeoIP/ASN enrichment. MMDB is preferred and supports IPv4/IPv6,
// country, city, coordinates, accuracy radius, ASN and organization. The
// original start,end,country CSV reader remains as a dependency-free fallback.

import (
	"encoding/csv"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type geoInfo struct {
	Country  string  `json:"country,omitempty"`
	City     string  `json:"city,omitempty"`
	Lat      float64 `json:"lat,omitempty"`
	Lon      float64 `json:"lon,omitempty"`
	Accuracy uint16  `json:"accuracy_km,omitempty"`
	ASN      uint    `json:"asn,omitempty"`
	Org      string  `json:"organization,omitempty"`
	Provider string  `json:"provider_type,omitempty"`
	Intel    string  `json:"intel,omitempty"`
}

type geoRange struct {
	start, end uint32
	cc         string
}

type intelPrefix struct {
	prefix netip.Prefix
	label  string
}

type geoDB struct {
	ranges []geoRange
	city   *maxminddb.Reader
	asn    *maxminddb.Reader

	// intel is guarded separately from the rest of geoDB (which is immutable
	// after construction): threatIntelReloadLoop swaps it in place whenever
	// refresh-threat-cidrs.sh (#244) rewrites intelPath on disk, so a
	// scheduled refresh takes effect without a dashboard restart.
	intelMu   sync.RWMutex
	intel     []intelPrefix
	intelPath string
	intelMod  time.Time
}

type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		AccuracyRadius uint16  `maxminddb:"accuracy_radius"`
		Latitude       float64 `maxminddb:"latitude"`
		Longitude      float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

func loadGeoMMDB(cityPath, asnPath, intelPath string) (*geoDB, error) {
	g := &geoDB{}
	var err error
	if cityPath != "" {
		g.city, err = maxminddb.Open(cityPath)
		if err != nil {
			return nil, err
		}
	}
	if asnPath != "" {
		g.asn, err = maxminddb.Open(asnPath)
		if err != nil {
			if g.city != nil {
				g.city.Close()
			}
			return nil, err
		}
	}
	if g.city == nil && g.asn == nil {
		return nil, errors.New("no MMDB path configured")
	}
	g.intelPath = intelPath
	g.intel = loadIntelCIDRs(intelPath)
	if intelPath != "" {
		if info, err := os.Stat(intelPath); err == nil {
			g.intelMod = info.ModTime()
		}
	}
	return g, nil
}

// threatIntelReloadInterval is how often threatIntelReloadLoop polls
// intelPath's mtime. refresh-threat-cidrs.sh (#244) runs at most daily, so
// this only needs to be frequent enough that a fresh refresh reaches the
// dashboard promptly, not frequent enough to race it.
const threatIntelReloadInterval = 15 * time.Minute

// threatIntelReloadLoop lets a scheduled refresh-threat-cidrs.sh run (#244)
// take effect without a dashboard restart -- THREAT_CIDRS_FILE is otherwise
// only ever read once, at startup. No-ops when intelPath is unset.
func (g *geoDB) threatIntelReloadLoop() {
	if g == nil || g.intelPath == "" {
		return
	}
	ticker := time.NewTicker(threatIntelReloadInterval)
	defer ticker.Stop()
	for range ticker.C {
		g.reloadIntelIfChanged()
	}
}

// reloadIntelIfChanged re-reads intelPath only when its mtime has moved since
// the last (re)load -- refresh-threat-cidrs.sh (#244) runs at most daily, so
// this is cheap to call on every tick rather than worth a filesystem watcher.
// A no-op when intelPath is unset (the plain CSV geoip.g backend never sets
// it) or unreadable, so a bad refresh never blanks out a working intel set.
func (g *geoDB) reloadIntelIfChanged() {
	if g == nil || g.intelPath == "" {
		return
	}
	info, err := os.Stat(g.intelPath)
	if err != nil || !info.ModTime().After(g.intelMod) {
		return
	}
	fresh := loadIntelCIDRs(g.intelPath)
	g.intelMu.Lock()
	g.intel, g.intelMod = fresh, info.ModTime()
	g.intelMu.Unlock()
}

func loadGeoCSV(path string) (*geoDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rd := csv.NewReader(f)
	rd.FieldsPerRecord, rd.ReuseRecord = -1, true
	var ranges []geoRange
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		if len(rec) < 3 {
			continue
		}
		lo, ok1 := ipToU32(rec[0])
		hi, ok2 := ipToU32(rec[1])
		if !ok1 || !ok2 || lo > hi || len(rec[2]) < 2 {
			continue
		}
		ranges = append(ranges, geoRange{lo, hi, strings.ToUpper(rec[2])})
	}
	if len(ranges) == 0 {
		return nil, errors.New("no IPv4 ranges parsed")
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	return &geoDB{ranges: ranges}, nil
}

func loadIntelCIDRs(path string) []intelPrefix {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	var out []intelPrefix
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		if len(rec) < 2 {
			continue
		}
		if p, err := netip.ParsePrefix(strings.TrimSpace(rec[0])); err == nil {
			out = append(out, intelPrefix{p.Masked(), strings.TrimSpace(rec[1])})
		}
	}
	return out
}

func (g *geoDB) lookup(ip string) geoInfo {
	var out geoInfo
	if g == nil {
		return out
	}
	nip := net.ParseIP(ip)
	if nip == nil {
		return out
	}
	if g.city != nil {
		var r cityRecord
		if g.city.Lookup(nip, &r) == nil {
			out.Country = r.Country.ISOCode
			out.City = r.City.Names["en"]
			out.Lat, out.Lon, out.Accuracy = r.Location.Latitude, r.Location.Longitude, r.Location.AccuracyRadius
		}
	} else if v, ok := ipToU32(ip); ok {
		i := sort.Search(len(g.ranges), func(i int) bool { return g.ranges[i].start > v }) - 1
		if i >= 0 && v <= g.ranges[i].end {
			out.Country = g.ranges[i].cc
		}
	}
	if g.asn != nil {
		var r asnRecord
		if g.asn.Lookup(nip, &r) == nil {
			out.ASN, out.Org = r.Number, r.Org
			out.Provider = providerType(r.Org)
		}
	}
	if addr, err := netip.ParseAddr(ip); err == nil {
		addr = addr.Unmap()
		bestRank, bestBits := -1, -1
		g.intelMu.RLock()
		for _, p := range g.intel {
			if !p.prefix.Contains(addr) {
				continue
			}
			rank := intelCategoryRank(p.label)
			bits := p.prefix.Bits()
			// Highest severity wins regardless of file order (#244); on a tie,
			// the more specific (longer) prefix wins, matching ordinary CIDR
			// routing semantics -- a /32 blocklist entry inside a /16 range
			// from a broader feed should not be shadowed by the broader one.
			if rank > bestRank || (rank == bestRank && bits > bestBits) {
				out.Intel, bestRank, bestBits = p.label, rank, bits
			}
		}
		g.intelMu.RUnlock()
	}
	return out
}

// intelCategoryRank orders threat-cidrs.csv labels by severity so an address
// that falls inside more than one overlapping intel CIDR -- e.g. a Tor exit
// range that also happens to be reputation-listed -- resolves to the more
// severe label, not whichever entry happened to load first. See #244's
// malicious/neutral/benign taxonomy.
func intelCategoryRank(label string) int {
	switch {
	case strings.HasPrefix(label, "blocklist:"):
		return 2
	case label == "tor-exit":
		return 1
	default:
		return 0
	}
}

func providerType(org string) string {
	s := strings.ToLower(org)
	for _, needle := range []string{"censys", "shadowserver", "binaryedge", "securitytrails", "shodan", "internet measurement"} {
		if strings.Contains(s, needle) {
			return "scanner"
		}
	}
	for _, needle := range []string{"amazon", "google cloud", "microsoft", "azure", "digitalocean", "oracle cloud", "linode", "vultr", "cloudflare"} {
		if strings.Contains(s, needle) {
			return "cloud"
		}
	}
	for _, needle := range []string{"hosting", "server", "datacenter", "data center", "hetzner", "ovh", "colo", "leaseweb"} {
		if strings.Contains(s, needle) {
			return "hosting"
		}
	}
	if s != "" {
		return "network"
	}
	return ""
}

// intelBadgeClass maps an Intel/Provider label to a CSS badge modifier for
// events.html's origin badge (#244): a reputation-blocklist hit reads as a
// warning, a Tor exit is a real-but-not-inherently-malicious signal, and
// every other classification (cloud/scanner/hosting/network infrastructure)
// stays the existing neutral/informational styling.
func intelBadgeClass(label string) string {
	switch {
	case strings.HasPrefix(label, "blocklist:"):
		return "badge--danger"
	case label == "tor-exit":
		return "badge--warning"
	default:
		return "badge--muted"
	}
}

func ipToU32(s string) (uint32, bool) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return 0, false
	}
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), true
}
