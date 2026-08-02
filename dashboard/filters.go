package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// filter holds the /events query parameters. All set fields must match (AND).
type filter struct {
	ip, cidr, port, sensor, proto, path string // exact match, except CIDR containment
	persona, site, asset                string // exact honeypot identity metadata
	cred, cmd, session, shasum          string // exact match
	cat, country, city, client          string // exact match
	fingerprint, provider, org, asn     string // exact enriched metadata
	sig, q                              string // case-insensitive substring
	typ                                 string // login | command | alert | download
	// includeIPs (?ips=, repeatable) narrows a broader match -- typically
	// fingerprint -- down to specific source IPs (#278): unset means every
	// IP is shown, same as today; set means only these IPs are, so one IP
	// behind a fingerprint shared by many can be isolated from the rest.
	includeIPs []string
	since      time.Time
	sinceStr   string
	// family (?family=, #149) is not a storedEvent attribute the exact-match
	// checks above can compare directly -- it names a GitHub-analysis scanner
	// attribution, resolved up front by parseFilter into familyHashes (every
	// SHA-256 the pipeline attributed to it) and matched against e.Shasum.
	// family itself is kept only for chip display; matching always goes
	// through familyHashes, so this can never broaden into an arbitrary
	// substring/pattern test over event fields.
	family       string
	familyHashes map[string]bool
}

func parseFilter(r *http.Request) filter {
	v := r.URL.Query()
	f := filter{
		ip: v.Get("ip"), cidr: v.Get("cidr"), port: v.Get("port"), sensor: v.Get("sensor"),
		proto: v.Get("proto"), path: v.Get("path"), cred: v.Get("cred"),
		persona: v.Get("persona"), site: v.Get("site"), asset: v.Get("asset"),
		cmd: v.Get("cmd"), session: v.Get("session"), shasum: v.Get("shasum"),
		cat: v.Get("cat"), country: v.Get("country"), city: v.Get("city"), client: v.Get("client"),
		fingerprint: v.Get("fingerprint"), provider: v.Get("provider"), org: v.Get("org"), asn: v.Get("asn"),
		sig: v.Get("sig"), q: v.Get("q"), typ: v.Get("type"),
	}
	// A plain <input type="text" name="ips"> left empty still submits
	// "ips=" alongside any checked checkboxes of the same name -- drop
	// blanks rather than treating them as "match the empty IP".
	for _, ip := range v["ips"] {
		if ip = strings.TrimSpace(ip); ip != "" {
			f.includeIPs = append(f.includeIPs, ip)
		}
	}
	if d, err := time.ParseDuration(v.Get("since")); err == nil && d > 0 {
		f.since = time.Now().Add(-d)
		f.sinceStr = v.Get("since")
	}
	if family := strings.TrimSpace(v.Get("family")); family != "" {
		f.family = family
		f.familyHashes = githubAnalysisHashesForFamily(family)
	}
	return f
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func (f filter) match(e storedEvent) bool {
	if f.ip != "" && e.SrcIP != f.ip {
		return false
	}
	if len(f.includeIPs) > 0 && !slices.Contains(f.includeIPs, e.SrcIP) {
		return false
	}
	if f.cidr != "" {
		prefix, pErr := netip.ParsePrefix(f.cidr)
		addr, aErr := netip.ParseAddr(e.SrcIP)
		if pErr != nil || aErr != nil || !prefix.Contains(addr.Unmap()) {
			return false
		}
	}
	if f.port != "" && e.Port != f.port {
		return false
	}
	if f.sensor != "" && e.Sensor != f.sensor {
		return false
	}
	if f.proto != "" && e.Proto != f.proto {
		return false
	}
	if f.persona != "" && e.Persona != f.persona {
		return false
	}
	if f.site != "" && e.Site != f.site {
		return false
	}
	if f.asset != "" && e.Asset != f.asset {
		return false
	}
	if f.path != "" && e.Path != f.path {
		return false
	}
	if f.cred != "" && ((e.User == "" && e.Pass == "") || e.User+" / "+e.Pass != f.cred) {
		return false
	}
	if f.cmd != "" && e.Command != f.cmd {
		return false
	}
	if f.session != "" && e.Session != f.session {
		return false
	}
	if f.shasum != "" && e.Shasum != f.shasum {
		return false
	}
	if f.family != "" && !f.familyHashes[e.Shasum] {
		return false
	}
	if f.cat != "" && e.Category != f.cat {
		return false
	}
	if f.country != "" && e.Country != f.country {
		return false
	}
	if f.city != "" && e.City != f.city {
		return false
	}
	if f.client != "" && e.ClientVer != f.client {
		return false
	}
	if f.fingerprint != "" && e.Fingerprint != f.fingerprint {
		return false
	}
	if f.provider != "" && firstNonEmpty(e.Intel, e.Provider) != f.provider {
		return false
	}
	if f.org != "" && e.Org != f.org {
		return false
	}
	if f.asn != "" && strconv.FormatUint(uint64(e.ASN), 10) != strings.TrimPrefix(strings.ToUpper(f.asn), "AS") {
		return false
	}
	if f.sig != "" && (e.Alert == "" || !containsFold(e.Alert, f.sig)) {
		return false
	}
	switch f.typ {
	case "login":
		if !e.IsLogin {
			return false
		}
	case "command":
		if e.Command == "" {
			return false
		}
	case "alert":
		if e.Alert == "" {
			return false
		}
	case "download":
		if e.Shasum == "" {
			return false
		}
	}
	if !f.since.IsZero() && (e.when.IsZero() || e.when.Before(f.since)) {
		return false
	}
	if f.q != "" {
		blob := strings.Join([]string{e.SrcIP, e.Sensor, e.Detail, e.User, e.Pass,
			e.Command, e.Path, e.Alert, e.Session, e.Shasum, e.ClientVer, e.Fingerprint,
			e.FingerKind, e.Country, e.Org, e.Provider, e.Intel,
			e.Persona, e.Site, e.Asset, e.PersonaOrg}, " ")
		if !containsFold(blob, f.q) {
			return false
		}
	}
	return true
}

// describe renders the active filters as human-readable chips.
func (f filter) describe() []string {
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+" = "+v)
		}
	}
	add("ip", f.ip)
	add("network", f.cidr)
	add("port", f.port)
	add("sensor", f.sensor)
	add("proto", f.proto)
	add("path", f.path)
	add("persona", f.persona)
	add("site", f.site)
	add("asset", f.asset)
	add("credentials", f.cred)
	add("command", f.cmd)
	add("session", f.session)
	add("payload", shortHash(f.shasum))
	add("family", boundedFamily(f.family))
	add("category", f.cat)
	add("country", f.country)
	add("city", f.city)
	add("client", f.client)
	add("fingerprint", f.fingerprint)
	add("provider", f.provider)
	add("organization", f.org)
	add("ASN", f.asn)
	add("signature", f.sig)
	add("type", f.typ)
	add("search", f.q)
	if len(f.includeIPs) == 1 {
		add("isolated to ip", f.includeIPs[0])
	} else if len(f.includeIPs) > 1 {
		out = append(out, fmt.Sprintf("isolated to %d IPs", len(f.includeIPs)))
	}
	if f.sinceStr != "" {
		out = append(out, "last "+f.sinceStr)
	}
	return out
}

func (f filter) filtered(evs []storedEvent) []storedEvent {
	out := make([]storedEvent, 0, 64)
	for _, e := range evs {
		if f.match(e) {
			out = append(out, e)
		}
	}
	return out
}

// filterFieldOption is one <option> for a filterField whose Kind is
// "select" (#303) -- Value is what's submitted, Label is what's shown.
type filterFieldOption struct {
	Value string
	Label string
}

// filterSelectOptions classifies a shared filter-bar field as a small,
// fully-known, fixed enum (#303) -- a real <select> is strictly better than
// free text or a fetched autocomplete for these, since every possible value
// is already known statically and there's no reason to ever guess wrong.
// Keyed by the same query-param name buildFilterBar's callers already pass.
//
//   - event_type mirrors reports.html's own already-solved "type" field
//     (any/login/command/alert/download) -- ml-anomalies had the identical
//     concept as a plain text input until now.
//   - severity is worker.py's SEVERITY_BANDS (low/medium/high/critical).
//   - kind is exactly the 4 cluster kinds intelligence.go's clustersData
//     ever produces (Fingerprint/Payload/Autonomous system/Provider class)
//     -- confirmed by reading that switch directly, not assumed.
var filterSelectOptions = map[string][]filterFieldOption{
	"event_type": {
		{"", "any"}, {"login", "login"}, {"command", "command"},
		{"alert", "alert"}, {"download", "download"},
	},
	"severity": {
		{"", "any"}, {"low", "low"}, {"medium", "medium"},
		{"high", "high"}, {"critical", "critical"},
	},
	"kind": {
		{"", "any"}, {"Fingerprint", "Fingerprint"}, {"Payload", "Payload"},
		{"Autonomous system", "Autonomous system"}, {"Provider class", "Provider class"},
	},
}

// filterAutocompleteFields marks which shared filter-bar fields are backed
// by real, currently-existing values worth fetching from
// /api/filter-values (#303) -- see that file's filterValueFields, which
// this must stay in sync with (both keyed by the same field name).
var filterAutocompleteFields = map[string]bool{
	"sensor": true, "country": true, "asn": true, "ip": true, "port": true, "sig": true,
}

// filterField is one input control for the shared filter-bar template
// partial (#280 Phase 4): a query-param name, a human label, and the
// current value from the request, so the form round-trips pre-filled.
// Kind/Options (#303) let buildFilterBar upgrade a field to a real <select>
// (Kind == "select") or an autocomplete-enabled text input (Kind ==
// "autocomplete") automatically, purely from its Name -- existing callers
// never need to change to get this.
type filterField struct {
	Name    string
	Label   string
	Value   string
	Kind    string // "text" (default) | "select" | "autocomplete"
	Options []filterFieldOption
}

// filterBar is embedded by every page that gets the shared filter-bar UI:
// the visible fields, hidden fields preserving every other currently active
// query parameter (a GET form submission replaces the whole query string
// with just its own fields, same reasoning as #278's includeIPs form), the
// form's action URL, and a reset link populated only when at least one
// field is currently set.
type filterBar struct {
	FilterFields   []filterField
	FilterHidden   []queryPair
	FilterAction   string
	FilterResetURL string
}

// buildFilterBar constructs a filterBar for a request, given the page's own
// path and an ordered list of {query param, label} pairs.
func buildFilterBar(r *http.Request, action string, specs ...[2]string) filterBar {
	v := r.URL.Query()
	fields := make([]filterField, 0, len(specs))
	names := make([]string, 0, len(specs))
	active := false
	for _, s := range specs {
		val := v.Get(s[0])
		if val != "" {
			active = true
		}
		field := filterField{Name: s[0], Label: s[1], Value: val, Kind: "text"}
		if opts, ok := filterSelectOptions[s[0]]; ok {
			field.Kind = "select"
			field.Options = opts
		} else if filterAutocompleteFields[s[0]] {
			field.Kind = "autocomplete"
		}
		fields = append(fields, field)
		names = append(names, s[0])
	}

	hiddenQuery := r.URL.Query()
	for _, n := range names {
		hiddenQuery.Del(n)
	}
	var hidden []queryPair
	for key, values := range hiddenQuery {
		for _, val := range values {
			hidden = append(hidden, queryPair{Key: key, Value: val})
		}
	}

	resetURL := ""
	if active {
		resetQuery := r.URL.Query()
		for _, n := range names {
			resetQuery.Del(n)
		}
		resetURL = action
		if encoded := resetQuery.Encode(); encoded != "" {
			resetURL += "?" + encoded
		}
	}

	return filterBar{FilterFields: fields, FilterHidden: hidden, FilterAction: action, FilterResetURL: resetURL}
}
