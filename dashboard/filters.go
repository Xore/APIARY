package main

import (
	"net/http"
	"net/netip"
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
	since                               time.Time
	sinceStr                            string
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
	if d, err := time.ParseDuration(v.Get("since")); err == nil && d > 0 {
		f.since = time.Now().Add(-d)
		f.sinceStr = v.Get("since")
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
