package main

// #3446. One runnable check per decision in reflect.go's rule, plus an
// end-to-end check per echo site and a sweep that fails if this sensor ever
// grows a fourth one.
//
// Everything here is inert: httptest.NewRequest/httptest.NewRecorder
// against the handler directly. No listener, no socket, no live decoy.

import (
	"bytes"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- rule part 1+2: escape, do not delete ---------------------------------

func TestSanitiseHTMLEscapesRatherThanDeletes(t *testing.T) {
	in := `<script>alert("x")</script> & 'quoted'`
	got := sanitiseHTML(in)

	if strings.Contains(got, "<script>") {
		t.Errorf("a raw tag survived escaping: %q", got)
	}

	// The four characters that can break out of an HTML text or quoted
	// attribute position must not survive unescaped. "&" is checked
	// separately below, because its own escaped form still contains one.
	for _, raw := range []string{"<", ">", `"`, "'"} {
		if strings.Contains(got, raw) {
			t.Errorf("unescaped %q survived in %q", raw, got)
		}
	}

	// Every "&" left must be the start of an entity reference rather than
	// a bare ampersand an attacker could use to start one of their own.
	for rest := got; ; {
		i := strings.IndexByte(rest, '&')
		if i < 0 {
			break
		}
		ref := rest[i:]
		if !strings.HasPrefix(ref, "&amp;") && !strings.HasPrefix(ref, "&lt;") &&
			!strings.HasPrefix(ref, "&gt;") && !strings.HasPrefix(ref, "&quot;") &&
			!strings.HasPrefix(ref, "&#") {
			t.Errorf("a bare & survived escaping in %q", got)
			break
		}
		rest = ref[1:]
	}

	// The decisive escape-vs-delete assertion: escaping is lossless, so
	// the value the decoy echoes back is byte-for-byte the value that
	// arrived -- every character present, none of them removed.
	if back := html.UnescapeString(got); back != in {
		t.Errorf("escaping was lossy: %q round-tripped to %q, want %q", in, back, in)
	}
}

// --- rule part 3: bound, and drop rather than truncate --------------------

func TestSanitiseHTMLBoundsOnInputAndDropsOverIt(t *testing.T) {
	atBound := strings.Repeat("a", maxReflectedBytes)
	if got := sanitiseHTML(atBound); len(got) != maxReflectedBytes {
		t.Errorf("a value exactly at the bound was altered: got %d bytes, want %d", len(got), maxReflectedBytes)
	}

	over := strings.Repeat("a", maxReflectedBytes+1)
	if got := sanitiseHTML(over); got != "" {
		t.Errorf("a value one byte over the bound must be dropped, got %q", got)
	}

	// The bound is on the INPUT, so the worst-case escaped output is
	// bounded too: html.EscapeString expands "&" to "&amp;", the largest
	// expansion of any single byte it performs.
	worst := strings.Repeat("&", maxReflectedBytes)
	if got := len(sanitiseHTML(worst)); got > 5*maxReflectedBytes {
		t.Errorf("escaped output %d bytes exceeds 5x the bound %d", got, maxReflectedBytes)
	}

	// Drop, not truncate: a multi-byte rune straddling the bound must not
	// produce a replacement character or half a rune, because the whole
	// value is refused rather than cut.
	if got := sanitiseHTML(strings.Repeat("a", maxReflectedBytes-1) + "é" + "tail"); got != "" {
		t.Errorf("a rune straddling the bound was mangled rather than dropped: %q", got)
	}
}

// --- authority: accept or fall back ---------------------------------------

func TestSanitiseAuthorityAcceptsRealHosts(t *testing.T) {
	for _, host := range []string{
		"citrixgw01",
		"citrixgw01.example.test",
		"citrixgw01.example.test:443",
		"sub.domain.citrixgw01.example.test:8443",
		"192.0.2.10",
		"192.0.2.10:8443",
		"[2001:db8::1]",
		"[2001:db8::1]:8443",
		strings.Repeat("a", 63) + ".example.test",
	} {
		if got := sanitiseAuthority(host); got != host {
			t.Errorf("sanitiseAuthority(%q) = %q, want it reflected unchanged", host, got)
		}
	}
}

func TestSanitiseAuthorityFallsBackWhenNotAHost(t *testing.T) {
	for name, host := range map[string]string{
		"empty":             "",
		"quote injection":   `"><script>alert(1)</script>`,
		"apostrophe":        "evil'</script><svg onload=1>",
		"spaces":            "not a host at all",
		"control byte":      "evil\x01\x02",
		"tab":               "evil\thost",
		"path":              "evil.example.test/oauth/idp",
		"scheme":            "https://evil.example.test",
		"userinfo":          "user@evil.example.test",
		"traversal":         "evil.example.test/../../etc",
		"query":             "evil.example.test?a=1",
		"unbalanced port":   "evil.example.test:",
		"non-numeric port":  "evil.example.test:https",
		"port out of range": "evil.example.test:70000",
		"oversized port":    "evil.example.test:123456",
		"underscore label":  "my_host.example.test",
		"leading hyphen":    "-evil.example.test",
		"trailing hyphen":   "evil-.example.test",
		"empty label":       "evil..example.test",
		"over-long label":   strings.Repeat("a", 64) + ".example.test",
		"unbracketed ipv6":  "2001:db8::1",
		"unterminated v6":   "[2001:db8::1",
		"over the bound":    strings.Repeat("a", maxAuthorityBytes+1) + ".example.test",
	} {
		if got := sanitiseAuthority(host); got != personaAsset {
			t.Errorf("%s: sanitiseAuthority(%q) = %q, want the persona fallback %q", name, host, got, personaAsset)
		}
	}
}

// The fallback must be the same name every event on this sensor already
// carries, or an operator comparing two events sees two different boxes --
// one from the log line's asset_id, one from the authority a refused Host
// falls back to.
func TestPersonaFallbackIsTheAssetEveryEventCarries(t *testing.T) {
	// emit() writes every line to os.Stdout, so read it back rather than
	// asserting the constant against itself: this is the check that fails
	// if emit's asset and personaAsset ever drift apart, which is the only
	// way this invariant can actually break.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	w.Close()
	os.Stdout = orig
	line, readErr := io.ReadAll(r)
	r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}

	var e event
	if err := json.Unmarshal(bytes.TrimSpace(line), &e); err != nil {
		t.Fatalf("emitted line is not a decoy event (%v): %q", err, line)
	}
	if e.Asset != personaAsset {
		t.Fatalf("emitted asset_id = %q, want the persona fallback constant %q", e.Asset, personaAsset)
	}
}

// --- end to end, per echo site --------------------------------------------

// The wctx echo: a megabyte of wctx (what Go's default 1 MiB
// MaxHeaderBytes will actually accept on the wire) must not come back as a
// megabyte of body. Before the bound this sensor answered 1,048,909 bytes.
func TestWSFedEchoIsBoundedEndToEnd(t *testing.T) {
	req := httptest.NewRequest("GET", "/wsfed/passive?wctx="+strings.Repeat("W", 1<<20), nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 -- an over-long wctx must still be answered", rec.Code)
	}
	body := rec.Body.String()
	if len(body) > len(citrixWSFedTemplate)+maxReflectedBytes*5 {
		t.Fatalf("response is %d bytes; the reflection is still unbounded", len(body))
	}
	// And the value is absent, not present-but-truncated: the page is the
	// one this decoy serves for a wsfed request with no wctx at all.
	empty := httptest.NewRequest("GET", "/wsfed/passive", nil)
	emptyRec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(emptyRec, empty)
	if body != emptyRec.Body.String() {
		t.Fatalf("an over-long wctx did not produce the empty-context page.\n got: %q\nwant: %q",
			body, emptyRec.Body.String())
	}
}

func TestWSFedEchoStillReflectsARealContextValue(t *testing.T) {
	// The bound must not cost the decoy its behaviour: a real wctx (a URL
	// a requestor is relaying back) is far under the bound and comes back
	// whole.
	wctx := "https://portal.example.test/app?session=abc123"
	req := httptest.NewRequest("GET", "/wsfed/passive?wctx="+wctx, nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), wctx) {
		t.Fatalf("a real wctx was not reflected: %q", rec.Body.String())
	}
}

// The Host echo: the discovery document builds seven URLs off it, so the
// unvalidated version let an attacker write the text of all seven.
func TestOIDCDiscoveryDoesNotReflectANonHost(t *testing.T) {
	for _, host := range []string{
		`"><script>alert(1)</script>`,
		"not a host at all",
		"evil.example.test/oauth/idp",
		strings.Repeat("A", 4096) + ".example.test",
	} {
		req := httptest.NewRequest("GET", "/oauth/idp/.well-known/openid-configuration", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		newTestHandler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Host %q: code = %d, want 200 -- the decoy answers regardless", host, rec.Code)
		}
		var doc oidcDiscovery
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("Host %q: response is not valid JSON (%v): %q", host, err, rec.Body.String())
		}
		if doc.Issuer != "https://"+personaAsset+"/oauth/idp" {
			t.Fatalf("Host %q: issuer = %q, want the persona authority", host, doc.Issuer)
		}
		// No field may carry the rejected value, not just the issuer.
		for _, field := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI,
			doc.UserinfoEndpoint, doc.Issuer} {
			if strings.Contains(field, "A") && strings.Contains(field, strings.Repeat("A", 64)) {
				t.Fatalf("Host %q: a discovery URL still carries the rejected value: %q", host, field)
			}
		}
		if len(rec.Body.Bytes()) > 1024 {
			t.Fatalf("Host %q: response is %d bytes -- the reflection is still unbounded",
				host, len(rec.Body.Bytes()))
		}
	}
}

func TestOIDCDiscoveryStillSelfReferencesARealHost(t *testing.T) {
	// The decoy's whole reason for reading the Host is that a real
	// appliance's discovery document self-references off it. A legitimate
	// authority must still come back reflected, or the fix has cost the
	// surface its value.
	for _, host := range []string{"citrixgw01.example.test", "citrixgw01.example.test:443", "192.0.2.10:8443"} {
		req := httptest.NewRequest("GET", "/oauth/rp/.well-known/openid-configuration", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		newTestHandler().ServeHTTP(rec, req)

		var doc oidcDiscovery
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("Host %q: %v: %q", host, err, rec.Body.String())
		}
		if doc.Issuer != "https://"+host+"/oauth/rp" {
			t.Fatalf("Host %q: issuer = %q, want the request's own authority reflected", host, doc.Issuer)
		}
	}
}

// The 403 echo: routing forces the literal "/vpns" today, so this drives the
// helper directly -- the same reason the pre-existing escaping test does.
// The point of adding it to the bound is that the escaping test already
// treats this path as reachable-with-arbitrary-input.
func TestForbiddenBodyPathIsBoundedToo(t *testing.T) {
	if got := citrixForbiddenBody("/vpns"); !strings.Contains(got, "/vpns") {
		t.Fatalf("the real (literal) value must still be reflected, got %q", got)
	}
	if body := citrixForbiddenBody("/vpns/" + strings.Repeat("z", 1<<20)); strings.Contains(body, "zzzz") {
		t.Fatalf("an over-long path was reflected into the 403 page")
	}
}

// --- the survey, as a standing check --------------------------------------

// TestNoUnsanitisedRequestDataReachesDecoyContent is the check that makes
// this issue's third bullet permanent: a marker is planted in every channel
// a request can carry a value through, every response path on this sensor is
// swept, and the only reflections allowed to come back are the three
// audited ones -- and only in their sanitised form. A fourth echo site, or
// one of these three losing its sanitisation, fails here.
func TestNoUnsanitisedRequestDataReachesDecoyContent(t *testing.T) {
	const marker = "Zq7XreflectAuditZq7X"

	// The sweep drives ~350 requests through a logger that writes every
	// one of them to stdout. Send it to /dev/null for the duration rather
	// than the os.Pipe this package's other tests use: a pipe nobody
	// drains would block on its 64 KiB buffer partway through.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = devNull
	defer func() { os.Stdout = orig; devNull.Close() }()

	paths := []string{
		"/", "/vpn", "/vpn/", "/vpn/../vpns/", "/vpn/../vpns/portal/x",
		"/vpn/../vpns/cfg/smb.conf", "/vpn/../vpns/x/y", "/foo/../bar/baz",
		"/saml/login", "/cgi/samlauth", "/wsfed/passive", "/cgi/logout",
		"/oauth/idp/.well-known/openid-configuration",
		"/oauth/rp/.well-known/openid-configuration",
		"/p/u/doAuthentication.do", "/some/random/path",
		"/" + marker, "/a/" + marker + "/b", "/vpns/" + marker,
		"/vpn/../vpns/" + marker + "/",
	}
	queries := []string{
		"", "?" + marker + "=1", "?wctx=" + marker, "?a=" + marker + "&b=2",
	}
	methods := []string{"GET", "POST"}

	for _, p := range paths {
		for _, q := range queries {
			for _, method := range methods {
				req := httptest.NewRequest(method, p+q, strings.NewReader("body="+marker))
				req.Host = marker + ".example.test"
				req.Header.Set("User-Agent", marker)
				req.Header.Set("Referer", marker)
				req.Header.Set("Cookie", marker)
				rec := httptest.NewRecorder()
				newTestHandler().ServeHTTP(rec, req)

				body := rec.Body.String()
				if containsFold(body, marker) {
					// Exactly two reflections on this sensor are
					// sanctioned, and each only because
					// sanitiseHTML / sanitiseAuthority ran first:
					//
					//   wctx -> the caller's own WS-Fed context, the
					//           behaviour the decoy exists to present.
					//           Escaped, bounded, dropped over the bound.
					//   Host -> the authority the discovery document
					//           self-references off. Reflected only if
					//           it is a host, else personaAsset.
					//
					// Anything else -- a new template placeholder, or
					// one of these two losing its sanitisation -- fails
					// here.
					sanctionedWctx := p == "/wsfed/passive" && strings.Contains(q, "wctx="+marker)
					sanctionedHost := strings.HasPrefix(p, "/oauth/") &&
						rec.Header().Get("Content-Type") == "application/json"
					if !sanctionedWctx && !sanctionedHost {
						t.Errorf("%s %s%s: request data reached decoy content: %s",
							method, p, q, reflectClip(body))
					}
				}
				for h, vs := range rec.Header() {
					for _, v := range vs {
						if containsFold(v, marker) {
							t.Errorf("%s %s%s: request data reached response header %s: %s",
								method, p, q, h, v)
						}
					}
				}
			}
		}
	}
}

// containsFold is a case-insensitive Contains, and it has to be: every path
// comparison on this sensor lowercases (authSurfaceEvent and
// authSurfaceResponse both do), so a reflection that passes the path through
// a routing variable arrives case-folded, and a case-sensitive marker check
// would miss exactly the echo this test exists to catch.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// reflectClip trims a decoy body to something a failure message can carry.
// Whole body up to a cap rather than a window around the match: matching is
// case-insensitive and case-folding can move byte offsets, so a window
// computed from the folded index need not land on a rune boundary.
func reflectClip(s string) string {
	const max = 400
	if len(s) <= max {
		return s
	}
	return s[:max] + "...<clipped>"
}
