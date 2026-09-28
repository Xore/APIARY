package main

import "testing"

// TestODataDoubleEncodeProbe pins #3430's one implementable layer: the
// double-encoding bypass (%2561 -> %61 -> 'a') of a method/path filter,
// aimed at an OData-style endpoint.
//
// #3430 is a research note, not a CVE, and no capture exists -- it names a
// public third-party investigation and a reproduced technique chain, not a
// request this fleet received. So the positives follow the published shapes
// and the negatives are real traffic from the pinned 30-day corpus: the
// WordPress pagename double-encodings and the %25ADd PHP-CGI probe are the
// entries a looser rule claims, and each of them keeps the more specific
// class it already had.
func TestODataDoubleEncodeProbe(t *testing.T) {
	const want = "odata-double-encode-probe"

	cases := []struct {
		name, query, body, want string
	}{
		// --- the published shape. %2520 is a space that only exists after
		// a second decode, which is the entire point: a filter that
		// survives one pass and means something after the next.
		{
			name:  "double-encoded $filter value",
			query: `$filter=year%2520eq%25202026`,
			want:  want,
		},
		{
			name:  "double-encoded $select, comma split across the decode",
			query: `$select=Year%252cValue`,
			want:  want,
		},
		// Both halves can arrive double-encoded, key included.
		{
			name:  "double-encoded option name and value",
			query: `%24filter=year%2520eq%25202026`,
			want:  want,
		},
		// A form body, not a query: the POST half of the same probe.
		{
			name: "double-encoded $filter in a form body",
			body: `$top=10&$filter=Year%2520eq%25202026`,
			want: want,
		},
		// OData defines a namespace-alias prefix on system options, so
		// `northwind.$filter` is the same option and must not be missed
		// by a gate that compared the whole key.
		{
			name:  "aliased system option",
			query: `northwind.$filter=Year%2520eq%25202026`,
			want:  want,
		},
		// Key case is not payload case. The option names are matched
		// case-insensitively because OData clients and HTTP servers
		// disagree about it, and a gate that misses the casing loses the
		// event outright.
		{
			name:  "uppercase system option",
			query: `$FILTER=Year%2520eq%25202026`,
			want:  want,
		},

		// --- negatives. Each of these is why the class needs both halves
		// rather than one.

		// A real OData client sends exactly these keys. Without the
		// residual-escape half, every OData request in the world is an
		// alert, which is the failure mode classifyPayload's own doc
		// comment warns about.
		{
			name:  "legitimate OData client",
			query: `$select=Year,Value&$top=10&culture=en-US`,
			want:  "",
		},
		{
			name:  "legitimate OData filter, encoded once",
			query: `$filter=Year%20eq%202026`,
			want:  "",
		},
		{
			name:  "legitimate aliased client, encoded once",
			query: `northwind.$filter=Year%20eq%202026&$top=5`,
			want:  "",
		},
		// The other half alone is not this class: a double-encoded value
		// on an ordinary parameter is somebody else's business, and the
		// pagename cases below show what happens when it is not.
		{
			name:  "residual escape with no OData option",
			query: `q=%2561%2562`,
			want:  "",
		},
		// Real: the WordPress pagename double-encodings, which the
		// residual-escape half would otherwise claim.
		{
			name:  "real: pagename double-encoded traversal keeps its class",
			query: "page_id=2&pagename=%252e%252e%252fwp-config",
			want:  "wordpress-pagename-traversal",
		},
		{
			name:  "real: pagename backslash variant keeps its class",
			query: "pagename=..%255c..%255cwindows",
			want:  "wordpress-pagename-traversal",
		},
		// Real: the PHP-CGI probe arriving as %25ADd, the same encoding
		// variation the note on classifyPayload records.
		{
			name:  "real: php-cgi double-encoded keeps its class",
			query: `%25ADd+allow_url_include%3D1+%25ADd+auto_prepend_file%3Dphp://input`,
			want:  "php-cgi-argument-injection",
		},
		// #3430's %2561 bypass as published -- a double-encoded escape in
		// one key, an OData option in another, on the same request. The
		// real campaign puts that escape in a *path* segment, which
		// classifyPayload is not given, so this query form is a
		// reconstruction and the class does not claim it: matching it
		// would mean scanning every key in the request for a residue and
		// claiming it because some unrelated key elsewhere held an OData
		// option. Recorded as a negative so the boundary is visible
		// rather than assumed.
		//
		// #3447 (2026-09-28) -- THE PIN IS NOW DELIBERATELY KEPT, and this
		// comment is the record of that decision, because the issue required
		// the update to be visible rather than silent.
		//
		// The brief said this pin "fails if this ever starts matching" and
		// would need updating when layer C lands. The pin was examined
		// against the landed code and the honest finding is that it does NOT
		// need its expectation changed: `want` is still "". Two reasons, and
		// the first is the important one.
		//
		// 1. Layer C does not reach this case at all, by construction. The
		//    escape half of a layer C pair is read from the *path*
		//    (pathBorneResidualEscape), and `classifyPayload` is called with
		//    (query, body) only. `%2561` here is a query key, which is
		//    #3443's territory, so this input is not a half for the new layer
		//    and cannot complete a pair. Even replayed twice, it does not
		//    fire -- pinned in TestLayerCDoesNotOverMatch.
		//
		// 2. More generally, the same-request rule makes an in-request match
		//    between an option and an unrelated escape impossible in code,
		//    not by policy. A single request carrying both halves seeds the
		//    state and returns ""; the pair can only complete on a later
		//    request, and then only for a bound (fingerprint, resource) pair.
		//    Pinned in TestLayerCSameRequestNeverFires.
		//
		// So the trap #3447 names -- "fire because an unrelated key happened
		// to hold an option-shaped value" -- is now structurally impossible
		// rather than merely avoided, and relaxing this expectation would
		// *reopen* the trap rather than record progress. The value of
		// "want" below is unchanged from #3443 and the reason it is still ""
		// is now stronger. Changing it to "odata-path-encoded-bypass" would
		// have been the wrong fix: it would have required fabricating the
		// query form into a match, which is what the #3443 agent refused to
		// do in the first place.
		//
		// What DID change when layer C landed is elsewhere and is pinned
		// there: TestLayerCCatchesThePublishedPathBorneBypass, which fires
		// on the real two-request shape the path actually produces, and
		// TestLaunderingClassIsNotA3430Layer, which asserts the two classes
		// are unreachable from each other's inputs.
		{
			name:  "residual escape split onto a different key than the option",
			query: `$filter=year%20eq%202026&%2561=1`,
			want:  "",
		},
		// The laundering itself is not a payload. #3430's technique 2 is
		// that the request arrives from a third-party scanner, which is a
		// fact about the source, not the bytes -- and the source is
		// exactly what laundering makes worthless.
		{
			name:  "relay-laundered ordinary request",
			query: `page=2&sort=name`,
			want:  "",
		},
		{
			name: "self-submitting form body from a relay",
			body: `url=https%3A%2F%2F203.0.113.7%2Fdump&submit=go`,
			want: "",
		},
		// $ inside another value is not a system option. The gate parses
		// keys, so a substring match would fire here.
		{
			name:  "option name only inside a value",
			query: `q=%24filter%253DYear%2520eq`,
			want:  "",
		},
		// A malformed escape decodes to nothing, so it is not a residual
		// escape. A deliberately broken % sequence must not become a way
		// to hide the payload, but it is not evidence of a second decode
		// either.
		{
			name:  "malformed escape is not a residual escape",
			query: `$filter=Year%zz%2520eq`,
			want:  "",
		},
		// Ordinary traffic that happens to carry a percent sign.
		{
			name:  "percent in an ordinary value",
			query: `discount=50%25&coupon=SAVE`,
			want:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyPayload(c.query, c.body); got != c.want {
				t.Errorf("classifyPayload(%q, %q) = %q, want %q", c.query, c.body, got, c.want)
			}
		})
	}
}

// TestResidualEscapeIsNotFooledByBrokenEncoding pins the helper's own
// boundary: a % needs two hex digits behind it, and the scan must not run
// off the end of a short string.
func TestResidualEscapeIsNotFooledByBrokenEncoding(t *testing.T) {
	// A % needs two hex digits behind it. Truncated and malformed forms are
	// not escapes -- otherwise a stray percent sign is evidence, which
	// would make the class fire on ordinary text.
	for _, s := range []string{"%", "%2", "abc%", "Year%2", "%zz", "%2G", "50% off"} {
		if residualEscape(s) {
			t.Errorf("residualEscape(%q) = true, want false", s)
		}
	}
	// Two hex digits is enough and the rest of the string does not matter.
	// "Year%20eq" is a single-encoded space that arrived undecoded, which
	// is the same evidence as the double-encoded case.
	for _, s := range []string{"%20", "%61", "Year%20eq", "Year%2520eq", "%zz%20", "a%ffb"} {
		if !residualEscape(s) {
			t.Errorf("residualEscape(%q) = false, want true", s)
		}
	}
}
