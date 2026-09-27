package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #3189 / CVE-2026-63077: unauthenticated deserialization RCE in JetBrains
// TeamCity, CVSS 3.1 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), CWE-502, in
// CISA KEV since 2026-08-05, fixed in TeamCity 2025.11.7 and 2026.1.3. The
// JetBrains CNA record names the mechanism: deserialization of untrusted data
// reached through the agent polling protocol, so nothing about it needs a
// credential, and the vendor describes command execution with the server
// process's own privileges.
//
// The class is a statement about BYTES. The sensor never reconstructs the
// object, never feeds it to a deserializer, and never answers a question the
// deserialization would have answered -- a classifier that read the stream to
// confirm it would be a second copy of the sink it is meant to observe. What
// is matched is the container itself:
//
//   - the Java serialization stream header, raw (AC ED 00 05) or as the
//     base64 XML-RPC and JSP transports actually carry it (rO0AB...), and
//   - a gadget class name, which a Java stream carries in cleartext and
//     which is the whole reason a container on the wire is an attack rather
//     than an accident.
//
// ...both required, together with TeamCity's own agent-protocol shape. Each
// half alone is ordinary: every TeamCity server has agents polling it, and a
// serialized object on an HTTP port is somebody else's finding. The
// conjunction is the CVE, and it is the conjunction -- not a broad substring
// -- that is what the negatives below pin.
//
// The fixtures follow the published request shape rather than a capture: the
// research note on #3189 records that no exploitation detail, no PoC and no
// corpus of this signature exists, and that the backup/AWS-key/S3 chain,
// the Cadence connection and the quoted JetBrains advice in the original
// issue are all UNVERIFIED. Nothing below depends on any of them, and
// nothing here claims a working payload: a request carrying a container is an
// ATTEMPT to reach a deserialization sink, which is a different and much
// smaller claim than "the CVE was exploited".
//
// The negatives are the ones that decide whether this is usable. The
// classifier's own rule -- stated above classifyPayload -- is that a pattern
// that fires on ordinary traffic is worse than no pattern. WordPress
// XML-RPC shares the transport with TeamCity's agent protocol, and this
// sensor serves a bait endpoint of its own at /xmlrpc.php, so containers on
// that transport are expected to reach this code -- and they are not
// TeamCity's. The case that must not be stolen is the one with the same
// bytes and a different product.
func TestTeamcityAgentDeserialization(t *testing.T) {
	const want = "teamcity-agent-deserialization"

	cases := []struct {
		name, query, body string
		want              string
	}{
		// --- the published shape: an unauthenticated agent-poll request
		// whose parameter is a serialized object, base64 in the XML-RPC
		// string transport. methodName is the dispatch name, so this needs
		// no session, which is the "PR:N" half of the CVSS vector.

		{
			name: "agent registration poll carrying a base64 stream",
			body: `<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>xmlrpc/allowRegistration</methodName><params><param><value><string>rO0ABXNyABNvcmcuYXBhY2hlLmNvbW1vbnN0AAtUcmFuc2Zvcm1lcnAAAAAA</string></value></param></params></methodCall>`,
			want: want,
		},
		{
			// The same envelope carrying the stream raw rather than
			// base64'd, which is what an agent talking to a JSP endpoint
			// sends. Byte-identical signature, different transport.
			name:  "raw stream on the generic xmlrpc envelope",
			query: "methodName=xmlrpc%2Fremote",
			body:  "\xac\xed\x00\x05\x73\x72\x00\x1borg.jetbrains.teamcity\x74\x00\x1cTeamCityMessageDto\x70\x00\x00\x00\x00",
			want:  want,
		},
		{
			// TeamCity's own JSP fallback entry point, which takes the
			// call name and its argument as plain query parameters. The
			// container rides in the query here rather than the body,
			// and it is the query this function is handed first.
			name:  "work-download call with the container in the query",
			query: "methodName=agentUnload&buildServerId=9014&agentName=build-agent-07&data=rO0ABXNyABtvcmcuamV0YnJhaW5zLnRlYW1jaXR5dAAcVGVhbUNpdHlNZXNzYWdlRHRv",
			want:  want,
		},
		{
			// The container at the very front of the body, with the
			// product named in the query. On origin/main this is filed as
			// the generic serialized-object class, which is the whole
			// reason the new case sits above it.
			name:  "container at offset zero, product in the query",
			query: "methodName=xmlrpc%2FgetUnregisteredAgents",
			body:  "rO0ABXNyABNvcmcuYXBhY2hlLmNvbW1vbnN0AAtUcmFuc2Zvcm1lcnAAAAAA",
			want:  want,
		},
		{
			// The half of the conjunction that is not a magic number: a
			// Java stream carries its class descriptor in cleartext, so a
			// gadget class name arriving as a plain string is the same
			// reach -- a scanner that cannot encode binary probes the sink
			// by naming the class. No container, so the class says "aimed
			// at", and this test exists to keep that distinction honest.
			name: "gadget class named in the clear with the TeamCity DTO named beside it",
			body: `<methodCall><methodName>xmlrpc/remote</methodName><params><param><value><string>teamcity.server.message</string></value></param><param><value><string>org.apache.commons.collections.functors.InvokerTransformer</string></value></param></params></methodCall>`,
			want: want,
		},

		// --- negatives. The three the change is required to get right,
		// then the boundary cases around them.

		{
			// A normal TeamCity-looking request: the same call, the same
			// product, ordinary parameters. Every TeamCity server has
			// agents doing exactly this, forever. Flagging it would put
			// this class on the fleet's ordinary background traffic.
			name: "an ordinary agent registration poll, no container",
			body: `<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>xmlrpc/allowRegistration</methodName><params><param><value><string>build-agent-07</string></value></param><param><value><int>1</int></value></param></params></methodCall>`,
			want: "",
		},
		{
			// The same keyword with no magic bytes, in the other
			// transport: TeamCity's agent property bag is full of
			// teamcity.* names, and none of them is a container.
			name:  "the product's own parameters, no magic bytes",
			query: "methodName=xmlrpc%2FallowRegistration",
			body:  "agentName=build-agent-07&poolId=0&properties=teamcity.agent.jvm.os.name=Linux&teamcity.build.id=9014",
			want:  "",
		},
		{
			// A plain-text body that mentions the product, which is what
			// a CI system's own log line or an error page looks like.
			name: "plain text naming the product",
			body: "teamcity agent build-agent-07 connected, pool Default, authorized",
			want: "",
		},
		{
			name:  "plain text query naming the product",
			query: "q=teamcity&buildTypeId=Build&status=success",
			want:  "",
		},
		{
			// The boundary that matters most in production: same bytes,
			// different product. WordPress XML-RPC shares the transport
			// with TeamCity's agent protocol and this sensor serves a bait
			// at /xmlrpc.php, so a serialized object here is far more
			// likely to be somebody else's. A WordPress call name must not
			// be claimed by the TeamCity class, or the attribution is
			// worse than having no class at all.
			//
			// "no label" is the honest expectation, not a gap this change
			// fills: the generic case below only recognises a stream at the
			// very start of a body or raw magic bytes anywhere in one, and a
			// base64 token in the middle of an XML document is neither.
			// Widening that is a separate decision about the generic class
			// with its own false-positive evidence, and it is not what
			// #3189 asks for.
			name: "WordPress XML-RPC carrying the same container is not TeamCity's",
			body: `<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>1</string></value></param><param><value><string>admin</string></value></param><param><value><string>rO0ABXNyABNvcmcuYXBhY2hlLmNvbW1vbnN0AAtUcmFuc2Zvcm1lcnAAAAAA</string></value></param></params></methodCall>`,
			want: "",
		},
		{
			// The same request with the stream in the raw transport the
			// generic case does recognise, which is where the product
			// attribution is easiest to get wrong: this is the shape that
			// was already a serialized-object event on this sensor before
			// this change, and it has to still be one afterwards.
			name: "WordPress XML-RPC with a raw stream keeps the generic class",
			body: "<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><base64>\xac\xed\x00\x05\x73\x72\x00\x13org.apache.commons</base64></value></param></params></methodCall>",
			want: "serialized-object",
		},
		{
			// The same in the raw transport, and the case that proves the
			// new branch only reclassifies inside its own gate: with no
			// TeamCity shape present the generic case is unchanged.
			name: "a bare stream with no product shape keeps the generic class",
			body: "\xac\xed\x00\x05\x73\x72\x00\x13org.apache.commons\x70\x00\x00\x00\x00",
			want: "serialized-object",
		},
		{
			// A container at offset zero and nothing else. Before this
			// change the generic case caught it on its prefix; it still
			// does, and the generic case is not weakened.
			name: "base64 stream with no product shape keeps the generic class",
			body: "rO0ABXNyABNvcmcuYXBhY2hlLmNvbW1vbnN0AAtUcmFuc2Zvcm1lcnAAAAAA",
			want: "serialized-object",
		},
		{
			// A gadget class name with no container and no product is not
			// an attempt at all -- a string in a request is a string, and
			// this class does not get to guess that somebody meant to
			// hand it to a deserializer somewhere else.
			name: "a gadget class name on its own is not an attempt",
			body: `<param><value><string>org.apache.commons.collections.functors.InvokerTransformer</string></value></param>`,
			want: "",
		},
		{
			// A call name that merely contains a TeamCity one. TeamCity
			// is not the only product with an XML-RPC agent channel, and
			// the gate is a whole-value match for that reason.
			name:  "a neighbouring call name is not TeamCity's",
			query: "methodName=xmlrpc%2FallowRegistrationAndPing",
			body:  "rO0ABXNyABNvcmcuYXBhY2hlLmNvbW1vbnN0AAtUcmFuc2Zvcm1lcnAAAAAA",
			want:  "serialized-object",
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

// TestTeamcityDeserializationMatchesBytesWithoutDecoding is the assertion
// behind the hard rule: nothing on this path deserializes, decodes or
// evaluates anything it received.
//
// A decoder-based implementation could not pass the first case. The token
// after the container header is not valid base64, so anything that tried to
// decode it -- to confirm the object graph, to walk its class table, to
// count its fields -- would have to fail, skip the token, or reject the
// request. The classifier cannot: it compares five bytes at a token
// boundary and returns. The second case is the other direction, so the
// matcher cannot be "something that looks like base64": valid base64 that
// decodes cleanly to ordinary bytes carries no container and is not flagged.
//
// Nothing here is fed to encoding/gob, to a struct decode, or to any other
// object reader, and the test would not compile if it were -- a deserializer
// of any family would have to be imported, and this package imports none.
func TestTeamcityDeserializationMatchesBytesWithoutDecoding(t *testing.T) {
	const want = "teamcity-agent-deserialization"

	cases := []struct {
		name, query, body string
		want              string
	}{
		{
			// Header present, tail not decodable. A decoder stops here.
			name:  "header present, rest of the token undecodable",
			query: "methodName=xmlrpc%2Fremote",
			body:  "<string>rO0AB\xff\xfe\x00\x01not base64 at all</string>",
			want:  want,
		},
		{
			// The same on the raw transport, truncated mid-header: four
			// bytes is the whole signature and the match does not care
			// that there is nothing behind it.
			name:  "raw header truncated to nothing behind it",
			query: "methodName=xmlrpc%2Fremote",
			body:  "\xac\xed\x00\x05",
			want:  want,
		},
		{
			// Valid base64, decodes to ordinary text, no container.
			name:  "valid base64 that decodes to something harmless",
			query: "methodName=xmlrpc%2Fremote",
			body:  "<string>" + "aGVsbG8gdGhlcmUgYWdlbnQgaXMgcmVnaXN0ZXJlZA==" + "</string>",
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

// TestTeamcityDeserializationReachesTheEvent covers the half a classifier
// unit test cannot: that the class lands on the emitted event, and that the
// rest of the event keeps saying what it says today.
//
// Three things are asserted rather than assumed.
//
// The unauthenticated half: this sensor keeps no session and consults no
// backend, so "pre-auth" here is a statement about the request, not about a
// session the decoy never had. credential_status is absent and
// auth_outcome is unknown -- no credential was presented and nothing decided
// anything about an identity -- while the payload is still classified. The
// class must not require a login to have happened first, because the CVE does
// not.
//
// The decoy is not a TeamCity: it answers with the generic 404 and category
// stays the generic "wordpress" for an /xmlrpc path. The research note on
// #3189 is explicit that a generic response is not a persona, and that a
// product classifier must have a cited benign basis rather than be inferred
// from a path. So the CVE reading lives in payload_class only, and this
// assertion fails if somebody later grows it into a persona.
//
// The redaction contract of #3213: the opaque scrubber ran over this text/xml
// body, and it must not have cost the fleet the signature.
func TestTeamcityDeserializationReachesTheEvent(t *testing.T) {
	s, output := newTestServer()

	const body = `<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>xmlrpc/allowRegistration</methodName><params><param><value><string>rO0ABXNyABNvcmcuYXBhY2hlLmNvbW1vbnN0AAtUcmFuc2Zvcm1lcnAAAAAA</string></value></param></params></methodCall>`

	r := httptest.NewRequest(http.MethodPost, "http://example/xmlrpc", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")
	r.RemoteAddr = "203.0.113.9:51000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	line := output.String()
	if !strings.Contains(line, `"payload_class":"teamcity-agent-deserialization"`) {
		t.Fatalf("the event did not carry the payload class: %s", line)
	}
	// Unauthenticated: nothing was presented and nothing was decided.
	if !strings.Contains(line, `"credential_status":"absent"`) {
		t.Fatalf("the request was not recorded as carrying no credential: %s", line)
	}
	if !strings.Contains(line, `"auth_outcome":"unknown"`) {
		t.Fatalf("an authentication decision was recorded for a pre-auth probe: %s", line)
	}
	// The container itself must survive redaction, or an analyst cannot
	// read the payload out of the event that was classified.
	if !strings.Contains(line, "rO0AB") {
		t.Fatalf("the container signature was scrubbed out of the stored body: %s", line)
	}
	// No persona: the decoy answered with its generic 404 and the path
	// category is the generic one it was before this change.
	if w.Code != http.StatusNotFound {
		t.Fatalf("the decoy answered %d; a TeamCity persona is out of scope", w.Code)
	}
	if !strings.Contains(line, `"category":"wordpress"`) {
		t.Fatalf("the path category changed: %s", line)
	}
}
