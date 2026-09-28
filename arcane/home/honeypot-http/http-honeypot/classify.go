package main

import (
	"net/url"
	"strings"
)

// This file is the dispatcher #3464 asked for, and it is the only place the
// classifiers are ordered. Each case lives in its own file next to its own
// rationale and its own helpers -- classify_roundcube.go,
// classify_wordpress.go, classify_ollure.go, classify_odata.go,
// classify_generic.go -- so a branch adding a CVE touches that file and one
// line below, instead of two regions of a 700-line switch in main.go.
//
// THE ORDER IS SEMANTIC. It is most-specific-first and first-match-wins, and
// several classes overlap on purpose: a base64 dropper is also php-code, a
// pagename traversal into pearcmd is also a pearcmd chain, a Roundcube login
// carrying SQL is also the generic sqli class, a TeamCity agent poll
// carrying a Java stream is also a serialized object. Swapping two entries
// does not shuffle labels around -- it relabels every payload both classes
// match, and nothing in the request says that happened.
//
// Two ways to get this wrong, both of which used to be easy:
//
//   - inserting a new case below a generic one. "serialized-object" is the
//     case the issue names, and #3444 hit it for TeamCity: anything with a
//     Java or PHP object header is claimed by it, so a new case that belongs
//     above it and lands below it is simply dead. TestPayloadClassOrderIsPinned
//     in classify_order_3464_test.go is the answer to that -- the whole order
//     is asserted as data, so a rebase that merges the wrong side of it fails
//     CI instead of quietly losing a class.
//   - inserting it above a case it has no business beating. The precedence
//     table in the same file is the answer to that, one payload per
//     overlap, asserted against the specific class.

// classifyInput is what a case is handed. Query and Body are the request as
// it arrived; the other three are derived once per request rather than inside
// each case. Both forms are load-bearing: the raw pair is what the
// url.ParseQuery-based cases parse, and a decode that happens before they see
// the bytes changes which parameters exist, while the lowercased pair is what
// the substring cases match against.
type classifyInput struct {
	// Query and Body are exactly as they arrived.
	Query string
	Body  string
	// Q and B are the lowercased, percent-decoded query and the lowercased
	// body.
	Q string
	B string
	// Both is Q and B joined by a newline, so that no needle can straddle
	// the boundary between the query and the body.
	Both string
}

// payloadClass is one case of the classifier: the label it reports, and the
// predicate that decides it. Nothing else -- no interface, no registry, no
// discovery. A case is a struct literal in the slice below and a function in
// its own file, and those two facts are the whole extension mechanism.
type payloadClass struct {
	label string
	match func(classifyInput) bool
}

// payloadClasses is the dispatch, in the order it runs. Read it top to bottom
// as "most identifying first, most generic last"; a new case goes in the
// section it belongs to, and the section comments are the reason it belongs
// there. The long rationale for any one case is in that case's file.
var payloadClasses = []payloadClass{
	// --- named exploit chains, most identifying first ---

	// #3364, CVE-2026-48842. Ahead of the generic sqli class, because a
	// Roundcube probe is frequently both at once.
	{"roundcube-virtuser-query-sqli", roundcubeVirtuserSQLi},

	// #3189, CVE-2026-63077. Ahead of the generic serialized-object case
	// at the bottom of this list, which is what the raw and base64
	// containers would otherwise be filed under.
	{"teamcity-agent-deserialization", teamcityAgentDeserialization},

	// #3309, CVE-2026-87902. Ahead of pearcmd-rce, which is this chain's
	// own second stage.
	{"wordpress-pagename-traversal", wordpressPagenameTraversal},

	// #3309, CVE-2026-87902 again, and the half the case above cannot
	// reach. Checked after the pagename case and before pearcmd-rce, so
	// #3359's labels do not move: a request it already claims keeps the
	// class it has had since #3359 shipped, and this only picks up what
	// falls through.
	{"wordpress-template-inclusion", wordpressTemplateInclusion},

	// CVE-2012-1823 / CVE-2024-4577.
	{"php-cgi-argument-injection", phpCGIArgumentInjection},

	// ThinkPHP's invokefunction routing gadget.
	{"thinkphp-rce", thinkphpInvokefunction},

	// Traversal to PEAR's CLI, escalated to writing a PHP file.
	{"pearcmd-rce", pearcmdConfigCreate},

	// Log4Shell and its JNDI relatives.
	{"jndi-lookup", jndiLookup},

	// --- code the request wants run ---

	// Ahead of the bare php-code case, which would otherwise swallow it.
	{"php-base64-shell", phpBase64Shell},

	{"php-code", phpCode},

	{"downloader", downloaderChain},

	{"command-injection", commandInjection},

	// --- what the request wants to read or become ---

	// Ahead of path-traversal: both the file it reads and the
	// traversal that got there are named, and the class has to say
	// which one mattered.
	{"secret-read", secretRead},

	// Traversal on its own, once the escalations above have had their turn.
	{"path-traversal", pathTraversal},

	// #3394, Ollure. Below path-traversal and secret-read on purpose: a
	// name that is both a traversal and a target is a traversal.
	{"ollama-model-target", ollamaModelTargetCase},

	// Creating an administrator through an API that should not allow it.
	{"admin-account-create", adminAccountCreate},

	// #3430, scanner-laundering double-encoding, matched on the OData
	// option's own bytes rather than on a path.
	{"odata-double-encode-probe", odataDoubleEncodeCase},

	// --- injection into an interpreter that is already running ---

	// The generic class. Roundcube and the OData case above are read out
	// of parsed parameters, so they do not compete with this one over a
	// payload that rode in the query string.
	{"sqli", sqliInjection},

	{"prototype-pollution", prototypePollution},

	{"xxe", xxeInjection},

	{"template-injection", templateInjection},

	// --- probes that carry a payload without exploiting anything ---

	{"soap-probe", soapProbe},
	{"vpn-handshake", vpnHandshake},
	{"mcp-probe", mcpProbe},
	{"mining-rpc-probe", miningRPCProbe},
	{"batch-request-probe", batchRequestProbe},

	// version.bind is also a bare hostname, and this one says what it is.
	{"dns-version-probe", dnsVersionProbe},
	{"open-resolver-probe", openResolverProbe},

	{"androxgh0st", androxgh0stMarker},
	{"wordpress-rest-probe", wordpressRESTProbe},
	{"info-disclosure", infoDisclosure},
	{"multipart-padding", multipartPadding},

	// Java and PHP serialised objects, by their header rather than their
	// contents. The generic object case: a new case that is more specific
	// than this belongs ABOVE it, not below, or this claims its traffic
	// first. See the header note on the file.
	{"serialized-object", serializedObject},

	// Anything speaking a binary protocol at an HTTP port. Last: it is a
	// statement about the bytes rather than about intent, and any pattern
	// above is more informative.
	{"binary-protocol", binaryProtocol},
}

// classifyPayload names what a request carried, from its query string and
// body. Empty when nothing recognisable is there, which is most traffic.
//
// Patterns rather than a model, and that is a measurement rather than a
// preference (#1809, #1888). Over 30 days the fleet saw 11,139 requests
// carrying a body or a query and 583 distinct values between them -- and
// that count is itself inflated, because ~19 events each of an otherwise
// identical multipart probe differ only by their random
// WebKitFormBoundary. One payload, CVE-2017-9841's PHPUnit probe, is a
// quarter of the corpus by itself. A corpus that small and that repetitive
// is a lookup table; the model argument only becomes real if a month ever
// starts yielding thousands of genuinely new payloads instead of a
// handful.
//
// The order is specific-to-generic, and the first match wins. Real
// payloads nest -- the second most common body here is a <?php wrapper
// around a base64 blob that decodes to a wget|sh chain, which is three of
// these classes at once -- so the outermost, most identifying shape is
// checked first. This runs on the RAW body: naming one class does not
// decide what is kept, and since #3213 the kept copy is redacted, so this
// pass must not be the thing that reads a redacted string and finds nothing
// in it.
//
// Counts in the comments come from running this function over that whole
// window rather than over examples, which is also how the one surprising
// result was checked rather than assumed: command-injection labels 4,273
// events across 270 distinct bodies, far more than anything else except
// the PHPUnit probe. Sampling them showed it is right -- they are 5 KB
// multipart bodies whose padding hides a `id; hostname; pwd` passed to a
// Node child_process, so the class is one campaign rather than a leaky
// pattern.
//
// A pattern that fires on ordinary traffic is worse than no pattern, since
// it makes every event look interesting. The classes are deliberately
// narrow and the tail is left unlabelled: 92.5% of the window is named,
// and what remains is scanner cache-busting like "v=GyJrG" and "id=3",
// which has no class worth giving it.

func classifyPayload(query, body string) string {
	// Query strings arrive percent-encoded, and attackers vary the
	// encoding of the same probe to slip signatures -- the PHP-CGI probe
	// arrives as %ADd, %25ADd and plain -d in the same window. Match
	// on the decoded form, falling back to the raw one when it will not
	// decode, so a deliberately malformed escape cannot hide a payload.
	decoded := query
	if unescaped, err := url.QueryUnescape(query); err == nil {
		decoded = unescaped
	}
	c := classifyInput{Query: query, Body: body, Q: strings.ToLower(decoded), B: strings.ToLower(body)}
	c.Both = c.Q + "\n" + c.B

	for _, p := range payloadClasses {
		if p.match(c) {
			return p.label
		}
	}
	return ""
}

// containsAny reports whether s contains any of the needles.
func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// residualEscape reports whether s holds a %XX escape that is still there --
// a string that will decode again if something asks it to. Malformed
// sequences are not escapes and do not count.
//
// Shared with the scanner-laundering detector in laundering.go, which asks
// the same question of a decoded path, and with the OData case in
// classify_odata.go. It is here rather than in either because it belongs to
// neither: it is the two bytes and nothing else.
func residualEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		var hi, lo byte
		if unhex(s[i+1], &hi) && unhex(s[i+2], &lo) {
			return true
		}
	}
	return false
}
