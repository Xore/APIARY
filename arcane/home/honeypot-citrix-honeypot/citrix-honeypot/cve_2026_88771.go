package main

// #3467 -- CVE-2026-88771 and CVE-2026-88772, the Citrix NetScaler ADC /
// NetScaler Gateway zero-day RCE pair that CISA added to KEV on 2026-09-27.
//
// WHAT THIS FILE SHIPS, STATED UP FRONT SO IT CANNOT BE MISREAD
//
// This ships KEV-metadata-driven coverage. It does not ship exploit
// detection, because exploit detection for this pair is not yet possible
// from public information, and a fabricated signature in a honeypot is
// worse than no signature at all: it produces detection events that an
// analyst will trust and that correspond to nothing on the wire.
//
// Re-verified for this change, 2026-09-28, against primary sources:
//
//   - CISA KEV feed, catalog version 2026.09.27, released
//     2026-09-27T21:30:35Z, 1728 entries. Both CVEs present, both
//     dateAdded 2026-09-27, both dueDate 2026-09-30, both
//     forensicTriage "Yes". Their Notes field points at CTX697096 and at
//     a "provided IOCs" scan -- see the "no payload bytes" note below.
//   - Citrix bulletin CTX697096, Changelog 2026-09-27 "Initial
//     Publication". Carries the per-CVE preconditions, the CVSS v4.0
//     vectors, the CWE ids and the fixed builds reproduced below.
//
// Verified ABSENT from both primary sources, which is what shapes this
// whole file:
//
//   1. No request path, HTTP method, header, query parameter, body field
//      or payload byte sequence for either CVE. CTX697096 is a
//      precondition/upgrade table plus regexes for reading a customer's
//      OWN ns.conf. It contains no attack traffic and no exploit shape.
//   2. No network-observable precondition to filter on for CVE-2026-88771.
//      Its precondition is "All NetScaler ADC and NetScaler Gateway
//      deployments (Default configuration / No additional feature
//      required)" -- every deployment qualifies, so there is nothing to
//      test for. A decoy standing in for the product is affected by
//      definition.
//   3. The "provided IOCs" that both KEV and CTX697096 point at are not
//      request signatures. Per watchTowr's 2026-09-27 write-up they are
//      run as an "IOC scan on the NetScaler Console Security Advisory
//      page (version 14.1-73.36 or later, telemetry enabled)" or
//      requested from Citrix Support -- i.e. appliance-console artifacts
//      gated on a build this decoy does not run, not wire patterns. There
//      is nothing there for a network decoy to match even in principle.
//      Citrix's own caveat, quoted by watchTowr, is that the IOCs "do not
//      cover every technique" so "a clean result is not proof" -- which
//      cuts against over-reading any single signal, including this one.
//   4. watchTowr states 88773-88778 are "Not reported" exploited and
//      that 88778 is "Fixed by enabling Enhanced ISN Generation, not by
//      the upgrade alone". Out of scope here; see the follow-ups at the
//      bottom of this file.
//
// CONSEQUENCE FOR CVE-2026-88772: its precondition is "DTLS configuration
// enabled on NetScaler ADC or NetScaler Gateway (Note: Enabled by default
// on VPN vServer)" -- CTX697096, verbatim. DTLS is a UDP transport. This
// decoy is TCP-only: main() listens with net.Listen("tcp", ...) behind
// tls.NewListener, and portbridge fronts it as tcp:4443 -> 10.8.0.2:443:pp.
// There is no UDP socket and no DTLS handshake anywhere in the stack, so
// the 88772 precondition is not observable on this surface at all. The
// honest deliverable is therefore a documented gap, not a classifier. See
// emitKEVCoverage's decoy_exercises_precondition field, which records the
// gap as queryable data rather than leaving it in a comment nobody
// triages on.
//
// WHAT IS THEREFORE INFERRED, AND LABELLED AS SUCH
//
// The one observable this file adds is a command-metacharacter shape
// check, and its provenance is uneven:
//
//   DOCUMENTED: CVE-2026-88771's primitive. CTX697096: "A remote code
//   execution vulnerability exists due to improper input validation, which
//   can allow an unauthenticated attacker to execute arbitrary commands."
//   KEV agrees: "an unauthenticated attacker to execute arbitrary
//   commands." Note this is CWE-20 (Improper Input Validation), NOT
//   CWE-78 (OS Command Injection) -- Citrix did not characterise it as
//   command injection, and the distinction matters: a CWE-20 primitive
//   tells you the input is not validated, not that it arrives in the path.
//
//   INFERRED: that the unvalidated input arrives in the path, the query
//   or the body, and that it therefore shows up as shell metacharacters.
//   Neither CTX697096 nor KEV nor the watchTowr write-up says where the
//   input lands, and the primitive could equally be a header, a cookie, a
//   typed field or a protocol opcode. This file therefore checks all
//   three request-controlled surfaces the issue named, treats a match as
//   evidence of a COMMAND-METACHARACTER SHAPE and nothing more, and
//   encodes the inference in the event name itself.
//
// The event name carries "inferred" deliberately:
//
//	netscaler_cmd_metachar_shape_inferred
//
// authSurfaceEvent's own comment records why a CVE-numbered event name is
// the wrong tool when the shape is unconfirmed: a classifier that "looks
// like real detection coverage in the dashboard while never having been
// checked against a real request" is the failure mode, and this package
// already declined to add a cve_2026_19490 event for exactly that
// reason. A triage dashboard that renders
// "netscaler_cmd_metachar_shape_inferred" cannot mislead anyone into
// reading a semicolon in a query string as a confirmed CVE-2026-88771
// exploit. The CVE association is carried instead by the
// netscaler_kev_exposure events below and by docs/research/3467-*.

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// netscalerKEVEntry is the verified, citable metadata for one CVE of the
// CTX697096 pair. Every field here is transcribed from a primary source;
// none of it is inferred. Keeping it as data rather than prose is what
// lets emitKEVCoverage put it in front of an analyst instead of leaving
// it buried in a comment.
type netscalerKEVEntry struct {
	CVE string
	// KEVAdded / KEVDue are the catalog's own dateAdded / dueDate.
	KEVAdded string
	KEVDue   string
	// CVSSv4 is the full vector from CTX697096, not just the 9.5 base
	// score, because the vectors differ in the two fields that matter for
	// detection: 88771 is AC:L/AT:P (low complexity, but requires
	// attacker preparation) and 88772 is AC:H (high complexity).
	CVSSv4 string
	// CWE is CTX697096's classification. Worth being precise about: KEV
	// lists cwes ["CWE-119"] for BOTH entries, which contradicts the
	// bulletin for 88771 (CWE-20) and looks like a catalog-side copy of
	// 88772's row. CTX697096 is the vendor's own classification of its own
	// CVE, so it wins here; the discrepancy is noted rather than silently
	// resolved.
	CWE          string
	Precondition string
	// FixedIn is CTX697096's "What Customers Should Do" list. 13.1 has a
	// second fixed build (13.1-64.24) that watchTowr documents for
	// appliances where `show ns variable` returns anything, because of a
	// reboot loop; CTX697096 does not mention it, so it is not asserted
	// here as vendor guidance.
	FixedIn string
	// decoyExercisesPrecondition is the honest answer to "could this
	// decoy ever satisfy this CVE's precondition?", which for a network
	// decoy is the question that decides whether classifier work is
	// possible at all.
	decoyExercisesPrecondition bool
	preconditionGap            string
}

var netscalerKEV2026 = []netscalerKEVEntry{
	{
		CVE:      "CVE-2026-88771",
		KEVAdded: "2026-09-27",
		KEVDue:   "2026-09-30",
		CVSSv4:   "9.5 CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
		CWE:      "CWE-20",
		Precondition: "all NetScaler ADC and NetScaler Gateway deployments " +
			"(default configuration, no additional feature required)",
		FixedIn: "14.1-73.37; 13.1-64.23; 13.1-37.279 (FIPS/NDcPP)",
		// True, and vacuously so: the precondition is "every deployment",
		// so there is nothing to test and nothing to miss. A decoy
		// impersonating the product always meets it.
		decoyExercisesPrecondition: true,
	},
	{
		CVE:      "CVE-2026-88772",
		KEVAdded: "2026-09-27",
		KEVDue:   "2026-09-30",
		CVSSv4:   "9.5 CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
		CWE:      "CWE-119",
		Precondition: "DTLS configuration enabled on NetScaler ADC or NetScaler " +
			"Gateway (enabled by default on VPN vServer)",
		FixedIn: "14.1-73.37; 13.1-64.23; 13.1-37.279 (FIPS/NDcPP)",
		// False. See the DTLS paragraph in this file's header.
		decoyExercisesPrecondition: false,
		preconditionGap: "DTLS is a UDP transport; this decoy listens on TCP " +
			"only (net.Listen(\"tcp\") behind tls.NewListener, fronted " +
			"tcp:4443 -> 10.8.0.2:443:pp) and terminates no DTLS handshake, " +
			"so CVE-2026-88772's precondition is not observable here. " +
			"Closing this needs a UDP/DTLS listener, which is a new exposed " +
			"surface and therefore out of scope for a detection change.",
	},
}

// summary renders one entry as a stable, greppable, single-line string.
// Deliberately not JSON: this lands in the existing `data` string field, and
// a key=value list is readable to an analyst in a raw document without a
// mapping change, which keeps the change additive to the emitted schema
// (no new fields on the shared `event` struct, nothing to migrate).
func (e netscalerKEVEntry) summary() string {
	fields := []string{
		"kev_added=" + e.KEVAdded,
		"kev_due=" + e.KEVDue,
		"cvss4=" + e.CVSSv4,
		"cwe=" + e.CWE,
		"precondition=" + e.Precondition,
		"fixed_in=" + e.FixedIn,
		"decoy_exercises_precondition=" + boolWord(e.decoyExercisesPrecondition),
	}
	if e.preconditionGap != "" {
		fields = append(fields, "precondition_gap="+e.preconditionGap)
	}
	return strings.Join(fields, " ")
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// emitKEVCoverage logs the verified KEV/bulletin metadata once per process
// start, through the sensor's existing emit path -- no new logging
// mechanism, no new event struct fields.
//
// This is the "KEV-metadata-driven coverage" the issue's honest fallback
// amounts to, made queryable: an analyst can now ask which KEV entries
// this decoy is standing in for, what each one's precondition is, and --
// for 88772 -- that this surface structurally cannot exercise it, without
// reading Go source. Emitted next to the existing "listening" event, once,
// rather than per request: this is deployment metadata, not traffic, and
// repeating it on every request would inflate the event stream for no
// gain.
//
// The CVE id goes in `path` because that is the field analysts already
// filter this sensor on, and it makes `path: "CVE-2026-88771"` a working
// query against the real schema. These are static compile-time constants
// transcribed from CTX697096, not attacker-controlled input, so putting
// them in a field the decoy otherwise uses for request paths cannot be
// influenced by a client.
func emitKEVCoverage(l *logger, port int) {
	for _, e := range netscalerKEV2026 {
		l.emit(event{Port: port, Event: "netscaler_kev_exposure", Path: e.CVE, Data: e.summary()})
	}
}

// netscalerCmdMetacharEvent is the event kind cmdShapeEvent returns.
//
// Named for the observable, not for the CVE, and carrying "inferred" in
// the name on purpose -- see the header. An analyst who sees this in a
// triage view learns that a request to this decoy contained a
// command-metacharacter shape, which is a fact; they do not learn that a
// CVE-2026-88771 exploit was seen, which is not a fact anyone can assert
// yet.
const netscalerCmdMetacharEvent = "netscaler_cmd_metachar_shape_inferred"

// highConvictionShellTokens fire the classifier on their own, because
// cmdShapeEvent is handed values that have already been through a
// percent-decoder, and no browser, SDK or application form serialiser
// emits a raw backtick, a command substitution or a newline into a
// decoded request target. A percent-encoded one (%60, %24%28, %0a) --
// which is what an exploit client would send, precisely so the target
// looks inert to a middlebox -- arrives back as the literal character.
//
// Which decoder runs depends on the surface, and this is not uniform, so
// it is worth being exact:
//
//   - r.URL.Path IS decoded by net/http. Nothing to do.
//   - r.URL.RawQuery is NOT: it is the raw wire form, still "%60"-shaped.
//     queryForShape below unescapes it, and is the reason that helper
//     exists.
//   - a POST body is NOT decoded either, and deliberately stays that way.
//     See queryForShape's comment for why the body is left alone rather
//     than run through a form parser this sensor does not otherwise have.
//
// Kept to exactly these five on purpose. Widening the high tier is the
// easy way to raise recall and the fastest way to start crying wolf.
var highConvictionShellTokens = map[string]bool{
	"`": true, "$(": true, "${": true, "\n": true, "\r": true,
}

// lowConvictionShellTokens each have a real benign use in HTTP traffic, so
// ONE of them must never fire this classifier; two *distinct* ones in the
// same request is the threshold.
//
//	;   matrix/session parameters: "/store;jsessionid=ABC123" is Jetty
//	    and Tomcat, and a NetScaler AAA vserver fronts plenty of those.
//	    This is also why a bare "/vpn/;id" is NOT classified: it is
//	    indistinguishable from the benign form by shape alone.
//	|   filter/pipe syntax in some templating and WAF test strings
//	&   the query-string separator, i.e. "a=1&b=2" on essentially every
//	    authenticated request this decoy will ever see
//	> < URL and template punctuation
//	&&  a sloppy or empty-parameter encoder emitting "a=1&&b=2"
//	||  the same class of encoder artifact
var lowConvictionShellTokens = []string{"&&", "||", ";", "|", ">", "<", "&"}

// allShellTokens is the single matcher list, longest-first, because the
// scan below must be NON-OVERLAPPING and PREFER THE LONGEST MATCH.
//
// This ordering is load-bearing, not cosmetic. An earlier draft used
// strings.Contains per token, which made "a=1&&b=2" match both "&" and
// "&&" -- two "distinct" low tokens, so the classifier fired on the exact
// sloppy-encoder artifact the low tier exists to tolerate. Left-to-right
// consumption with longest-match-first makes "&&" one token and "a&b" one
// token, which is what the tiering actually means. There is a regression
// test pinning that specific case.
var allShellTokens = buildShellTokens()

func buildShellTokens() []string {
	all := make([]string, 0, len(highConvictionShellTokens)+len(lowConvictionShellTokens))
	for tok := range highConvictionShellTokens {
		all = append(all, tok)
	}
	all = append(all, lowConvictionShellTokens...)
	// Longest first: the scan returns the first match at a position, so
	// "&&" has to be offered before "&" and "$(" before anything that
	// could match a prefix of it. Sort by descending length, stable
	// within a length so the map iteration above cannot make the tier
	// boundary wobble between runs.
	sort.SliceStable(all, func(i, j int) bool { return len(all[i]) > len(all[j]) })
	return all
}

// hasShellShape reports whether s contains a command-metacharacter shape
// worth classifying: any high-conviction token, or two or more distinct
// low-conviction tokens.
//
// Scans left to right, consuming a matched token whole, so overlapping
// tokens cannot double-count. Returns at the first high-conviction hit or
// the second distinct low-conviction one -- there is nothing to learn
// from further tokens, and a decoy request is not a hot path worth
// scanning twice.
func hasShellShape(s string) bool {
	seenLow := make(map[string]bool, len(lowConvictionShellTokens))
	for i := 0; i < len(s); {
		matched := ""
		for _, tok := range allShellTokens {
			if strings.HasPrefix(s[i:], tok) {
				matched = tok
				break
			}
		}
		if matched == "" {
			i++
			continue
		}
		if highConvictionShellTokens[matched] {
			return true
		}
		seenLow[matched] = true
		if len(seenLow) >= 2 {
			return true
		}
		i += len(matched)
	}
	return false
}

// cmdShapeEvent classifies the INFERRED command-metacharacter shape that
// #3467 derives from CVE-2026-88771's documented "execute arbitrary
// commands" primitive, returning "" for everything else.
//
// The three arguments are the three request-controlled surfaces the issue
// named (path, query, body); they are joined with a space so that a token
// cannot be synthesised across a field boundary -- a path ending in "$"
// and a query starting with "(" must not combine into "$(".
func cmdShapeEvent(reqPath, query, body string) string {
	if hasShellShape(reqPath + " " + query + " " + body) {
		return netscalerCmdMetacharEvent
	}
	return ""
}

// queryForShape returns r's raw query string with percent-escapes
// resolved, for cmdShapeEvent to inspect.
//
// r.URL.RawQuery is the raw wire form, so an exploit client that sends
// "?cmd=%60id%60" leaves the backtick encoded and the high-conviction
// tier would never see it. r.URL.Path has the opposite property --
// net/http decodes it before the handler runs -- so the path needs
// nothing here. Resolving the query is what makes the two surfaces behave
// the same way.
//
// Lenient on failure, on purpose: a malformed escape (%zz, a bare %) is
// attacker traffic and must reach the classifier as-is rather than being
// dropped to "" on an error path, because a scanner probing decoders is
// precisely the traffic worth classifying. The raw string is the fallback.
//
// The known cost of decoding: a benign query that percent-encodes shell
// punctuation in a search box ("q=a%20%3E%20b%20%3C%20c") decodes into
// two distinct low-conviction tokens and will classify. That is a real
// false-positive path, stated here rather than discovered later. It is
// acceptable for three reasons -- a decoy attracts no organic search
// box, the event is explicitly named as inferred, and the alternative
// (missing every encoded payload) is the worse error for a sensor whose
// entire job is to be attacked.
//
// The POST body is deliberately NOT decoded here. It arrives as raw bytes
// and stays that way: inventing a form parser to unescape it would mean
// guessing which content type the attacker meant, and a body that
// arrives already containing the literal byte -- which is what an
// exploit client does -- is caught either way. Percent-encoded bodies
// are a known miss, not an oversight.
func queryForShape(r *http.Request) string {
	if unescaped, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
		return unescaped
	}
	return r.URL.RawQuery
}

// FOLLOW-UPS, deliberately not code in this change
//
//   - CVE-2026-88772 needs a UDP/DTLS listener before it can be detected
//     at all (see the header). A new exposed transport is a deception-
//     design change with its own review, the same call #3032 (a) recorded
//     for the AAA/SAML surface, so it belongs in its own issue.
//   - CVE-2026-88773 (HTTP request smuggling, CWE-444, 9.3, "HTTP
//     Configuration enabled") is a real request-shape CVE and the
//     contradictory-framing-header classifier the issue sketches would
//     match it. It is not reported exploited (watchTowr's table), it is
//     outside the "88771 + 88772" scope this change was given, and
//     http-honeypot already has Content-Length handling to sit alongside,
//     so it belongs in the http-honeypot per-CVE file work (#3464) rather
//     than here.
//   - A "probe with no preceding session-establishment request" classifier
//     (the issue's Signal A bullet 1) needs per-source connection state,
//     which no classifier in this package holds today. Worth doing, and
//     worth doing once there is a stateful base to hang it on.
//   - When a real PoC or a Citrix-published wire-level indicator exists,
//     this is the place it goes: add the confirmed literal with its
//     primary-source citation and drop the "inferred" from the event name.
//     Until then it stays where it is.
