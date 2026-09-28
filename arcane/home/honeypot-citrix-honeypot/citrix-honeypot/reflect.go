package main

// #3446: the decoy's echo/serialisation path.
//
// Three response bodies on this sensor put a value that arrived in the
// request back into the reply:
//
//   - citrix403Page's "{url}"          (the collapsed request path)
//   - citrixWSFedTemplate's "{wctx}"   (a query parameter)
//   - oidcDiscoveryJSON's "base"       (the Host header, in seven fields)
//
// All three are attacker-controlled output. Two of them were already
// escaped for their output context when the pages were first ported; none of
// them was bounded, and the Host one was never checked for being a host at
// all. That gap is this file.
//
// THE RULE, stated once so there is one thing to audit and one thing to
// change if it ever needs to:
//
//	Reflect a request value only when the destination can legitimately carry
//	it, and never more of it than a real client of that surface would send.
//	Encode it for the destination's context. Never delete parts of it.
//
// Read in that order, it is three decisions, and each one rules out the
// other two options rather than merely being one of them:
//
//  1. REFLECT, DO NOT DELETE. These are the decoy's own decoy behaviours.
//     A WS-Federation passive requestor sends wctx and expects to see its
//     own context echoed back; a traversal scanner hits the 403 page and
//     reads its own path in it. A sanitiser that stripped characters would
//     make both surfaces lie, and the resulting mangle (a URL with its
//     query punctuation eaten) is itself a fingerprint -- "this appliance
//     mangled my context" tells a scanner it is not talking to the product
//     it is fingerprinting. Deleting is also the wrong shape of control for
//     a trust boundary: it is the option whose failure mode is a bypass
//     whenever the character set guessed wrong. Escaping is the option that
//     fails closed.
//
//  2. ESCAPE FOR THE DESTINATION, NOT FOR THE SOURCE. An HTML attribute
//     value gets HTML escaping. A JSON string gets JSON encoding. Neither
//     is "sanitise the input", and neither substitutes for (3): escaping
//     controls what the *bytes* can do, not how much text an attacker gets
//     to place.
//
//  3. BOUND IT, AND DROP WHAT IS OVER THE BOUND RATHER THAN TRUNCATING IT.
//     Go's default http.Server.MaxHeaderBytes is 1 MiB
//     (http.DefaultMaxHeaderBytes; this server leaves it unset), so
//     without a bound an attacker chooses the size of the decoy's own
//     response -- measured at 1,048,909 bytes of body for a 1 MiB wctx on
//     this sensor, and roughly 5x that again once the Host is repeated
//     across seven fields of the discovery document. Over the bound the
//     value is not reflected at all: the template's own empty form is
//     served, which is byte-for-byte what this decoy already answers for a
//     request that carried no such parameter, so an over-long value is
//     indistinguishable from a client that did not send one.
//
//     Drop rather than truncate, specifically: a truncated value is neither
//     what the client sent nor what a real appliance emits, so it turns the
//     bound into a fingerprint; it can also cut a multi-byte rune in half;
//     and it leaves the attacker a partial write, which is a strictly worse
//     outcome than the empty form. Nothing is silently mangled: the value
//     is either reflected in full or not reflected at all.

import (
	"html"
	"net"
	"strconv"
	"strings"
)

// personaAsset is this decoy's own appliance name -- the same string every
// event already carries in its `asset` field. It is also the fallback when a
// request's Host header is not a host (see sanitiseAuthority), chosen so the
// fallback is persona-consistent rather than a value invented for the
// failure branch: an operator reading two events from this sensor should not
// see two different names for the same box.
const personaAsset = "citrixgw01"

// maxReflectedBytes bounds how much of a request value any decoy body will
// echo, measured on the INPUT rather than the escaped output, so the bound
// is a statement about what an attacker sends rather than about what
// escaping happens to expand it to.
//
// 4 KiB. Every legitimate value this sensor reflects is orders of magnitude
// smaller: a wctx is a relay-state context (an opaque token, or a URL a few
// hundred bytes long), and a request path is a path. The bound is also
// 256x below the 1 MiB of header the server will accept, so the
// unbounded-reflection case is closed by a wide margin rather than a
// hair's breadth, and the largest body the decoy can be made to emit on
// these paths is ~4 KiB of input expanding to at most 5x that
// (html.EscapeString turns every "&" into "&amp;").
const maxReflectedBytes = 4096

// maxAuthorityBytes bounds a reflected Host header. RFC 1035 caps a DNS
// name at 253 octets; 255 leaves room for the shortest realistic ":port"
// and is far above any hostname a scanner sends at a decoy. Not derived
// from Go's 1 MiB header cap, because the point of this one is that the
// value has to BE a host -- the size is only the cheap half of the check.
const maxAuthorityBytes = 255

// maxDNSLabelBytes is RFC 1035's per-label limit.
const maxDNSLabelBytes = 63

// sanitiseHTML prepares v for substitution into an HTML text or attribute
// position in a decoy body. See the rule at the top of this file: escape for
// the destination, bound the input, drop rather than truncate.
//
// The empty string is both "no value supplied" and "value refused": the
// templates this feeds (citrixWSFedTemplate, citrix403Page) already carry an
// empty value at the substitution point, so an over-long reflection and an
// absent one produce the same response.
func sanitiseHTML(v string) string {
	if len(v) > maxReflectedBytes {
		return ""
	}
	return html.EscapeString(v)
}

// sanitiseAuthority prepares a request's Host header for use as the base of
// the decoy's own self-referencing URLs (RFC 8414's discovery document
// builds every one of its endpoint URLs off the authority the request
// arrived on, the way a real appliance behind one vserver does).
//
// This one is accept-or-fall-back rather than escape, and deliberately so.
// The value's STRUCTURE is what reaches the response here -- it is not
// being dropped into one attribute, it is the prefix of seven URL fields --
// so escaping, which is already applied downstream by json.Marshal, cannot
// change what an attacker achieves: they still get to choose the text of
// every field in the document. The only control that removes that choice is
// requiring the value to be the thing the document's grammar says it is, a
// host. A Host that is not a host is not reflected; the decoy's own persona
// asset is used instead, and the document is otherwise unchanged, so the
// response stays a complete, well-formed discovery document either way.
//
// Falling back rather than refusing the request is what keeps this in
// persona: the decoy answers every auth-surface probe, and a 400 or a 404
// here would be the one response a real NetScaler AAA vserver never gives.
func sanitiseAuthority(host string) string {
	if validAuthority(host) {
		return host
	}
	return personaAsset
}

// validAuthority reports whether s is a syntactically valid HTTP authority:
// a DNS name or an IP literal, with an optional port. Anything else -- a
// space, a quote, a control character, a path, a scheme, an over-long name,
// an unbracketed IPv6 literal -- is not a host and is not reflected.
func validAuthority(s string) bool {
	if s == "" || len(s) > maxAuthorityBytes {
		return false
	}

	name, port, hasPort := splitAuthority(s)
	if hasPort && !validPort(port) {
		return false
	}
	return validAuthorityHost(name)
}

// splitAuthority separates an authority into its host and port. The bracketed
// IPv6 form is handled first because an IPv6 literal contains colons of its
// own, so splitting those would cut the address in half and reject a host
// that is perfectly valid.
func splitAuthority(s string) (host, port string, hasPort bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			// Unterminated bracket: not an authority this function can
			// reason about. Hand the whole string to validAuthorityHost,
			// which will reject it.
			return s, "", false
		}
		host = s[:end+1]
		if rest := s[end+1:]; rest != "" {
			if rest[0] != ':' {
				return s, "", false
			}
			return host, rest[1:], true
		}
		return host, "", false
	}

	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// validPort accepts a decimal TCP port. No sign, no whitespace, no leading
// "+", and a value in range: a Host header that fails any of those is not
// carrying a port number a real client would have sent.
func validPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// validAuthorityHost reports whether h is an IP literal or a DNS name.
//
// The DNS check is deliberately the strict RFC 1035 preferred form: letters,
// digits and hyphens only, 1-63 octets per label, no label starting or
// ending in a hyphen, at least one label. That excludes "_" and every
// non-ASCII byte, which a virtual host a scanner is fingerprinting never
// carries, and it means the value that ends up in the document is one whose
// shape is fixed by a published grammar rather than by this function's
// taste -- the difference between a whitelist and a filter.
func validAuthorityHost(h string) bool {
	if h == "" {
		return false
	}

	// An IPv6 literal in a Host header is bracketed (RFC 3986 3.2.2), and
	// Go's r.Host preserves the brackets.
	if strings.HasPrefix(h, "[") {
		return strings.HasSuffix(h, "]") && net.ParseIP(h[1:len(h)-1]) != nil
	}
	if net.ParseIP(h) != nil {
		return true
	}

	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > maxDNSLabelBytes {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
