package main

// #3309's two classes, and the three helpers both of them need.
//
// Two cases rather than one because they are two different readings of the
// same CVE. The pagename case is traversal in `pagename`; the template
// case is everything the pagename case cannot reach, which is most of what
// the flaw actually allows. Splitting the CVE across two branches is what
// #3425 and #3449 did, and the dispatch in classify.go is where they meet.

import (
	"net/url"
	"strings"
)

// decodeUpTo percent-decodes s up to rounds times, stopping as soon as a
// round changes nothing or stops being decodable. Three rounds is the budget
// the CVE-2026-87902 cases allow, because the whole point of the CVE is that
// the target application decodes the value again after the web server has
// already decoded it once.
func decodeUpTo(s string, rounds int) string {
	full := s
	for i := 0; i < rounds; i++ {
		next, err := url.QueryUnescape(full)
		if err != nil || next == full {
			break
		}
		full = next
	}
	return full
}

// formValues splits a query string or form body into key/value pairs the way
// the application being attacked does, which is not always the way
// url.ParseQuery does.
//
// The difference that matters is the semicolon. Since Go 1.17
// url.ParseQuery rejects any pair containing one and drops it; PHP's only
// separator is "&", so `data://text/plain;base64,...` arrives at WordPress as
// a single value with its media type intact -- and the sensor, parsing it the
// Go way, could not see the parameter at all. Using the stricter parser would
// drop exactly the values worth seeing, in both WordPress cases: the CVE
// works because the target decodes what the web server hands it, so the
// classification has to be done on the bytes the target will parse.
//
// Deliberately minimal -- split on "&", then on the first "=", then unescape
// each side. An undecodable side is kept exactly as it arrived rather than
// dropped, because a deliberately broken escape is a way of hiding a payload
// and the bytes are still worth matching.
func formValues(raw string) url.Values {
	out := url.Values{}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		out.Add(formUnescape(key), formUnescape(value))
	}
	return out
}

// formUnescape percent-decodes one side of a form pair, returning it
// unchanged when it will not decode. A malformed escape is a way of varying a
// probe's appearance without changing what it means, so the raw bytes are
// kept rather than discarded.
func formUnescape(s string) string {
	if unescaped, err := url.QueryUnescape(s); err == nil {
		return unescaped
	}
	return s
}

// wordpressPagenameTraversal reports a `pagename` parameter -- in the query
// or a form-encoded body -- carrying traversal. Double encoding is the tell:
// after the one decode formValues does, a legitimate page slug never still
// contains an encoded dot, slash or backslash, and a fully decoded one never
// contains "../". Parameters are parsed, not substring-matched, so "pagename"
// inside some other value cannot trigger it.
//
// CVE-2026-87902 (KEV 2026-09-25): WordPress resolves the page template from
// `pagename`, which it urldecodes once more itself, so a double-encoded
// traversal walks out of the theme directory into any readable .php --
// pearcmd.php for RCE. The class sits near the top of the dispatch for that
// reason: pearcmd-rce is this chain's second stage and would otherwise claim
// the request, which is a lie about where the attacker was when the traversal
// happened. Zero matches in the 30 days before this landed; the traffic that
// looks similar (theme css.php?files=../, index.php pearcmd LFI) has no
// pagename and keeps its own class.
func wordpressPagenameTraversal(c classifyInput) bool {
	return wordpressPagenameTraversalCase(c.Query, c.Body)
}

// wordpressPagenameTraversalCase carries the (query, body) half. It exists so
// the body of the rule is the same bytes main.go ran before this file existed,
// with the #3449 semicolon fix already folded in, and so the signature the
// case had there is still callable from a test.
func wordpressPagenameTraversalCase(query, body string) bool {
	for _, raw := range []string{query, body} {
		for key, vals := range formValues(raw) {
			if !strings.EqualFold(key, "pagename") {
				continue
			}
			for _, v := range vals {
				once := strings.ToLower(v)
				if containsAny(once, "%2e", "%2f", "%5c") {
					return true
				}
				if containsAny(decodeUpTo(once, 3), "../", "..\\") {
					return true
				}
			}
		}
	}
	return false
}

// wpCorePaths are the strings that say "this request is aimed at WordPress"
// without being the attacker's target file. wp-config.php is deliberately
// absent: naming a file is what an attacker does, and treating that as proof
// of what application was being attacked is how a real disclosure probe ends
// up filed as a WordPress CVE.
var wpCorePaths = []string{
	"wp-content/", "wp-includes/", "wp-json", "wp-admin/",
	"wp-login.php", "wp-blog-header.php", "wp-load.php",
}

// wordpressTemplateInclusion reports CVE-2026-87902 (WordPress Core
// unauthenticated local PHP file inclusion) reached in a way the
// pagename-traversal case above cannot see: a stream wrapper or a remote URL
// instead of a `../`, or one of the other parameters that name a template.
//
// The gate is the request's shape and the payload is a requirement on top of
// it, and the order is the design. Three things must be true, and any one of
// them alone is ordinary traffic:
//
//   - a template selector is present -- pagename, page_template, template,
//     theme or stylesheet, the parameters WordPress resolves through its page
//     template hierarchy;
//   - a WordPress signal that is not the attacker's target is present -- the
//     routing variables WordPress Core reads (page_id, the CVE's documented
//     precondition, and rest_route, WordPress's own REST multiplexer), or a
//     WordPress core path in a value;
//   - and an inclusion payload sits in a template selector: traversal, a PHP
//     stream wrapper, a remote URL, or -- the advisory's third indicator --
//     PEAR command syntax in the query string of a WordPress front end.
//
// The second condition is the one that keeps this from being a wider
// `pagename` check. `pagename` and `template` are WordPress query variables,
// which is not the same as being a WordPress-only parameter name, and a
// scanner probing one application must not have its generic LFI relabelled as
// somebody else's CVE. Requiring a second, WordPress-owned signal is
// deliberately the stricter choice: a probe that sends a wrapper in
// `pagename` and nothing else is left unlabelled rather than guessed at.
//
// The query and the body are read together rather than one at a time, because
// WordPress merges them: WP::parse_request() builds its query variables from
// $_GET plus $_POST, and the verified PoC depends on that -- its routing
// travels in the form body while PEAR's argv travels in the raw query string,
// because PHP splits the query on literal `+` without decoding the
// arguments. Checked one bag at a time, that request has a WordPress half and
// a PEAR half and no reason to connect them.
//
// Nothing here resolves a path. A request-supplied name is never joined to a
// directory, opened, stat'd or included -- formValues splits a string into
// key/value pairs and every value is matched as bytes, which is the same
// contract wordpressPagenameTraversal has.
func wordpressTemplateInclusion(c classifyInput) bool {
	return wordpressTemplateInclusionCase(c.Query, c.Body)
}

// wordpressTemplateInclusionCase carries the (query, body) half, for the same
// reason as the pagename case above: the rule itself keeps the signature it
// had in main.go, and the dispatch's classifyInput is unwrapped here.
func wordpressTemplateInclusionCase(query, body string) bool {
	shape, selectors := false, []string(nil)
	for _, raw := range []string{query, body} {
		for key, vals := range formValues(raw) {
			lower := strings.ToLower(key)
			if lower == "page_id" || lower == "rest_route" {
				shape = true
			}
			if lower == "pagename" || lower == "page_template" || lower == "template" ||
				lower == "theme" || lower == "stylesheet" {
				selectors = append(selectors, vals...)
			}
			for _, v := range vals {
				if containsAny(strings.ToLower(v), wpCorePaths...) {
					shape = true
				}
			}
		}
	}
	if !shape || len(selectors) == 0 {
		return false
	}
	for _, v := range selectors {
		if wordpressInclusionPayload(v) {
			return true
		}
	}
	// The PEAR stage. The existing pearcmd-rce case needs both markers in the
	// query string, which a split request never has: the advisory tells
	// defenders to look for "+config-create+" in the query of a request to
	// the WordPress front end, and that is a pair this classifier alone can
	// see. Both needles are PEAR's own vocabulary and cannot appear in
	// ordinary traffic.
	return containsAny(strings.ToLower(query), "config-create", "pearcmd") ||
		containsAny(strings.ToLower(body), "config-create", "pearcmd")
}

// wordpressInclusionPayload reports one template-bearing value that is trying
// to make the server include something -- the second half of
// wordpressTemplateInclusion.
//
// Three families, all of them things the target application would hand to an
// include or a stream-wrapper resolver:
//
//   - traversal, at either depth, since the CVE's mechanism is a late
//     urldecode() that a scanner which has read the advisory will pre-empt;
//   - a PHP stream wrapper. `php://filter` is the interesting one here: it
//     reads an arbitrary file and base64-encodes it, with no traversal at
//     all, so the traversal-only cases cannot see it. `pear://` is not in
//     this list because PHP has no such wrapper -- the PEAR stage is caught
//     by the command channel instead;
//   - a remote include, which is the same primitive pointed at the
//     attacker's own host.
//
// What is left out is the point of the exercise. A bare "..", a slug with a
// double dot in it, and a relative path that walks up and back down are all
// absent on purpose: they are what an ordinary WordPress front end is full
// of, and one false positive here puts this class on ordinary page views.
func wordpressInclusionPayload(v string) bool {
	once := strings.ToLower(v)
	full := decodeUpTo(once, 3)
	// Traversal. In `once` the dots are still encoded, which is the shape
	// wordpressPagenameTraversal looks for; in `full` they have come back.
	if containsAny(once, "%2e%2e", "%252e") || containsAny(full, "../", "..\\") {
		return true
	}
	// Wrappers and remote URLs are matched at both depths for the same
	// reason: the value reaches the target after one more urldecode() there,
	// so a probe that pre-encodes the scheme must not read as harmless.
	if containsAny(once, phpStreamWrappers...) || containsAny(full, phpStreamWrappers...) {
		return true
	}
	return containsAny(once, remoteIncludeSchemes...) || containsAny(full, remoteIncludeSchemes...)
}

// phpStreamWrappers and remoteIncludeSchemes are the inclusion primitives
// above. Every needle is a scheme followed by its delimiter, never a bare
// word: "php" and "data" are ordinary parameter values, and a scheme without
// its "//" is not a wrapper.
var (
	phpStreamWrappers = []string{
		"php://", "phar://", "data://", "data:text/", "expect://",
		"zip://", "glob://", "rar://", "ogg://", "compress.zlib://",
	}
	remoteIncludeSchemes = []string{"http://", "https://", "ftp://", "ftps://"}
)
