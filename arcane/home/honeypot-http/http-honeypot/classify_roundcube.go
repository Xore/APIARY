package main

// #3364's class. The case and every helper it needs are in this file, so a
// change to it touches one new-ish file and one line of the dispatch in
// classify.go, and nothing else in this package.

import (
	"net/url"
	"strings"
)

// roundcubeVirtuserSQLi reports a pre-authentication SQL injection aimed at
// Roundcube Webmail's virtuser_query plugin (CVE-2026-48842). CVSS 8.1; the
// Canadian Centre for Cyber Security's AV26-503 (2026-09-21) reports it
// exploited in the wild and has published no exploitation detail, so the shape
// below comes from the advisory and the product's own dispatch, not from a
// capture. The value the plugin is handed is escaped with preg_replace(), and
// a backslash inside the value defeats that escape, so what to match is a SQL
// payload on one of Roundcube's own dispatch parameters -- not a path. A real
// attack goes to whatever endpoint the application's dispatch resolves, which
// is the same reason #2919 and #3309 matched on the request's own bytes: a
// bait path for it would never match, because the path in a real attack is
// not ours.
//
// The gate is the request's shape and the payload is a requirement on top of
// it, in that order, and the order is the whole design. Roundcube addresses
// its own requests with a small set of dispatch parameters: `?_task=login`
// IS the login form, and `?_action=plugin.<name>` is a plugin endpoint, so
// both are reachable with no session and no credential -- which is the
// pre-auth half of the CVE. The plugin can also be named outright, as a
// parameter key or as the value of `_action`, which is how a scanner that
// knows the endpoint addresses it directly.
//
// Both halves are required because each alone is ordinary traffic. A request
// that merely names virtuser_query is a scanner enumerating plugins, and a
// request that merely carries SQL is somebody else's class -- the generic
// sqli case in classify_generic.go, or nothing at all when the payload rides
// in the query string, which that case does not read. A login form is the one
// route where a wrong label is guaranteed to cost something, because mail
// addresses contain apostrophes and this classifier is the thing reading them.
//
// Parameters are parsed, not substring-matched, for the reason
// wordpressPagenameTraversal gives: the text "virtuser_query" inside some
// other value must not trigger this, and neither must a payload that happens
// to contain "_task". Nothing is deserialized and nothing is evaluated --
// url.ParseQuery splits a string into key/value pairs, and every value is
// then matched as bytes.
//
// Its place in the dispatch is first, ahead of the generic sqli class,
// because a Roundcube probe is often both at once -- the same value is caught
// there when it happens to use one of that case's six tokens and unnamed
// otherwise. This class says which CVE, and that no session was needed to
// reach it.
//
// Not measured against the fleet's corpus: #3364 marks the coverage gap
// as unmeasured and the corpus is not reachable from here. What the
// tests pin instead is the boundary that decides whether the class is
// usable -- a real Roundcube login, an apostrophe in a mail address and
// a bare plugin enumeration each keep their own answer -- and, in
// classify_order_3464_test.go, that this class still beats sqli.
//
// Cost is bounded the way the rest of the classifier is: the body was
// already capped at 64 KiB by ServeHTTP, and every needle here is a
// plain substring search over one parameter value, so the whole case is
// a fixed number of linear passes over bytes already in memory.
func roundcubeVirtuserSQLi(c classifyInput) bool {
	for _, raw := range []string{c.Query, c.Body} {
		values, err := url.ParseQuery(raw)
		if err != nil && len(values) == 0 {
			continue
		}
		roundcube := false
		for key, vals := range values {
			// The dispatch parameters, and the plugin named as a key.
			// Matched whole rather than by substring: a key called
			// "_task_id" is some other application's, and "_user" -- the
			// field the lookup is actually handed -- carries no such
			// meaning, so the value check below is what decides that half.
			if strings.EqualFold(key, "_task") || strings.EqualFold(key, "_action") ||
				strings.EqualFold(key, "virtuser_query") || strings.EqualFold(key, "virtuser") {
				roundcube = true
			}
			// The plugin named as a value, in both the forms Roundcube
			// dispatches it: "virtuser_query" and "plugin.virtuser_query".
			// A test, not a Contains, so a path or a parameter whose name
			// merely starts with the plugin's does not open the gate.
			for _, v := range vals {
				switch v {
				case "virtuser_query", "plugin.virtuser_query":
					roundcube = true
				}
			}
		}
		if !roundcube {
			continue
		}
		for _, vals := range values {
			for _, v := range vals {
				if roundcubeSQLPayload(v) {
					return true
				}
			}
		}
	}
	return false
}

// roundcubeSQLPayload reports a parameter value that is trying to break out
// of a SQL string literal -- the second half of roundcubeVirtuserSQLi.
//
// The token list is the generic sqli case's, widened. This runs per
// parameter value, so it sees a value rather than a whole body, and the
// families the generic case does not name -- schema enumeration, error-based
// extraction, pg_sleep -- are the ones a webmail login probe reaches for
// once the escape is defeated. Every needle is a metacharacter sequence with
// no ordinary parameter value behind it, because the cost of a wrong label
// here is every Roundcube login in the corpus turning into an alert.
//
// Matching is case-insensitive, the way the generic sqli case effectively is
// (it matches a lowercased body). SQL keyword case is the cheapest encoding
// variation there is -- the note on classifyPayload records the PHP-CGI
// probe arriving as %ADd, %25ADd and plain -d in one window -- and a class
// that matches only the published casing loses the event outright:
// measured, an uppercase `UNION SELECT` through the gate was unlabelled
// on both GET and POST (#3364).
func roundcubeSQLPayload(v string) bool {
	v = strings.ToLower(v)
	return containsAny(v,
		// A quote closed and the rest of the statement appended.
		"';", "'--", "' #", "'/*", "')",
		// Tautologies -- the cheapest thing to automate.
		"' or '", "or 1=1", "or 1'='1", "or '1'='1", "and 1=1",
		// Union, and the schema table that makes a union worth running.
		"union select", "union all select", "information_schema",
		// Time- and error-based, including the PostgreSQL sleep a
		// Roundcube install is as likely to be behind as MySQL.
		"sleep(", "benchmark(", "waitfor delay", "extractvalue(", "updatexml(") ||
		pregReplaceEscapeBypass(v)
}

// pregReplaceEscapeBypass is the other half of roundcubeSQLPayload, and the
// only part of this classifier that looks at a backslash.
//
// The root cause of CVE-2026-48842 is an escaping routine whose backslash
// handling can be defeated from inside the value it is escaping: a backslash
// immediately before the quote turns the escape into a second backslash and
// the quote closes the literal anyway. So the byte pattern worth naming is
// the pair -- backslash-quote plus a SQL metacharacter in the same value --
// and not the injection alone, which is what the generic sqli case already
// looks for.
//
// Both halves are required, and that is not belt-and-braces. On a webmail
// login form the two halves are each ordinary on their own: a lone backslash
// is a Windows path, a JSON escape or a regex, and a lone apostrophe is a
// name like O'Brien -- an address this classifier would otherwise label as
// an attack on a route whose entire job is receiving mail addresses. The
// metacharacter is what makes the escape an attempt.
//
// The metacharacter list is SQL punctuation only. A bare "-" is left out
// deliberately: it is a hyphen in an address or a date, and admitting it
// would put this class straight back on ordinary mail traffic.
func pregReplaceEscapeBypass(v string) bool {
	i := strings.Index(v, `\'`)
	if i < 0 {
		return false
	}
	rest := v[:i] + v[i+2:]
	return containsAny(rest, "'", `"`, ";", "--", "#", "/*", "*/", "=", ")")
}
