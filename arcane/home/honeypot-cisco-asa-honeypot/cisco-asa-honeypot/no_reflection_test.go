package main

// #3446, companion to citrix-honeypot's reflect_test.go.
//
// The survey result for this sensor: no decoy response on this stack carries
// a request value. asaFiles maps a basename to a page and a miss falls back
// to wrong_url.html; every Location this handler sets is a constant
// ("/+CSCOE+/logon.html?fcadbadd=1", "/+webvpn+/index.html"); the CVE-2018-0101
// branch answers a fixed XML envelope. The request-derived values it does
// read -- path, query, body, headers -- are recorded on the event, which is
// this sensor's actual job, and the CVE payload is logged rather than
// served.
//
// The test is the standing version of that claim: a marker in every channel,
// every response path swept, nothing allowed to come back. It passed before
// this issue and nothing here changed to make it pass.
//
// Inert: httptest against the handler directly. No listener, no socket.

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNoRequestDataReachesDecoyResponseContent(t *testing.T) {
	const marker = "Zq7XreflectAuditZq7X"

	paths := []string{
		"/", "/index.html", "/logon.html", "/logon_redir.html", "/logon_failure",
		"/blank.html", "/wrong_url.html", "/readme.txt", "/asa",
		"/+CSCOE+/logon.html", "/+CSCOE+/login.html", "/+webvpn+/index.html",
		"/+CSCOE+/" + marker, "/" + marker + "/logon.html",
		"/deep/" + marker + "/logon.html", "/foo/../" + marker,
		"/host-scan-reply", "/" + marker,
	}
	queries := []string{
		"", "?reason=1", "?fcadbadd=1", "?" + marker + "=1",
		"?host=" + marker, "?a=" + marker + "&b=2",
	}

	for _, p := range paths {
		for _, q := range queries {
			for _, method := range []string{"GET", "POST"} {
				req := httptest.NewRequest(method, p+q, strings.NewReader("body="+marker))
				req.Host = marker + ".example.test"
				req.Header.Set("User-Agent", marker)
				req.Header.Set("Referer", marker)
				req.Header.Set("Cookie", marker)
				req.Header.Set("Authorization", "Basic "+marker)
				rec := httptest.NewRecorder()

				newTestWebvpnHandler().ServeHTTP(rec, req)

				if body := rec.Body.String(); containsFold(body, marker) {
					t.Errorf("%s %s%s: request data reached decoy content: %s",
						method, p, q, reflectClip(body))
				}
				for h, vs := range rec.Header() {
					for _, v := range vs {
						// A Location is the one response header an
						// attacker could use to aim a client somewhere
						// else, so it is checked here along with the
						// rest even though every one of them is a
						// constant today.
						if containsFold(v, marker) {
							t.Errorf("%s %s%s: request data reached response header %s: %s",
								method, p, q, h, v)
						}
					}
				}
			}
		}
	}
}

// containsFold is a case-insensitive Contains. Routing comparisons on this
// sensor are case-folded (serveGET and the page lookup both go through
// lowercased path helpers), so a reflection that passes the path through a
// routing variable can arrive case-folded, and a case-sensitive marker check
// would miss exactly the echo this test exists to catch.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// reflectClip trims a decoy body to something a failure message can carry.
// Whole body up to a cap rather than a window around the match: matching is
// case-insensitive and case-folding can move byte offsets, so a window
// computed from the folded index need not land on a rune boundary.
func reflectClip(s string) string {
	const max = 400
	if len(s) <= max {
		return s
	}
	return s[:max] + "...<clipped>"
}
