package main

// #3446, companion to citrix-honeypot's reflect_test.go.
//
// The survey result for this sensor: no decoy response on this stack carries
// a request value. Both branches of both methods answer with a package-level
// constant (workPlaceLoginPage, amcHopPage, or an empty 200), and the
// request-derived values that are read -- the path that selects a branch,
// the body, the headers, the source IP that keys the AMC relay -- are
// recorded on the event, which is this sensor's actual job.
//
// The test is the standing version of that claim: a marker in every channel,
// every response path swept, nothing allowed to come back. It passed before
// this issue and nothing here changed to make it pass.
//
// Inert: httptest against the handler directly. No listener, no socket, and
// an empty relay URL so the SSRF hop is refused rather than dialled.

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNoRequestDataReachesDecoyResponseContent(t *testing.T) {
	const marker = "Zq7XreflectAuditZq7X"

	paths := []string{
		"/", "/cgi-bin/welcome/welcome.cgi", "/cgi-bin/amc/rollbackConfirm.action",
		"/cgi-bin/amc/" + marker + ".action", "/" + marker,
		"/a/" + marker + "/b", "/cgi-bin/amc/host/ping", "/cgi-bin/amc/x?url=" + marker,
	}
	queries := []string{"", "?" + marker + "=1", "?url=" + marker, "?a=" + marker + "&b=2"}

	for _, p := range paths {
		for _, q := range queries {
			for _, method := range []string{"GET", "POST"} {
				req := httptest.NewRequest(method, p+q, strings.NewReader("body="+marker))
				req.Host = marker + ".example.test"
				req.Header.Set("User-Agent", marker)
				req.Header.Set("Referer", marker)
				req.Header.Set("Cookie", marker)
				rec := httptest.NewRecorder()

				// newTestHandler("") -- no relay target, so relayToAMC
				// refuses without opening a connection.
				newTestHandler("").ServeHTTP(rec, req)

				if body := rec.Body.String(); containsFold(body, marker) {
					t.Errorf("%s %s%s: request data reached decoy content: %s",
						method, p, q, reflectClip(body))
				}
				for h, vs := range rec.Header() {
					for _, v := range vs {
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

// containsFold is a case-insensitive Contains, and it has to be: this
// sensor's path predicates (ssrfRelayPath, amcActionPath,
// welcomeCGIPath) all case-fold, so a reflection that passes the path
// through a routing variable can arrive case-folded, and a case-sensitive
// marker check would miss exactly the echo this test exists to catch.
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
