package main

// #3446, companion to citrix-honeypot's reflect_test.go.
//
// #3446 asked for every decoy that echoes request values into response
// content to be checked, not just the one that surfaced the finding. This
// file is the recorded answer for this sensor: a marker is planted in every
// channel a request can carry a value through, every response branch below
// is swept, and the assertion is that none of it comes back.
//
// It passed before this issue was fixed and nothing here changed to make it
// pass -- that is the point. serve() builds every one of its responses from
// a package-level constant, and the request-derived values it does handle
// (Host, path, query, headers, body) are recorded on the event, which is
// this sensor's actual job. The test exists so the next person who adds a
// template placeholder to a decoy page finds out at `go test` time.
//
// Inert: httptest against the handler directly. No listener, no socket.

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNoRequestDataReachesDecoyResponseContent(t *testing.T) {
	const marker = "Zq7XreflectAuditZq7X"

	paths := []string{
		"/", "/index.html", "/robots.txt", "/version", "/v2/", "/v1/models",
		"/v1/chat/completions", "/manager/html", "/manager", "/jmx-console",
		"/wp-login.php", "/wp-admin", "/wp-admin/install.php", "/readme.html",
		"/xmlrpc.php",
		"/wp-content/plugins/duplicator/readme.txt",
		"/wp-content/plugins/wp-file-manager/readme.txt",
		"/wp-content/" + marker + "/readme.txt", "/wp-content/uploads/x",
		"/pa", "/phpmyadmin", "/pma", "/adminer", "/login", "/admin",
		"/signin", "/app.env", "/.git/config", "/creds.aws", "/d.yml",
		"/e.yaml", "/f.bak", "/latest/meta-data", "/latest/meta-data/iam",
		"/computeMetadata/v1", "/metadata/instance", "/api/v1/pods",
		"/apis/apps/v1", "/" + marker, "/a/" + marker + "/b",
		"/vpn/" + marker + "/login", "/api/v1/users?" + marker + "=1",
	}
	queries := []string{
		"", "?" + marker + "=1", "?pagename=" + marker,
		"?a=" + marker + "&b=2", "?$filter=" + marker,
	}

	for _, p := range paths {
		for _, q := range queries {
			for _, method := range []string{"GET", "POST"} {
				var buf bytes.Buffer
				s := &server{log: &logger{out: &buf}, sensor: "http-honeypot"}
				req := httptest.NewRequest(method, p+q, strings.NewReader("body="+marker))
				req.Host = marker + ".example.test"
				req.Header.Set("User-Agent", marker)
				req.Header.Set("Referer", marker)
				req.Header.Set("Cookie", marker)
				req.Header.Set("Authorization", "Basic "+marker)
				req.RemoteAddr = "203.0.113.9:54321"
				rec := httptest.NewRecorder()

				s.ServeHTTP(rec, req)

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

// containsFold is a case-insensitive Contains, and it has to be: serve()
// routes on strings.ToLower(r.URL.Path), so a reflection that passes the
// path through the routing variable arrives lowercased in the body, and a
// case-sensitive marker check would miss exactly the echo this test exists
// to catch. (Verified: an injected path echo passes a case-sensitive
// check and fails this one.)
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
