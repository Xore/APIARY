package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
)

// pageMeta is embedded (anonymously) in every top-level page data struct so
// {{.Nonce}} resolves via Go's promoted-field lookup without every page
// author needing to remember to declare the field themselves (#58). It
// carries only the nonce today; it is the natural place for any future
// per-request rendering value every page needs.
type pageMeta struct {
	Nonce string
}

func (p *pageMeta) SetNonce(n string) { p.Nonce = n }

// nonceSetter is implemented by every *T whose T embeds pageMeta.
type nonceSetter interface {
	SetNonce(string)
}

// renderPage is the single call site every full-page HTML route uses: one
// nonce, one CSP (secHeaders), one Content-Type, one template execution.
// Centralising this (rather than repeating the four-line pattern at each of
// the dashboard's ~18 page routes) is what makes "every route sends the
// nonce-based CSP" a property of one function instead of an invariant every
// handler has to remember to uphold. data must be a pointer to a struct
// embedding pageMeta -- ExecuteTemplate dereferences pointers transparently,
// so the template author never needs to know or care.
func renderPage(w http.ResponseWriter, tmpl *template.Template, name string, data nonceSetter) {
	renderPageStatus(w, tmpl, name, data, http.StatusOK)
}

// renderPageStatus (#1575) is renderPage with an explicit status code, for
// the handful of full-page routes that aren't a plain 200 -- today just the
// catch-all 404 (routes.go). The status must be written after secHeaders
// sets its response headers but before ExecuteTemplate's first Write (which
// would otherwise implicitly commit 200): calling w.Header().Set after
// WriteHeader is a silent no-op, so renderPage can't simply WriteHeader(200)
// itself first and let callers overwrite it.
func renderPageStatus(w http.ResponseWriter, tmpl *template.Template, name string, data nonceSetter, status int) {
	n := nonce()
	secHeaders(w, n)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data.SetNonce(n)
	w.WriteHeader(status)
	// #1323: html/template writes directly to w as it executes, so a
	// failure partway through (a nil pointer the template dereferences, a
	// missing field) leaves the client with a silently truncated page and,
	// without this, no server-side trace of what went wrong at all -- the
	// single call site every full-page route shares, so this one fix
	// covers all of them.
	logTemplateErr(name, tmpl.ExecuteTemplate(w, name, data))
}

// logTemplateErr (#1323) is the shared error path for every
// tmpl.ExecuteTemplate call in the dashboard -- renderPage's own full-page
// routes above, plus the smaller HTML-fragment endpoints (event/ip/payload
// row pagination, the settings modal) that call ExecuteTemplate directly
// since they don't go through renderPage's nonce/CSP setup. A no-op when
// err is nil, so every call site can pass the ExecuteTemplate result
// straight through without its own if-block.
func logTemplateErr(name string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "dashboard: render %q: %v\n", name, err)
	}
}

func nonce() string {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(fmt.Sprintf("generate CSP nonce: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// vncBridgeOrigin (#805) is the read-only VNC bridge's own origin
// (ws://host:port or wss://host), added to connect-src so the sandbox-vnc
// page's browser-side WebSocket connection is not blocked by the same CSP
// that protects every other page here -- opting in only the one origin this
// one page needs, resolved once at startup from SANDBOX_VNC_BRIDGE_WS
// (main.go), empty (no relaxation at all) when that env var is unset.
var vncBridgeOrigin string

func setVNCBridgeOrigin(bridgeWS string) {
	u, err := url.Parse(bridgeWS)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return
	}
	vncBridgeOrigin = u.Scheme + "://" + u.Host
}

func secHeaders(w http.ResponseWriter, nonceValue string) {
	frameSrc := "frame-src 'self'"
	connectSrc := "connect-src 'self' https://tile.openstreetmap.org"
	if vncBridgeOrigin != "" {
		connectSrc += " " + vncBridgeOrigin
	}
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'nonce-"+nonceValue+"'; "+
			// #1020: the vendored Xore/theme's theme.css @imports Google
			// Fonts (Fira Sans/Space Grotesk/Fira Code); its own docs/CSP.md
			// documents fonts.googleapis.com (style-src, for the @import
			// itself) and fonts.gstatic.com (font-src, for the actual font
			// files) as required for any consumer.
			"style-src 'self' 'nonce-"+nonceValue+"' https://fonts.googleapis.com; "+
			// #1224: ECharts' own canvas renderer sets inline style
			// ATTRIBUTES via plain JS DOM property assignment (container.
			// style.cssText = ..., not a <style> tag) -- confirmed live,
			// this genuinely broke chart rendering without an explicit
			// allowance. A bare 'unsafe-inline' on style-src itself
			// wouldn't work here: per the CSP spec (confirmed against
			// Chrome's own console message when this was diagnosed),
			// 'unsafe-inline' is ignored outright wherever a nonce or hash
			// source is ALSO present in that same directive's source list,
			// regardless of order -- so it would need dropping style-src's
			// nonce entirely (weakening its real protection against an
			// injected <style> block) just to unblock attribute mutations.
			// style-src-attr is CSP3's own separate, more specific
			// directive for exactly style="" attribute mutations -- an
			// independent source list from style-src, so its own
			// 'unsafe-inline' isn't shadowed by style-src's nonce, and
			// style-src itself (governing <style> tags/blocks) keeps its
			// full nonce-only protection unchanged.
			"style-src-attr 'unsafe-inline'; "+
			"img-src 'self' data: https://tile.openstreetmap.org; "+
			connectSrc+"; "+
			frameSrc+"; "+
			"font-src 'self' https://fonts.gstatic.com; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}
