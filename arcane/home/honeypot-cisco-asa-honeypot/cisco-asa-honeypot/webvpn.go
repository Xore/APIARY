// webvpn.go ports asa_server.py's WebLogicHandler (#238, #414): the Cisco
// ASA WebVPN HTTPS decoy for CVE-2018-0101 (a crafted host-scan-reply POST
// body crashes/exploits a real ASA; here it's just captured and logged).
package main

import (
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// asaFiles mimics upstream's asa/ directory: send_file(filename) looks up
// a file by basename only (SimpleHTTPRequestHandler.send_file semantics),
// regardless of the rest of the request path.
var asaFiles = map[string]string{
	"wrong_url.html":   ciscoWrongURLPage,
	"logon_redir.html": ciscoLogonRedirPage,
	"logon_failure":    ciscoLogonFailurePage,
	"logon.html":       ciscoLogonPage,
	"blank.html":       "",
	"index.html":       ciscoRootRedirectPage,
}

const exploitString = "host-scan-reply"

// canned VPN-parse-error response upstream always returns for a POST that
// isn't specifically handled otherwise (WebLogicHandler.RESPONSE).
const asaParseErrorResponse = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<version who="sg">9.0(1)</version>
<error id="98" param1="" param2="">VPN Server could not parse request.</error>
</config-auth>`

type webvpnHandler struct {
	log  *logger
	port int
}

func webvpnSrcIP(r *http.Request) (string, int) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func (h *webvpnHandler) log2(r *http.Request, kind, reqPath, data string) {
	ip, port := webvpnSrcIP(r)
	h.log.emit(event{Port: h.port, SrcIP: ip, SrcPort: port, Event: kind, Path: reqPath, Data: data,
		UserAgent: r.UserAgent(), Headers: webvpnHeaderMap(r)})
}

// webvpnHeaderMap flattens net/http's []string-per-key header representation
// into one string per key -- which client hit this decoy, and with what
// else, was previously available on every request and simply never read.
func webvpnHeaderMap(r *http.Request) map[string]string {
	m := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

func (h *webvpnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.serveGET(w, r)
	case http.MethodPost:
		h.servePOST(w, r)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func clearedCookies() []string {
	return []string{
		"tg=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpn=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpn_portal=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpnSharePoint=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpnlogin=1; path=/; secure",
		"sdesktop=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
	}
}

func (h *webvpnHandler) redirect(w http.ResponseWriter, loc string) {
	for _, c := range []string{"tg=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"} {
		w.Header().Add("Set-Cookie", c)
	}
	w.Header().Set("Location", loc)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusFound)
}

func (h *webvpnHandler) sendFile(w http.ResponseWriter, name string, status int) {
	body, ok := asaFiles[name]
	if !ok {
		if name != "wrong_url.html" {
			h.sendFile(w, "wrong_url.html", http.StatusNotFound)
			return
		}
		body = ciscoWrongURLPage
	}
	if status == http.StatusOK {
		for _, c := range clearedCookies()[1:5] {
			w.Header().Add("Set-Cookie", c)
		}
		w.Header().Add("Set-Cookie", "webvpnlogin=1; secure")
		w.Header().Set("Cache-Control", "max-age=0")
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func (h *webvpnHandler) serveGET(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Path
	h.log2(r, "get", reqPath, "")

	// Upstream compares against self.path, which (unlike Go's r.URL.Path)
	// includes the raw query string -- so its bare-path check only matches
	// a request with NO query string at all, and "?reason=1" always falls
	// to the second branch instead. Checking RawQuery here keeps that
	// same precedence.
	if reqPath == "/+CSCOE+/logon.html" && r.URL.RawQuery == "" {
		h.redirect(w, "/+CSCOE+/logon.html?fcadbadd=1")
		return
	}
	if reqPath == "/+CSCOE+/logon.html" && strings.Contains(r.URL.RawQuery, "reason=1") {
		h.sendFile(w, "logon_failure", http.StatusOK)
		return
	}

	if reqPath == "/" {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Pragma", "no-cache")
		for _, c := range clearedCookies() {
			w.Header().Add("Set-Cookie", c)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(ciscoRootRedirectPage))
		return
	}

	name := path.Base(strings.TrimRight(strings.SplitN(reqPath, "?", 2)[0], "/"))
	if name == "asa" {
		h.sendFile(w, "wrong_url.html", http.StatusForbidden)
		return
	}
	h.sendFile(w, name, http.StatusOK)
}

func (h *webvpnHandler) servePOST(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	h.log2(r, "post", r.URL.Path, string(body))

	respBody := asaParseErrorResponse

	if strings.Contains(string(body), exploitString) {
		if payloads := parseHostScanReplies(body); len(payloads) > 0 {
			for _, p := range payloads {
				h.log2(r, "cve_2018_0101_payload", r.URL.Path, p)
			}
		}
	} else if r.URL.Path == "/" {
		h.redirect(w, "/+webvpn+/index.html")
		return
	} else if r.URL.Path == "/+CSCOE+/logon.html" {
		h.redirect(w, "/+CSCOE+/logon.html?fcadbadd=1")
		return
	} else if strings.SplitN(r.URL.Path, "?", 2)[0] == "/+webvpn+/index.html" {
		respBody = ciscoLogonRedirPage
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(respBody))
}

// parseHostScanReplies extracts every <host-scan-reply> element's text
// content, matching upstream's `xml.iter('host-scan-reply')`. Malformed
// XML (a crafted exploit attempt need not be well-formed) yields no
// payloads rather than an error -- an honeypot has no obligation to make
// sense of attacker input, only to never crash on it.
func parseHostScanReplies(data []byte) []string {
	type node struct {
		XMLName xml.Name
		Content string `xml:",chardata"`
		Nodes   []node `xml:",any"`
	}
	var root node
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil
	}
	var out []string
	var walk func(n node)
	walk = func(n node) {
		if n.XMLName.Local == "host-scan-reply" {
			out = append(out, strings.TrimSpace(n.Content))
		}
		for _, c := range n.Nodes {
			walk(c)
		}
	}
	walk(root)
	return out
}
