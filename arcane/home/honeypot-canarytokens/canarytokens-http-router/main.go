// canarytokens-http-router -- this repo's own code, not vendored (see
// canarytokens-adapter's own package doc for the sibling pattern this
// follows). Sits between the publicly-reachable HTTP channel port and
// canarytokens-switchboard, fixing two confirmed-live gaps in the vendored
// platform itself that block a real, correctly-created HTTP-triggered
// token (PDF, Word, Excel, custom-image, QR, Windows-folder) from ever
// actually alerting when opened outside this network:
//
//  1. canarydrop.generate_random_hostname() (canarytokens/tokens.py)
//     always prepends the token's own random value as a DNS subdomain of
//     CANARY_DOMAINS/CANARY_NXDOMAINS -- every one of those token types'
//     embedded trigger action is therefore an HTTP request to
//     http://<token>.<domain>/<random-padding-path>. But
//     channel_http.py's CanarytokenPage.render_GET looks the token up
//     with Canarytoken(value=request.uri) -- the URI/PATH only, never the
//     Host header. A flat proxy pass-through (what this stack had before)
//     leaves switchboard permanently unable to find the drop: confirmed
//     live, "Failed to find drop for: <mangled path>" for every single
//     hit. This router extracts the subdomain, validates it looks like a
//     real canarytoken (channel_http.py's own alphabet/length constants),
//     and rewrites the request path to `/<token><original path>` before
//     proxying, so switchboard's own regex-based find_canarytoken()
//     actually locates it -- same fix, independent of token type.
//
//  2. Even once switchboard finds the drop, its own per-type dispatch
//     (render_GET's `getattr(Canarytoken, f"_get_info_for_{type}")`)
//     silently no-ops for any type without a matching handler method.
//     Confirmed against both this deployment's pinned commit AND
//     upstream's current master: canarytokens/tokens.py has no
//     _get_info_for_adobe_pdf or _get_info_for_windows_dir at all --
//     switchboard logs "does not support alerting via HTTP" and returns
//     the same generic tracking GIF a real, working hit gets, so this
//     isn't even distinguishable from the response alone. Rather than
//     patch vendored upstream source (this repo's convention elsewhere,
//     e.g. GHOSTS, is to vendor verbatim and route around gaps with our
//     own code instead), this router independently looks the token up in
//     the same Redis instance switchboard itself uses (read-only,
//     canarydrop:<token> hash -- confirmed live against a real drop) and,
//     only for token types on the known-unsupported list, POSTs the same
//     alertPayload shape canarytokens-adapter already expects from
//     switchboard's own WebhookOutputChannel. Every other type's alert
//     still flows through switchboard's own native webhook dispatch,
//     untouched -- this only backstops the types switchboard itself
//     can't.
//
// Every request is proxied to switchboard and its response returned
// unmodified either way; the Redis lookup and webhook POST (goroutine 2)
// never affect what the client (whoever opened the artifact) sees, same
// posture as switchboard's own real hits: no behavioral tell that would
// out this as a tripwire.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// waitForMarker blocks until markerPath exists, polling every 3s. See #128
// (canarytokens-adapter's own copy of this same helper).
func waitForMarker(markerPath string) {
	for {
		if _, err := os.Stat(markerPath); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

// canarytokenRE mirrors canarytokens/constants.py's CANARYTOKEN_ALPHABET
// (0-9a-z) and CANARYTOKEN_LENGTH (25) exactly -- confirmed live against
// the vendored source, not assumed. Anchored: a Host header label is
// either exactly a canarytoken value or it isn't a token subdomain at
// all (never partial-match noise into a false positive).
var canarytokenRE = regexp.MustCompile(`^[0-9a-z]{25}$`)

// unsupportedHTTPTypes is the confirmed set of token types the vendored
// switchboard's channel_http.py has no _get_info_for_<type> handler for
// (grepped live against both this deployment's pinned commit and
// upstream's current master -- not a guess). Every other type dashboard-
// createable type (ms_word, ms_excel, web_image, qr_code) has its own
// handler and fires through switchboard's own native path once this
// router's rewrite makes the drop findable at all; re-check this list
// against tokens.py if CANARYTOKENS_REF is ever bumped.
var unsupportedHTTPTypes = map[string]bool{
	"adobe_pdf":   true,
	"windows_dir": true,
}

type router struct {
	proxy      *httputil.ReverseProxy
	redisAddr  string
	adapterURL string
	httpClient *http.Client
}

func extractToken(host string) (string, bool) {
	host = strings.ToLower(host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i] // strip a port, if the client sent Host: token.domain:443
	}
	label, _, found := strings.Cut(host, ".")
	if !found {
		return "", false
	}
	if !canarytokenRE.MatchString(label) {
		return "", false
	}
	return label, true
}

// hitInfo is a snapshot of exactly the request fields maybeBackstopAlert
// needs, captured before the request is handed to the reverse proxy.
// ReverseProxy.ServeHTTP clones the request it sends upstream rather than
// mutating the original in modern net/http/httputil, but this router
// still runs the alert goroutine fully concurrently with the proxy call
// (ServeHTTP returns as soon as both are started) -- snapshotting avoids
// depending on that implementation detail rather than risking a data
// race on r.Header/r.RemoteAddr across the two goroutines.
type hitInfo struct {
	srcIP     string
	userAgent string
	referer   string
}

func snapshotHit(r *http.Request) hitInfo {
	srcIP := r.Header.Get("X-Forwarded-For")
	if srcIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			srcIP = host
		} else {
			srcIP = r.RemoteAddr
		}
	} else if i := strings.IndexByte(srcIP, ','); i >= 0 {
		srcIP = strings.TrimSpace(srcIP[:i]) // leftmost = original client, same convention this repo already uses elsewhere
	}
	return hitInfo{
		srcIP:     srcIP,
		userAgent: r.Header.Get("User-Agent"),
		referer:   r.Header.Get("Referer"),
	}
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := extractToken(r.Host)
	if ok {
		hit := snapshotHit(r)
		r.URL.Path = "/" + token + r.URL.Path
		r.RequestURI = "" // must be cleared before this leaves as an outbound request
		go rt.maybeBackstopAlert(token, hit)
	}
	rt.proxy.ServeHTTP(w, r)
}

// maybeBackstopAlert looks the token up directly in switchboard's own
// Redis instance and, only for a type confirmed to have no native HTTP
// handler, fires the same webhook payload shape switchboard's own
// WebhookOutputChannel would have sent. Best-effort: every failure path
// just logs and returns, never blocks or affects the proxied response
// (called via `go` in ServeHTTP, already detached from the client).
func (rt *router) maybeBackstopAlert(token string, hit hitInfo) {
	fields, err := redisHGetAll(rt.redisAddr, "canarydrop:"+token)
	if err != nil {
		log.Printf("redis lookup failed for %s: %v", token, err)
		return
	}
	if len(fields) == 0 {
		return // not a real drop -- a request that merely looked token-shaped
	}
	tokenType := fields["type"]
	if !unsupportedHTTPTypes[tokenType] {
		return // switchboard's own handler covers this type; don't double-alert
	}

	payload := map[string]any{
		"channel":    "HTTP",
		"token_type": tokenType,
		"src_ip":     hit.srcIP,
		"src_data": map[string]any{
			"useragent": hit.userAgent,
			"referer":   hit.referer,
		},
		"token":         token,
		"time":          time.Now().UTC().Format("2006-01-02 15:04:05 (MST)"),
		"memo":          fields["memo"],
		"manage_url":    "",
		"public_domain": fields["generated_hostname"],
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("marshal backstop alert for %s: %v", token, err)
		return
	}
	resp, err := rt.httpClient.Post(rt.adapterURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("backstop alert POST for %s (%s) failed: %v", token, tokenType, err)
		return
	}
	resp.Body.Close()
	log.Printf("backstop alert sent for %s (%s), adapter responded %d", token, tokenType, resp.StatusCode)
}

// redisHGetAll speaks just enough RESP (Redis serialization protocol) for
// a single HGETALL -- no client library, matching this repo's other
// small Go services' zero-dependency, scratch-buildable convention.
func redisHGetAll(addr, key string) (map[string]string, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	cmd := fmt.Sprintf("*2\r\n$7\r\nHGETALL\r\n$%d\r\n%s\r\n", len(key), key)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("unexpected RESP reply: %q", line)
	}
	var count int
	if _, err := fmt.Sscanf(line[1:], "%d", &count); err != nil {
		return nil, err
	}
	if count <= 0 {
		return map[string]string{}, nil
	}

	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		bulkHeader, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		bulkHeader = strings.TrimRight(bulkHeader, "\r\n")
		if len(bulkHeader) == 0 || bulkHeader[0] != '$' {
			return nil, fmt.Errorf("unexpected RESP bulk header: %q", bulkHeader)
		}
		var n int
		if _, err := fmt.Sscanf(bulkHeader[1:], "%d", &n); err != nil {
			return nil, err
		}
		if n < 0 {
			values = append(values, "")
			continue
		}
		buf := make([]byte, n+2) // +2 for trailing \r\n
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		values = append(values, string(buf[:n]))
	}

	fields := make(map[string]string, count/2)
	for i := 0; i+1 < len(values); i += 2 {
		fields[values[i]] = values[i+1]
	}
	return fields, nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8083", 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
		return
	}

	waitForMarker("/markers/log-init.done")

	switchboardTarget, err := url.Parse(getenv("SWITCHBOARD_URL", "http://canarytokens-switchboard:8083"))
	if err != nil {
		log.Fatalf("invalid SWITCHBOARD_URL: %v", err)
	}

	rt := &router{
		proxy:      httputil.NewSingleHostReverseProxy(switchboardTarget),
		redisAddr:  getenv("REDIS_ADDR", "canarytokens-redis:6379"),
		adapterURL: getenv("ADAPTER_URL", "http://canarytokens-adapter.internal:8090/"),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	addr := getenv("LISTEN_ADDR", ":8083")
	log.Printf("canarytokens-http-router listening on %s, proxying to %s, redis at %s", addr, switchboardTarget, rt.redisAddr)
	if err := http.ListenAndServe(addr, rt); err != nil {
		log.Fatal(err)
	}
}
