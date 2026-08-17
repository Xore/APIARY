package main

// honeyfs_implant_client.go -- #1487 items 3/5: HTTP client for the
// honeyfs-implant service (arcane/home/honeypot-cowrie/honeyfs-implant,
// merged in #1553 -- "live honeyfs implant primitive for #1487 items
// 2/3/5"). WireGuard-tunnel-only, same posture as canarytokens_client.go's
// own CANARYTOKENS_API_URL; see that file's header for the shared
// reasoning this mirrors.
//
// This is the dashboard-side half of #1487 item 3 (credential provisioning/
// rotation). Per the design comment on #1487: "a credential is just another
// honeyfs artifact ... Rotation = calling implant again with new content."
// credentials_manager.go's rotate path does exactly that -- it calls
// implant() a second time at the same path with a freshly rendered body,
// there is no separate "rotate" verb on the wire.
//
// Request/response shape confirmed against honeyfs-implant/main.go
// (#1553's merged diff), not guessed:
//
//	POST /implant  {"path", "content_base64", "memo"} JSON
//	               -> {"ok", "path", "bytes_written", "error"}
//
// content_base64 is base64-encoded raw artifact bytes; path is relative to
// the honeyfs root (e.g. "home/mwagner/.aws/credentials"). This client
// handles the base64 encoding itself -- callers pass raw bytes.
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const honeyfsImplantRequestTimeout = 20 * time.Second

// honeyfsImplantMaxResponseBytes bounds the response read -- /implant only
// ever answers a small JSON status object, never the artifact itself.
const honeyfsImplantMaxResponseBytes = 1 << 20 // 1MB

type honeyfsImplantClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// newHoneyfsImplantClient returns nil when baseURL is empty -- every call
// site treats a nil client as "live credential/implant actions disabled",
// matching newCanarytokensClient's own nil-when-unconfigured posture.
func newHoneyfsImplantClient(baseURL, token string) *honeyfsImplantClient {
	if baseURL == "" {
		return nil
	}
	return &honeyfsImplantClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: honeyfsImplantRequestTimeout},
	}
}

// honeyfsImplantURLIsLocal mirrors canarytokensAPIURLIsLocal's shape --
// plain http, no credentials/query, host is loopback/link-local/private.
// honeyfs-implant carries a live filesystem-write capability onto a running
// honeypot (compose.yml's own honeyfs-implant service is WireGuard-tunnel
// bound, e.g. 10.8.0.2:19428), so this must never be pointed at a public
// endpoint.
func honeyfsImplantURLIsLocal(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" || u.User != nil || u.RawQuery != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

type honeyfsImplantResult struct {
	Path         string
	BytesWritten int
}

// implant calls POST {baseURL}/implant. path must already be validated as
// honeyfs-root-relative by the caller (credentials_api.go) -- this client
// does not re-derive containment itself, honeyfs-implant's own
// resolveHoneyfsPath (main.go, #1553) is the actual enforcement point, this
// is just belt-and-suspenders on the caller's side.
func (c *honeyfsImplantClient) implant(path string, content []byte, memo string) (*honeyfsImplantResult, error) {
	if c == nil {
		return nil, fmt.Errorf("honeyfs-implant: not configured")
	}
	payload := map[string]any{
		"path":           path,
		"content_base64": base64.StdEncoding.EncodeToString(content),
		"memo":           memo,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL+"/implant", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, honeyfsImplantMaxResponseBytes))
	if err != nil {
		return nil, err
	}
	var result struct {
		OK           bool   `json:"ok"`
		Path         string `json:"path"`
		BytesWritten int    `json:"bytes_written"`
		Error        string `json:"error"`
	}
	if jsonErr := json.Unmarshal(data, &result); jsonErr != nil {
		return nil, fmt.Errorf("honeyfs-implant: malformed response (status %d): %w", resp.StatusCode, jsonErr)
	}
	if !result.OK || resp.StatusCode != http.StatusOK {
		msg := result.Error
		if msg == "" {
			msg = fmt.Sprintf("honeyfs-implant: request failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return &honeyfsImplantResult{Path: result.Path, BytesWritten: result.BytesWritten}, nil
}
