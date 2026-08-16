package main

// canarytokens_client.go -- #1487: HTTP client for the self-hosted
// Canarytokens platform's own REST API (canarytokens/frontend/app.py,
// mounted at a deliberately non-guessable ROOT_API_ENDPOINT -- confirmed
// live in #1426, not web-UI-only as the #1415 research pass originally
// assumed). WireGuard-tunnel-only (CANARYTOKENS_API_URL, e.g.
// http://10.8.0.2:19426/<root>) -- see docker-compose.canarytokens.yml's
// own header for why token creation/management itself stays internal even
// though the tokens' own trigger channel (switchboard) is now public
// (vps/traefik/dynamic.yml's honeypot-canarytokens router).
//
// Every request/response shape here is confirmed against the vendored
// source at CANARYTOKENS_REF (canarytokens/Dockerfile), not guessed:
// POST {root}/generate takes {"token_type", "memo", ...} JSON (or a
// multipart form when a file is attached -- required for the web_image
// type's upload), and returns TokenResponse-shaped JSON (token, auth_token,
// token_url, hostname, plus qrcode_png for QR tokens). GET {root}/download
// returns the raw artifact bytes directly (canarytokens/models/common.py's
// TokenDownloadResponse subclasses FastAPI's own Response, not a JSON
// wrapper), with Content-Type/Content-Disposition already set.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// canarytokensTokenType enumerates the token types #1487 actually exposes
// from the dashboard -- a deliberate subset of thinkst/canarytokens' full
// ~28 types, matching #1487's own scope: types that produce a plantable
// file/document artifact or an embeddable image "to use outside the
// honeypot". Credential/AWS-key/listener-service token types (already
// covered internally by #1427's breadcrumb design) stay out of this
// surface.
type canarytokensTokenType string

const (
	canarytokensAdobePDF    canarytokensTokenType = "adobe_pdf"
	canarytokensMSWord      canarytokensTokenType = "ms_word"
	canarytokensMSExcel     canarytokensTokenType = "ms_excel"
	canarytokensCustomImage canarytokensTokenType = "web_image"
	canarytokensWindowsDir  canarytokensTokenType = "windows_dir"
	canarytokensQRCode      canarytokensTokenType = "qr_code"
)

// canarytokensTypeInfo drives both the dashboard's type picker (Label/
// Description/RequiresUpload/SupportsSnippet, serialized to JSON) and the
// server-side dispatch (DownloadFmt/ContentType/FilenameSuffix, matching
// canarytokens/models/common.py's DownloadFmtTypes/DownloadContentTypes
// exactly). DownloadFmt empty means the artifact never goes through
// /download at all -- true only for web_image: no DownloadFmtTypes entry
// exists for it upstream, since a web-bug token's "artifact" is the trigger
// URL itself (see canarytoken_action.go's own comment on why this client
// never fetches it server-side).
type canarytokensTypeInfo struct {
	Label           string `json:"label"`
	Description     string `json:"description"`
	RequiresUpload  bool   `json:"requires_upload"`
	SupportsSnippet bool   `json:"supports_snippet"`
	DownloadFmt     string `json:"-"`
	ContentType     string `json:"-"`
	FilenameSuffix  string `json:"-"`
}

var canarytokensSupportedTypes = map[canarytokensTokenType]canarytokensTypeInfo{
	canarytokensAdobePDF: {
		Label:          "PDF document",
		Description:    "A real PDF that phones home the instant it's opened in Adobe Reader.",
		DownloadFmt:    "pdf",
		ContentType:    "application/pdf",
		FilenameSuffix: ".pdf",
	},
	canarytokensMSWord: {
		Label:           "MS Word document",
		Description:     "A real .docx that phones home when opened. Optionally include a decoy text snippet.",
		DownloadFmt:     "msword",
		ContentType:     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		FilenameSuffix:  ".docx",
		SupportsSnippet: true,
	},
	canarytokensMSExcel: {
		Label:           "MS Excel document",
		Description:     "A real .xlsx that phones home when opened. Optionally include a decoy text snippet.",
		DownloadFmt:     "msexcel",
		ContentType:     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		FilenameSuffix:  ".xlsx",
		SupportsSnippet: true,
	},
	canarytokensCustomImage: {
		Label:          "Custom image (web bug)",
		Description:    "Upload a PNG/GIF/JPEG (e.g. a logo). Get back a trigger URL that serves the same image and fires when it loads anywhere -- an email, a webpage, a document.",
		RequiresUpload: true,
	},
	canarytokensWindowsDir: {
		Label:          "Windows Folder token",
		Description:    "A desktop.ini + icon bundle that fires when the folder is opened in Explorer.",
		DownloadFmt:    "zip",
		ContentType:    "application/zip",
		FilenameSuffix: ".zip",
	},
	canarytokensQRCode: {
		Label:          "QR code",
		Description:    "A PNG QR code that fires when scanned and opened.",
		DownloadFmt:    "qr_code",
		ContentType:    "image/png",
		FilenameSuffix: ".png",
	},
}

func canarytokensTypeIsSupported(t canarytokensTokenType) bool {
	_, ok := canarytokensSupportedTypes[t]
	return ok
}

const canarytokensRequestTimeout = 20 * time.Second

// canarytokensMaxUploadBytes bounds the custom-image upload -- generous for
// a logo/pixel image, far below anything that would strain the frontend's
// own upload handling.
const canarytokensMaxUploadBytes = 8 << 20 // 8MB

// canarytokensMaxResponseBytes bounds every response this client reads
// fully into memory -- generate responses are small JSON; download
// responses are real documents/images, capped generously above the largest
// artifact these token types produce (a decorated Office doc or PDF).
const canarytokensMaxResponseBytes = 32 << 20 // 32MB

type canarytokensClient struct {
	baseURL    string
	httpClient *http.Client
}

// canarytokensDefaultAPIRoot is frontend/app.py's ROOT_API_ENDPOINT at the
// commit canarytokens/Dockerfile currently pins (CANARYTOKENS_REF) -- a
// deliberately non-guessable path, upstream's own anti-scraping measure,
// not a predictable "/api". Overridable via CANARYTOKENS_API_ROOT since a
// future re-pin could change it; the default keeps this working out of the
// box for the deployment this repo actually ships.
const canarytokensDefaultAPIRoot = "/d3aece8093b71007b5ccfedad91ebb11"

// newCanarytokensClient returns nil when baseURL is empty -- every call
// site already treats a nil client as "canarytoken creation disabled", the
// same posture s.ollamaURL/s.ipBlocks take for their own optional
// dependencies. apiRoot defaults to canarytokensDefaultAPIRoot when empty.
func newCanarytokensClient(baseURL, apiRoot string) *canarytokensClient {
	if baseURL == "" {
		return nil
	}
	if apiRoot == "" {
		apiRoot = canarytokensDefaultAPIRoot
	}
	return &canarytokensClient{
		baseURL:    strings.TrimRight(baseURL, "/") + apiRoot,
		httpClient: &http.Client{Timeout: canarytokensRequestTimeout},
	}
}

// canarytokensAPIURLIsLocal mirrors ollamaEndpointIsLocal's shape (#151) --
// plain http, no credentials/query, host is loopback/link-local/private.
// The Canarytokens frontend API is reached only over the WireGuard tunnel
// (10.8.0.2) and must never be pointed at a public endpoint: unlike the
// tokens' own trigger channel (deliberately made public by #1487), the
// creation/management API carries no per-request auth beyond network
// reachability.
func canarytokensAPIURLIsLocal(raw string) bool {
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

type canarytokensGenerateRequest struct {
	TokenType          canarytokensTokenType
	Memo               string
	IncludeTextSnippet bool
	TextSnippet        string
	UploadFilename     string
	UploadContentType  string
	UploadBytes        []byte
}

type canarytokensGenerateResult struct {
	Token        string `json:"token"`
	AuthToken    string `json:"auth_token"`
	TokenURL     string `json:"token_url"`
	Hostname     string `json:"hostname"`
	QRCodePNG    string `json:"qrcode_png,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// generate calls POST {root}/generate. A file upload (web_image only)
// forces a multipart/form-data request -- app.py's own generate() branches
// on Content-Type: application/json is parsed as JSON, anything else as a
// form, with the type field accepted as either "type" or "token_type".
func (c *canarytokensClient) generate(req canarytokensGenerateRequest) (*canarytokensGenerateResult, error) {
	if c == nil {
		return nil, fmt.Errorf("canarytokens: not configured")
	}
	var body io.Reader
	var contentType string
	if req.UploadBytes != nil {
		buf := &bytes.Buffer{}
		w := multipart.NewWriter(buf)
		if err := w.WriteField("token_type", string(req.TokenType)); err != nil {
			return nil, err
		}
		if err := w.WriteField("memo", req.Memo); err != nil {
			return nil, err
		}
		part, err := w.CreateFormFile(string(req.TokenType), req.UploadFilename)
		if err != nil {
			return nil, err
		}
		if _, err := part.Write(req.UploadBytes); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		body = buf
		contentType = w.FormDataContentType()
	} else {
		payload := map[string]any{
			"token_type": req.TokenType,
			"memo":       req.Memo,
		}
		if req.IncludeTextSnippet {
			payload["include_text_snippet"] = true
			payload["text_snippet"] = req.TextSnippet
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
		contentType = "application/json"
	}
	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL+"/generate", body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", contentType)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, canarytokensMaxResponseBytes))
	if err != nil {
		return nil, err
	}
	var result canarytokensGenerateResult
	if jsonErr := json.Unmarshal(data, &result); jsonErr != nil {
		return nil, fmt.Errorf("canarytokens: malformed generate response (status %d): %w", resp.StatusCode, jsonErr)
	}
	if resp.StatusCode != http.StatusOK || result.Error != "" {
		msg := result.ErrorMessage
		if msg == "" {
			msg = fmt.Sprintf("canarytokens: generate failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("%s", msg)
	}
	if result.Token == "" || result.AuthToken == "" {
		return nil, fmt.Errorf("canarytokens: generate response missing token/auth")
	}
	return &result, nil
}

type canarytokensDownload struct {
	Data        []byte
	ContentType string
	Filename    string
}

// download calls GET {root}/download?token=&auth=&fmt=. Only called for
// types with a non-empty DownloadFmt (see canarytokensSupportedTypes) --
// web_image has no /download support upstream at all (the trigger URL IS
// the artifact; fetching it server-side would itself count as a "hit", so
// this client never does that -- see canarytoken_action.go's own comment).
func (c *canarytokensClient) download(token, auth, dlFmt string) (*canarytokensDownload, error) {
	if c == nil {
		return nil, fmt.Errorf("canarytokens: not configured")
	}
	q := url.Values{"token": {token}, "auth": {auth}, "fmt": {dlFmt}}
	httpReq, err := http.NewRequest(http.MethodGet, c.baseURL+"/download?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, canarytokensMaxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("canarytokens: download failed with status %d", resp.StatusCode)
	}
	filename := ""
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		filename = params["filename"]
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return &canarytokensDownload{Data: data, ContentType: contentType, Filename: filename}, nil
}
