package main

// canarytokens_api.go -- #1487: dashboard-driven Canarytoken creation for
// external use. Settings > Canarytokens pane API:
//
//	GET  /api/settings/canarytokens/types          supported type catalogue
//	GET  /api/settings/canarytokens                creation history
//	POST /api/settings/canarytokens/create          create a token, return
//	                                                  its metadata + a
//	                                                  same-origin download
//	                                                  link
//	GET  /api/settings/canarytokens/{id}/download   fetch the artifact
//
// Every endpoint requires the same administrator+same-origin guard as the
// rest of the settings surface (settings_admin_api.go's
// adminSettingsIdentity) -- this creates a real, internet-triggerable
// monitoring artifact and hands the caller a downloadable file, the same
// "admin/operator only" posture #1487's own scoping decision settled on.
//
// web_image (custom image / "web bug") tokens are deliberately never
// re-fetched from canarytokens server-side: upstream has no /download
// support for that type (no DownloadFmtTypes entry -- confirmed against
// the vendored source), because the token's own trigger URL IS the
// artifact -- GETting it is indistinguishable from a real "someone opened
// this" hit (canarytokens/channel_http.py's render_GET fires the alert on
// exactly that request). Fetching it here to build a preview/download would
// self-trigger a false "fired" event on a token nobody has planted yet. For
// that type this API instead hands back the exact bytes the operator
// already uploaded (never round-tripped through canarytokens) alongside the
// trigger URL to embed.
import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *store) serveCanarytokensTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	type typeEntry struct {
		Key string `json:"key"`
		canarytokensTypeInfo
	}
	keys := make([]string, 0, len(canarytokensSupportedTypes))
	for k := range canarytokensSupportedTypes {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	entries := make([]typeEntry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, typeEntry{Key: k, canarytokensTypeInfo: canarytokensSupportedTypes[canarytokensTokenType(k)]})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"available": s.canarytokens != nil,
		"types":     entries,
	})
}

func (s *store) serveCanarytokensList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if s.canarytokensHistory == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "tokens": []canarytokensPublicRecord{}})
		return
	}
	records, err := s.canarytokensHistory.list()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "error": err.Error(), "tokens": []canarytokensPublicRecord{}})
		return
	}
	items := make([]canarytokensPublicRecord, 0, len(records))
	for _, record := range records {
		items = append(items, canarytokensRecordToPublic(record))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"available": true, "tokens": items})
}

// canarytokensPublicRecord is the only shape this package ever encodes into
// an HTTP response for a canarytokensRecord -- it deliberately has no field
// for the platform's own auth_token credential (canarytokensRecord.AuthToken),
// which stays server-side and is used only by serveCanarytokensDownload to
// re-call canarytokens' /download on the operator's behalf. Never encode a
// canarytokensRecord directly to a browser-facing response; always go
// through canarytokensRecordToPublic.
type canarytokensPublicRecord struct {
	ID          string    `json:"id"`
	TokenType   string    `json:"token_type"`
	Memo        string    `json:"memo"`
	TokenURL    string    `json:"token_url,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	DownloadURL string    `json:"download_url,omitempty"`
	EmbedOnly   bool      `json:"embed_only"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func canarytokensRecordToPublic(record canarytokensRecord) canarytokensPublicRecord {
	item := canarytokensPublicRecord{
		ID:        record.ID,
		TokenType: record.TokenType,
		Memo:      record.Memo,
		TokenURL:  record.TokenURL,
		Hostname:  record.Hostname,
		CreatedBy: record.CreatedBy,
		CreatedAt: record.CreatedAt,
	}
	if info, known := canarytokensSupportedTypes[canarytokensTokenType(record.TokenType)]; known && info.DownloadFmt != "" {
		item.DownloadURL = "/api/settings/canarytokens/" + record.ID + "/download"
	} else {
		item.EmbedOnly = true
	}
	return item
}

func (s *store) serveCanarytokensCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.adminSettingsIdentity(w, r, true)
	if !ok {
		return
	}
	if s.canarytokens == nil {
		http.Error(w, "canarytoken creation is not configured on this host", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, canarytokensMaxUploadBytes+1<<20)
	if err := r.ParseMultipartForm(canarytokensMaxUploadBytes); err != nil {
		http.Error(w, "invalid form (file too large or malformed)", http.StatusBadRequest)
		return
	}

	tokenType := canarytokensTokenType(strings.TrimSpace(r.FormValue("token_type")))
	info, known := canarytokensSupportedTypes[tokenType]
	if !known {
		http.Error(w, "unsupported token_type", http.StatusBadRequest)
		return
	}
	memo := strings.TrimSpace(r.FormValue("memo"))
	if memo == "" {
		http.Error(w, "memo is required", http.StatusBadRequest)
		return
	}

	genReq := canarytokensGenerateRequest{TokenType: tokenType, Memo: memo}
	if info.SupportsSnippet && r.FormValue("include_text_snippet") == "true" {
		genReq.IncludeTextSnippet = true
		genReq.TextSnippet = strings.TrimSpace(r.FormValue("text_snippet"))
	}

	var uploadedBytes []byte
	var uploadedFilename, uploadedContentType string
	if info.RequiresUpload {
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "a file upload is required for this token type", http.StatusBadRequest)
			return
		}
		defer file.Close()
		data := make([]byte, header.Size)
		if _, err := io.ReadFull(file, data); err != nil {
			http.Error(w, "failed to read uploaded file", http.StatusBadRequest)
			return
		}
		uploadedBytes, uploadedFilename = data, header.Filename
		uploadedContentType = header.Header.Get("Content-Type")
		genReq.UploadFilename, genReq.UploadContentType, genReq.UploadBytes = uploadedFilename, uploadedContentType, uploadedBytes
	}

	result, err := s.canarytokens.generate(genReq)
	if err != nil {
		s.auditConfig(identity, r, "canarytokens.create", []string{string(tokenType)}, "error")
		http.Error(w, "canarytoken creation failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	now := time.Now().UTC()
	record := canarytokensRecord{
		ID:           result.Token,
		TokenType:    string(tokenType),
		Memo:         memo,
		TokenURL:     result.TokenURL,
		Hostname:     result.Hostname,
		FilenameHint: uploadedFilename,
		AuthToken:    result.AuthToken,
		CreatedBy:    firstNonEmpty(identity.Username, identity.Subject),
		CreatedAt:    now,
	}
	if s.canarytokensHistory != nil {
		s.canarytokensHistory.save(record)
	}
	s.auditConfig(identity, r, "canarytokens.create", []string{string(tokenType)}, "success")

	resp := canarytokensRecordToPublic(record)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *store) serveCanarytokensDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	if s.canarytokens == nil || s.canarytokensHistory == nil {
		http.Error(w, "canarytoken creation is not configured on this host", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	record, found := s.canarytokensHistory.get(id)
	if !found {
		http.NotFound(w, r)
		return
	}
	info, known := canarytokensSupportedTypes[canarytokensTokenType(record.TokenType)]
	if !known || info.DownloadFmt == "" {
		http.Error(w, "this token type has no downloadable artifact; use its token_url directly", http.StatusBadRequest)
		return
	}
	dl, err := s.canarytokens.download(record.ID, record.AuthToken, info.DownloadFmt)
	if err != nil {
		http.Error(w, "download failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	filename := dl.Filename
	if filename == "" {
		filename = record.ID + info.FilenameSuffix
	}
	contentType := dl.ContentType
	if contentType == "" {
		contentType = info.ContentType
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(dl.Data)))
	w.Header().Set("X-Robots-Tag", "noindex")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(dl.Data)
}
