package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCanarytokensAPIURLIsLocal(t *testing.T) {
	// Built via url.URL rather than a literal in this file: a source literal
	// shaped like "scheme://user:pass@host" trips scripts/check-public-leaks.py's
	// generic credential-in-URL pattern regardless of how obviously fake the
	// values are -- the check is structural, not content-aware.
	credentialedURL := (&url.URL{Scheme: "http", User: url.UserPassword("u", "p"), Host: "10.8.0.2:19426"}).String()

	cases := []struct {
		raw  string
		want bool
	}{
		{"http://10.8.0.2:19426", true},
		{"http://localhost:19426", true},
		{"http://127.0.0.1:19426", true},
		{"https://10.8.0.2:19426", false},      // must be plain http, matching the WireGuard-internal-only contract
		{"http://cdn.honeypot.example", false}, // a public hostname must never be accepted here
		{"http://10.8.0.2:19426?x=1", false},   // no query params
		{credentialedURL, false},               // no credentials
		{"not a url", false},
	}
	for _, c := range cases {
		if got := canarytokensAPIURLIsLocal(c.raw); got != c.want {
			t.Errorf("canarytokensAPIURLIsLocal(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestCanarytokensTypeIsSupported(t *testing.T) {
	if !canarytokensTypeIsSupported(canarytokensAdobePDF) {
		t.Fatal("adobe_pdf must be supported")
	}
	if canarytokensTypeIsSupported("aws_keys") {
		t.Fatal("aws_keys is out of #1487's scope and must not be supported")
	}
}

// fakeCanarytokensServer stands in for canarytokens/frontend/app.py's
// /generate and /download endpoints, matching their real shapes (JSON
// generate response; raw-bytes download with Content-Disposition) closely
// enough to exercise canarytokensClient without the real Python service.
func fakeCanarytokensServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/root/generate", func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		var tokenType, memo string
		if strings.HasPrefix(ct, "multipart/form-data") {
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatalf("server: parse multipart: %v", err)
			}
			tokenType = r.FormValue("token_type")
			memo = r.FormValue("memo")
			file, header, err := r.FormFile("web_image")
			if err != nil {
				t.Fatalf("server: expected web_image file part: %v", err)
			}
			file.Close()
			// Mirrors canarytokens/models/web_image.py's UploadedImage.content_type
			// (a Pydantic Literal["image/png","image/gif","image/jpeg"]) --
			// upstream validates the multipart part's own Content-Type header,
			// not the bytes, and rejects anything else (including Go's
			// mime/multipart.CreateFormFile's own hardcoded
			// "application/octet-stream" default) with a generic error. #1586
			// item 4's web_image-always-502s bug was exactly this: the client
			// used to send that default unconditionally. Confirmed live against
			// the real canarytokens-frontend container.
			switch header.Header.Get("Content-Type") {
			case "image/png", "image/gif", "image/jpeg":
			default:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "1", "error_message": "Malformed request, invalid data supplied."})
				return
			}
		} else {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			tokenType, _ = body["token_type"].(string)
			memo, _ = body["memo"].(string)
		}
		if memo == "" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "memo missing"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "faketoken123",
			"auth_token": "fakeauth456",
			"token_url":  "https://cdn.honeypot.example/faketoken123",
			"hostname":   "cdn.honeypot.example",
			"token_type": tokenType,
		})
	})
	mux.HandleFunc("/root/download", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "faketoken123" || r.URL.Query().Get("auth") != "fakeauth456" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="faketoken123.pdf"`)
		_, _ = w.Write([]byte("%PDF-fake-content"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCanarytokensClientGenerateAndDownload(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	client := newCanarytokensClient(srv.URL, "/root")

	result, err := client.generate(canarytokensGenerateRequest{TokenType: canarytokensAdobePDF, Memo: "test memo"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if result.Token != "faketoken123" || result.AuthToken != "fakeauth456" {
		t.Fatalf("unexpected generate result: %#v", result)
	}

	dl, err := client.download(result.Token, result.AuthToken, "pdf")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(dl.Data) != "%PDF-fake-content" || dl.ContentType != "application/pdf" || dl.Filename != "faketoken123.pdf" {
		t.Fatalf("unexpected download result: %#v", dl)
	}
}

func TestCanarytokensClientGenerateRequiresMemo(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	client := newCanarytokensClient(srv.URL, "/root")
	if _, err := client.generate(canarytokensGenerateRequest{TokenType: canarytokensAdobePDF}); err == nil {
		t.Fatal("expected an error when the upstream API rejects a missing memo")
	}
}

// fakePNGBytes is real PNG magic-byte content (a 1x1 image) -- long enough
// for http.DetectContentType to positively identify it as image/png, unlike
// a short literal such as "fake-png-bytes".
var fakePNGBytes = []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0}

func TestCanarytokensClientGenerateWithUpload(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	client := newCanarytokensClient(srv.URL, "/root")
	result, err := client.generate(canarytokensGenerateRequest{
		TokenType:         canarytokensCustomImage,
		Memo:              "logo",
		UploadFilename:    "logo.png",
		UploadContentType: "image/png",
		UploadBytes:       fakePNGBytes,
	})
	if err != nil {
		t.Fatalf("generate with upload: %v", err)
	}
	if result.Token == "" {
		t.Fatal("expected a token")
	}
}

// TestCanarytokensClientGenerateWithUploadRejectsWrongDeclaredContentType is
// the regression case for #1586 item 4: web_image creation always 502'd
// because generate() built the outbound multipart part with
// mime/multipart.CreateFormFile, which hardcodes Content-Type:
// application/octet-stream with no way to override it -- and upstream
// (canarytokens/models/web_image.py's UploadedImage) rejects any Content-
// Type other than image/png, image/gif, or image/jpeg on that part,
// regardless of the actual bytes. fakeCanarytokensServer's own web_image
// handling mirrors that validation, so this documents (and pins) the
// pre-fix failure mode.
func TestCanarytokensClientGenerateWithUploadRejectsWrongDeclaredContentType(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	client := newCanarytokensClient(srv.URL, "/root")
	_, err := client.generate(canarytokensGenerateRequest{
		TokenType:         canarytokensCustomImage,
		Memo:              "logo",
		UploadFilename:    "logo.bin",
		UploadContentType: "application/octet-stream",
		UploadBytes:       []byte("not sniffable as an image"),
	})
	if err == nil {
		t.Fatal("expected upstream to reject a non-image declared Content-Type for bytes it can't sniff as an image either")
	}
}

// TestCanarytokensClientGenerateWithUploadSniffsUndeclaredImageType covers
// createFormFileWithContentType's fallback: a declared Content-Type that
// isn't one of upstream's accepted values (here, empty -- e.g. a browser
// that couldn't determine a MIME type) must not doom a genuinely-valid
// image upload; the actual bytes get sniffed instead.
func TestCanarytokensClientGenerateWithUploadSniffsUndeclaredImageType(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	client := newCanarytokensClient(srv.URL, "/root")
	result, err := client.generate(canarytokensGenerateRequest{
		TokenType:      canarytokensCustomImage,
		Memo:           "logo",
		UploadFilename: "logo.png",
		UploadBytes:    fakePNGBytes,
	})
	if err != nil {
		t.Fatalf("generate with upload (sniffed content type): %v", err)
	}
	if result.Token == "" {
		t.Fatal("expected a token")
	}
}

func newCanarytokensTestStore(t *testing.T, role string, canarytokensBaseURL string) *store {
	t.Helper()
	s := newSettingsAPITestStore(t, role)
	s.canarytokensHistory = newCanarytokensManager(s.es)
	if canarytokensBaseURL != "" {
		s.canarytokens = newCanarytokensClient(canarytokensBaseURL, "/root")
	}
	return s
}

func multipartCanarytokensRequest(t *testing.T, sameOrigin bool, fields map[string]string, fileField, filename string, fileBytes []byte) *http.Request {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if fileField != "" {
		part, err := w.CreateFormFile(fileField, filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(fileBytes); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/settings/canarytokens/create", buf)
	request.Header.Set("Content-Type", w.FormDataContentType())
	addIdentityTestCookie(request)
	if sameOrigin {
		request.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	return request
}

func TestServeCanarytokensCreateRejectsNonAdminAndCrossOrigin(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	nonAdmin := newCanarytokensTestStore(t, "user", srv.URL)
	response := httptest.NewRecorder()
	nonAdmin.serveCanarytokensCreate(response, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "adobe_pdf", "memo": "m"}, "", "", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-admin create: status = %d, want 403", response.Code)
	}

	admin := newCanarytokensTestStore(t, "admin", srv.URL)
	response = httptest.NewRecorder()
	admin.serveCanarytokensCreate(response, multipartCanarytokensRequest(t, false, map[string]string{"token_type": "adobe_pdf", "memo": "m"}, "", "", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin create: status = %d, want 403", response.Code)
	}
}

func TestServeCanarytokensCreateUnconfigured(t *testing.T) {
	s := newCanarytokensTestStore(t, "admin", "")
	response := httptest.NewRecorder()
	s.serveCanarytokensCreate(response, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "adobe_pdf", "memo": "m"}, "", "", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
}

func TestServeCanarytokensCreateRejectsUnsupportedTypeAndMissingMemo(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	s := newCanarytokensTestStore(t, "admin", srv.URL)

	response := httptest.NewRecorder()
	s.serveCanarytokensCreate(response, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "aws_keys", "memo": "m"}, "", "", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unsupported type: status = %d, want 400", response.Code)
	}

	response = httptest.NewRecorder()
	s.serveCanarytokensCreate(response, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "adobe_pdf"}, "", "", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing memo: status = %d, want 400", response.Code)
	}
}

func TestServeCanarytokensCreateRequiresUploadForImageType(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	s := newCanarytokensTestStore(t, "admin", srv.URL)
	response := httptest.NewRecorder()
	s.serveCanarytokensCreate(response, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "web_image", "memo": "logo"}, "", "", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing upload: status = %d, want 400", response.Code)
	}
}

func TestServeCanarytokensCreateSucceedsRecordsHistoryAndAudits(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	s := newCanarytokensTestStore(t, "admin", srv.URL)

	response := httptest.NewRecorder()
	s.serveCanarytokensCreate(response, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "adobe_pdf", "memo": "finance report"}, "", "", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed canarytokensPublicRecord
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "faketoken123" || parsed.DownloadURL == "" || parsed.EmbedOnly {
		t.Fatalf("unexpected create response: %#v", parsed)
	}

	events := s.settings.audit.read(10)
	if len(events) == 0 || events[0].Action != "canarytokens.create" || events[0].Result != "success" {
		t.Fatalf("action must be audited: %#v", events)
	}
	if !containsString(events[0].Fields, "adobe_pdf") {
		t.Fatalf("audit fields must record the token type: %#v", events[0].Fields)
	}

	// The auth_token is a real credential and must never leave the server.
	if strings.Contains(response.Body.String(), "fakeauth456") {
		t.Fatal("response body must never contain the canarytokens auth_token")
	}

	record, found := s.canarytokensHistory.get("faketoken123")
	if !found {
		t.Fatal("expected a saved history record")
	}
	if record.AuthToken != "fakeauth456" || record.Memo != "finance report" || record.CreatedBy == "" {
		t.Fatalf("unexpected saved record: %#v", record)
	}
}

func TestServeCanarytokensCreateImageTypeIsEmbedOnly(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	s := newCanarytokensTestStore(t, "admin", srv.URL)
	response := httptest.NewRecorder()
	req := multipartCanarytokensRequest(t, true, map[string]string{"token_type": "web_image", "memo": "logo"}, "file", "logo.png", fakePNGBytes)
	s.serveCanarytokensCreate(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed canarytokensPublicRecord
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.EmbedOnly || parsed.DownloadURL != "" {
		t.Fatalf("web_image must be embed-only with no download_url: %#v", parsed)
	}
}

func TestServeCanarytokensDownload(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	s := newCanarytokensTestStore(t, "admin", srv.URL)

	createResp := httptest.NewRecorder()
	s.serveCanarytokensCreate(createResp, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "adobe_pdf", "memo": "m"}, "", "", nil))
	if createResp.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", createResp.Code, createResp.Body.String())
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/settings/canarytokens/faketoken123/download", nil)
	request.SetPathValue("id", "faketoken123")
	addIdentityTestCookie(request)
	s.serveCanarytokensDownload(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Body.String() != "%PDF-fake-content" {
		t.Fatalf("unexpected body: %q", response.Body.String())
	}
	if ct := response.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("Content-Type = %q, want application/pdf", ct)
	}
}

// #1586: fakeCanarytokensServer's own /root/download always answers
// "application/pdf" regardless of the requested fmt (see its own handler
// above) -- exactly the scenario a real upstream mismatch would look like.
// A windows_dir token (DownloadFmt "zip", ContentType "application/zip")
// downloaded through it must still come back as application/zip: our own
// statically-known type for what we asked for, not whatever the response
// happened to carry. Before this fix, dl.ContentType (the upstream header)
// won whenever it was merely non-empty, so this download would have come
// back mislabeled as a PDF.
func TestServeCanarytokensDownloadTrustsOwnContentTypeOverUpstream(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	s := newCanarytokensTestStore(t, "admin", srv.URL)

	createResp := httptest.NewRecorder()
	s.serveCanarytokensCreate(createResp, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "windows_dir", "memo": "m"}, "", "", nil))
	if createResp.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", createResp.Code, createResp.Body.String())
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/settings/canarytokens/faketoken123/download", nil)
	request.SetPathValue("id", "faketoken123")
	addIdentityTestCookie(request)
	s.serveCanarytokensDownload(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if ct := response.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type = %q, want application/zip (our own known type, not the upstream response's application/pdf)", ct)
	}
}

func TestServeCanarytokensDownloadUnknownID(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	s := newCanarytokensTestStore(t, "admin", srv.URL)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/settings/canarytokens/nosuchtoken/download", nil)
	request.SetPathValue("id", "nosuchtoken")
	addIdentityTestCookie(request)
	s.serveCanarytokensDownload(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

func TestServeCanarytokensListEmptyAndPopulated(t *testing.T) {
	srv := fakeCanarytokensServer(t)
	s := newCanarytokensTestStore(t, "admin", srv.URL)

	response := httptest.NewRecorder()
	s.serveCanarytokensList(response, settingsRequest(t, http.MethodGet, "/api/settings/canarytokens", false, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var parsed struct {
		Available bool                       `json:"available"`
		Tokens    []canarytokensPublicRecord `json:"tokens"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Available || len(parsed.Tokens) != 0 {
		t.Fatalf("expected an empty but available list: %#v", parsed)
	}

	createResp := httptest.NewRecorder()
	s.serveCanarytokensCreate(createResp, multipartCanarytokensRequest(t, true, map[string]string{"token_type": "adobe_pdf", "memo": "m"}, "", "", nil))
	if createResp.Code != http.StatusOK {
		t.Fatalf("create failed: %d", createResp.Code)
	}

	response = httptest.NewRecorder()
	s.serveCanarytokensList(response, settingsRequest(t, http.MethodGet, "/api/settings/canarytokens", false, ""))
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Tokens) != 1 || parsed.Tokens[0].ID != "faketoken123" {
		t.Fatalf("expected one record: %#v", parsed)
	}
	// The list response must never leak the auth_token credential.
	if strings.Contains(response.Body.String(), "fakeauth456") {
		t.Fatal("list response must never contain the canarytokens auth_token")
	}
}

func TestServeCanarytokensTypesListsSupportedTypes(t *testing.T) {
	s := newCanarytokensTestStore(t, "admin", "")
	response := httptest.NewRecorder()
	s.serveCanarytokensTypes(response, settingsRequest(t, http.MethodGet, "/api/settings/canarytokens/types", false, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var parsed struct {
		Available bool `json:"available"`
		Types     []struct {
			Key   string `json:"key"`
			Label string `json:"label"`
		} `json:"types"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Available {
		t.Fatal("expected available=false when canarytokens client is unconfigured")
	}
	if len(parsed.Types) != len(canarytokensSupportedTypes) {
		t.Fatalf("got %d types, want %d", len(parsed.Types), len(canarytokensSupportedTypes))
	}
}

func init() {
	// Guard against a future canarytokensSupportedTypes edit silently
	// breaking the DownloadFmt/RequiresUpload invariant every handler
	// above relies on: every type either has a download format or is
	// explicitly upload-driven+embed-only (web_image today).
	for typ, info := range canarytokensSupportedTypes {
		if info.DownloadFmt == "" && !info.RequiresUpload {
			panic(fmt.Sprintf("canarytokens type %q has neither a DownloadFmt nor RequiresUpload -- serveCanarytokensCreate would have no way to deliver its artifact", typ))
		}
	}
}
