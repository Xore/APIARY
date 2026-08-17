package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHoneyfsImplantURLIsLocal(t *testing.T) {
	// Built via url.URL rather than a literal in this file, same reasoning
	// as canarytokens_test.go's TestCanarytokensAPIURLIsLocal: a source
	// literal shaped like "scheme://user:pass@host" trips
	// scripts/check-public-leaks.py's generic credential-in-URL pattern.
	credentialedURL := (&url.URL{Scheme: "http", User: url.UserPassword("u", "p"), Host: "10.8.0.2:19428"}).String()

	cases := []struct {
		raw  string
		want bool
	}{
		{"http://10.8.0.2:19428", true},
		{"http://localhost:19428", true},
		{"http://127.0.0.1:19428", true},
		{"https://10.8.0.2:19428", false},
		{"http://cdn.honeypot.example", false},
		{"http://10.8.0.2:19428?x=1", false},
		{credentialedURL, false},
		{"not a url", false},
	}
	for _, c := range cases {
		if got := honeyfsImplantURLIsLocal(c.raw); got != c.want {
			t.Errorf("honeyfsImplantURLIsLocal(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// fakeHoneyfsImplantServer stands in for honeyfs-implant's own /implant
// endpoint (arcane/home/honeypot-cowrie/honeyfs-implant/main.go, #1553),
// matching its real request/response shape closely enough to exercise
// honeyfsImplantClient without the real Go service.
func fakeHoneyfsImplantServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/implant", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path          string `json:"path"`
			ContentBase64 string `json:"content_base64"`
			Memo          string `json:"memo"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "bad request"})
			return
		}
		if body.Path == "" || body.ContentBase64 == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "path and content_base64 are required"})
			return
		}
		if strings.Contains(body.Path, "..") {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "path escapes the honeyfs root"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "path": body.Path, "bytes_written": len(body.ContentBase64)})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestHoneyfsImplantClientImplant(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	client := newHoneyfsImplantClient(srv.URL, "")
	result, err := client.implant("home/mwagner/.aws/credentials", []byte("username=mwagner\npassword=hunter2\n"), "test memo")
	if err != nil {
		t.Fatalf("implant: %v", err)
	}
	if result.Path != "home/mwagner/.aws/credentials" || result.BytesWritten == 0 {
		t.Fatalf("unexpected implant result: %#v", result)
	}
}

func TestHoneyfsImplantClientImplantRejectsUpstreamError(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	client := newHoneyfsImplantClient(srv.URL, "")
	if _, err := client.implant("../etc/passwd", []byte("x"), "m"); err == nil {
		t.Fatal("expected an error when the upstream service rejects a path")
	}
}

func TestHoneyfsImplantClientNilWhenUnconfigured(t *testing.T) {
	if newHoneyfsImplantClient("", "") != nil {
		t.Fatal("expected a nil client for an empty base URL")
	}
	var nilClient *honeyfsImplantClient
	if _, err := nilClient.implant("a", []byte("b"), "c"); err == nil {
		t.Fatal("expected an error calling implant on a nil client")
	}
}

func newCredentialsTestStore(t *testing.T, role, implantBaseURL string) *store {
	t.Helper()
	s := newSettingsAPITestStore(t, role)
	s.credentials = newCredentialsManager(s.es)
	s.canarytokensHistory = newCanarytokensManager(s.es)
	if implantBaseURL != "" {
		s.honeyfsImplant = newHoneyfsImplantClient(implantBaseURL, "")
	}
	return s
}

func credentialsJSONRequest(t *testing.T, method, target string, sameOrigin bool, payload map[string]any) *http.Request {
	t.Helper()
	body := ""
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = string(raw)
	}
	return settingsRequest(t, method, target, sameOrigin, body)
}

func TestServeCredentialsCreateRejectsNonAdminAndCrossOrigin(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	payload := map[string]any{"path": "home/m/.aws/credentials", "username": "m", "password": "p", "memo": "m"}

	nonAdmin := newCredentialsTestStore(t, "user", srv.URL)
	response := httptest.NewRecorder()
	nonAdmin.serveCredentialsCreate(response, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create", true, payload))
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-admin create: status = %d, want 403", response.Code)
	}

	admin := newCredentialsTestStore(t, "admin", srv.URL)
	response = httptest.NewRecorder()
	admin.serveCredentialsCreate(response, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create", false, payload))
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin create: status = %d, want 403", response.Code)
	}
}

func TestServeCredentialsCreateUnconfigured(t *testing.T) {
	s := newCredentialsTestStore(t, "admin", "")
	payload := map[string]any{"path": "home/m/.aws/credentials", "username": "m", "password": "p", "memo": "m"}
	response := httptest.NewRecorder()
	s.serveCredentialsCreate(response, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create", true, payload))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
}

func TestServeCredentialsCreateRejectsMissingFieldsAndBadPath(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)

	cases := []map[string]any{
		{"path": "", "username": "m", "password": "p", "memo": "m"},
		{"path": "home/m/x", "username": "", "password": "p", "memo": "m"},
		{"path": "home/m/x", "username": "m", "password": "", "memo": "m"},
		{"path": "home/m/x", "username": "m", "password": "p", "memo": ""},
		{"path": "/etc/passwd", "username": "m", "password": "p", "memo": "m"},
		{"path": "../etc/passwd", "username": "m", "password": "p", "memo": "m"},
	}
	for _, payload := range cases {
		response := httptest.NewRecorder()
		s.serveCredentialsCreate(response, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create", true, payload))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("payload %#v: status = %d, want 400, body=%s", payload, response.Code, response.Body.String())
		}
	}
}

func TestServeCredentialsCreateRejectsUnsupportedTarget(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)
	payload := map[string]any{"target": "beelzebub_password_regex", "path": "home/m/x", "username": "m", "password": "p", "memo": "m"}
	response := httptest.NewRecorder()
	s.serveCredentialsCreate(response, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create", true, payload))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", response.Code, response.Body.String())
	}
}

func TestServeCredentialsCreateSucceedsWithDefaultTemplateAndAudits(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)
	payload := map[string]any{"path": "home/mwagner/.aws/credentials", "username": "mwagner", "password": "hunter2", "memo": "aws backup creds"}

	response := httptest.NewRecorder()
	s.serveCredentialsCreate(response, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create", true, payload))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var record credentialRecord
	if err := json.Unmarshal(response.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.ID == "" || record.Path != payload["path"] || record.Username != "mwagner" || record.Password != "hunter2" {
		t.Fatalf("unexpected created record: %#v", record)
	}
	if record.ContentTemplate != defaultCredentialContentTemplate {
		t.Fatalf("expected default content template, got %q", record.ContentTemplate)
	}
	if record.Target != "cowrie_honeyfs" {
		t.Fatalf("expected target to default to cowrie_honeyfs, got %q", record.Target)
	}
	if record.CreatedBy == "" {
		t.Fatal("expected created_by to be set")
	}

	saved, found := s.credentials.get(record.ID)
	if !found {
		t.Fatal("expected the record to be saved")
	}
	if saved.Password != "hunter2" {
		t.Fatalf("unexpected saved password: %q", saved.Password)
	}

	events := s.settings.audit.read(10)
	if len(events) == 0 || events[0].Action != "credentials.create" || events[0].Result != "success" {
		t.Fatalf("action must be audited: %#v", events)
	}
}

func TestServeCredentialsCreateHonorsCustomTemplate(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)
	payload := map[string]any{
		"path": "root/bin/sync-bastion02-backup.sh", "username": "svc-backup", "password": "s3cr3t",
		"memo":             "bastion02 backup script",
		"content_template": "#!/bin/sh\nBACKUP_PASS='{{password}}'\nBACKUP_USER='{{username}}'\n",
	}
	response := httptest.NewRecorder()
	s.serveCredentialsCreate(response, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create", true, payload))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var record credentialRecord
	if err := json.Unmarshal(response.Body.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.ContentTemplate, "BACKUP_PASS") {
		t.Fatalf("expected the custom template to be saved verbatim, got %q", record.ContentTemplate)
	}
}

func TestServeCredentialRotateGeneratesPasswordWhenNotSupplied(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)
	createResp := httptest.NewRecorder()
	s.serveCredentialsCreate(createResp, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create",
		true, map[string]any{"path": "home/m/.aws/credentials", "username": "m", "password": "original", "memo": "m"}))
	var created credentialRecord
	if err := json.Unmarshal(createResp.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := settingsRequest(t, http.MethodPost, "/api/settings/credentials/"+created.ID+"/rotate", true, "")
	request.SetPathValue("id", created.ID)
	s.serveCredentialRotate(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var rotated credentialRecord
	if err := json.Unmarshal(response.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Password == "original" || rotated.Password == "" {
		t.Fatalf("expected a freshly generated password, got %q", rotated.Password)
	}
	if rotated.RotatedAt.IsZero() || rotated.RotatedBy == "" {
		t.Fatalf("expected rotation metadata to be set: %#v", rotated)
	}
	if rotated.Path != created.Path {
		t.Fatalf("rotation must not change the implant path: got %q, want %q", rotated.Path, created.Path)
	}
}

func TestServeCredentialRotateWithSuppliedPassword(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)
	createResp := httptest.NewRecorder()
	s.serveCredentialsCreate(createResp, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create",
		true, map[string]any{"path": "home/m/.aws/credentials", "username": "m", "password": "original", "memo": "m"}))
	var created credentialRecord
	if err := json.Unmarshal(createResp.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/"+created.ID+"/rotate", true, map[string]any{"password": "specific-new-pass"})
	request.SetPathValue("id", created.ID)
	s.serveCredentialRotate(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var rotated credentialRecord
	if err := json.Unmarshal(response.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Password != "specific-new-pass" {
		t.Fatalf("expected the operator-supplied password to win, got %q", rotated.Password)
	}
}

func TestServeCredentialRotateUnknownID(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)
	response := httptest.NewRecorder()
	request := settingsRequest(t, http.MethodPost, "/api/settings/credentials/nosuchid/rotate", true, "")
	request.SetPathValue("id", "nosuchid")
	s.serveCredentialRotate(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

func TestServeCredentialLinkTokenSuccessAndClear(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)

	createResp := httptest.NewRecorder()
	s.serveCredentialsCreate(createResp, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create",
		true, map[string]any{"path": "home/m/.aws/credentials", "username": "m", "password": "p", "memo": "m"}))
	var cred credentialRecord
	if err := json.Unmarshal(createResp.Body.Bytes(), &cred); err != nil {
		t.Fatal(err)
	}

	// Seed a canarytoken record directly (bypassing the real canarytokens
	// platform, same as canarytokens_test.go's own approach elsewhere) --
	// item 5 only needs an existing tracked token id to link against.
	s.canarytokensHistory.save(canarytokensRecord{ID: "tok123", TokenType: "adobe_pdf", Memo: "linked bait", AuthToken: "auth", CreatedAt: time.Now().UTC()})

	response := httptest.NewRecorder()
	request := credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/"+cred.ID+"/link-token", true, map[string]any{"token_id": "tok123"})
	request.SetPathValue("id", cred.ID)
	s.serveCredentialLinkToken(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("link: status = %d, body = %s", response.Code, response.Body.String())
	}
	var linked credentialRecord
	if err := json.Unmarshal(response.Body.Bytes(), &linked); err != nil {
		t.Fatal(err)
	}
	if linked.LinkedTokenID != "tok123" {
		t.Fatalf("expected linked_token_id = tok123, got %q", linked.LinkedTokenID)
	}

	// Clearing the link (empty token_id) must succeed too.
	response = httptest.NewRecorder()
	request = credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/"+cred.ID+"/link-token", true, map[string]any{"token_id": ""})
	request.SetPathValue("id", cred.ID)
	s.serveCredentialLinkToken(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unlink: status = %d, body = %s", response.Code, response.Body.String())
	}
	var unlinked credentialRecord
	if err := json.Unmarshal(response.Body.Bytes(), &unlinked); err != nil {
		t.Fatal(err)
	}
	if unlinked.LinkedTokenID != "" {
		t.Fatalf("expected linked_token_id to be cleared, got %q", unlinked.LinkedTokenID)
	}
}

func TestServeCredentialLinkTokenRejectsUnknownTokenID(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)
	createResp := httptest.NewRecorder()
	s.serveCredentialsCreate(createResp, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create",
		true, map[string]any{"path": "home/m/.aws/credentials", "username": "m", "password": "p", "memo": "m"}))
	var cred credentialRecord
	if err := json.Unmarshal(createResp.Body.Bytes(), &cred); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/"+cred.ID+"/link-token", true, map[string]any{"token_id": "does-not-exist"})
	request.SetPathValue("id", cred.ID)
	s.serveCredentialLinkToken(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", response.Code, response.Body.String())
	}
}

func TestServeCredentialsListEmptyAndPopulated(t *testing.T) {
	srv := fakeHoneyfsImplantServer(t)
	s := newCredentialsTestStore(t, "admin", srv.URL)

	response := httptest.NewRecorder()
	s.serveCredentialsList(response, settingsRequest(t, http.MethodGet, "/api/settings/credentials", false, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var parsed struct {
		Available   bool               `json:"available"`
		Credentials []credentialRecord `json:"credentials"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Available || len(parsed.Credentials) != 0 {
		t.Fatalf("expected an empty but available list: %#v", parsed)
	}

	createResp := httptest.NewRecorder()
	s.serveCredentialsCreate(createResp, credentialsJSONRequest(t, http.MethodPost, "/api/settings/credentials/create",
		true, map[string]any{"path": "home/m/.aws/credentials", "username": "m", "password": "p", "memo": "m"}))
	if createResp.Code != http.StatusOK {
		t.Fatalf("create failed: %d", createResp.Code)
	}

	response = httptest.NewRecorder()
	s.serveCredentialsList(response, settingsRequest(t, http.MethodGet, "/api/settings/credentials", false, ""))
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Credentials) != 1 || parsed.Credentials[0].Username != "m" {
		t.Fatalf("expected one record: %#v", parsed)
	}
}

func TestRenderCredentialContent(t *testing.T) {
	got := renderCredentialContent("user={{username}} pass={{password}} again={{username}}", "alice", "s3cret")
	want := "user=alice pass=s3cret again=alice"
	if got != want {
		t.Fatalf("renderCredentialContent = %q, want %q", got, want)
	}
}

func TestGenerateCredentialPassword(t *testing.T) {
	a, err := generateCredentialPassword()
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateCredentialPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 20 || len(b) != 20 {
		t.Fatalf("expected 20-character passwords, got lengths %d/%d", len(a), len(b))
	}
	if a == b {
		t.Fatal("two generated passwords collided -- suspiciously non-random")
	}
	for _, r := range a {
		if !strings.ContainsRune(credentialPasswordAlphabet, r) {
			t.Fatalf("generated password contains an out-of-alphabet character: %q", r)
		}
	}
}
