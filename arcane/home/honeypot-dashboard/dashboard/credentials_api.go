package main

// credentials_api.go -- #1487 items 3/5: dashboard-driven credential
// provisioning/rotation into a honeypot's live filesystem via the
// honeyfs-implant primitive (#1553), plus linking a credential to an
// existing canarytoken (item 5's bookkeeping-only ask).
//
//	GET  /api/settings/credentials                 list every provisioned credential
//	POST /api/settings/credentials/create           provision a new credential (implants it live)
//	POST /api/settings/credentials/{id}/rotate      rotate a credential's password (re-implants at the same path)
//	POST /api/settings/credentials/{id}/link-token  associate/clear a canarytoken id (bookkeeping only)
//
// Same administrator+same-origin guard as canarytokens_api.go
// (adminSettingsIdentity) -- provisioning writes a real, live artifact into
// a running honeypot's filesystem, the same "admin/operator only" posture.
//
// Cowrie-honeyfs is the only implant target this pass wires up (Target
// "cowrie_honeyfs", the only value serveCredentialsCreate accepts today).
// Beelzebub's passwordRegex config rewrite (per the #1487 design comment:
// "for Beelzebub-style sensors, a config value ... that the same service
// can rewrite") is a natural follow-up but has a genuinely different
// request shape (a YAML config key to rewrite, not a file path+content) --
// deferred rather than forced into this same Target enum.
import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// credentialsRequestMaxBody bounds every JSON body this file decodes --
// generous for a small credentials file / short script content_template,
// far below anything that would strain the request path.
const credentialsRequestMaxBody = 16 << 10 // 16KB

func (s *store) serveCredentialsList(w http.ResponseWriter, r *http.Request) {
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
	if s.credentials == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "credentials": []credentialRecord{}})
		return
	}
	records, err := s.credentials.list()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "error": err.Error(), "credentials": []credentialRecord{}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"available": true, "credentials": records})
}

// credentialCreateRequest is the JSON body for POST
// /api/settings/credentials/create.
type credentialCreateRequest struct {
	Target          string `json:"target"`
	Path            string `json:"path"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	ContentTemplate string `json:"content_template"`
	Memo            string `json:"memo"`
}

func (s *store) serveCredentialsCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.adminSettingsIdentity(w, r, true)
	if !ok {
		return
	}
	if s.honeyfsImplant == nil {
		http.Error(w, "credential implant is not configured on this host (HONEYFS_IMPLANT_URL unset)", http.StatusServiceUnavailable)
		return
	}
	if s.credentials == nil {
		http.Error(w, "credential storage is not configured on this host (Elasticsearch unavailable)", http.StatusServiceUnavailable)
		return
	}

	var req credentialCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, credentialsRequestMaxBody)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		req.Target = "cowrie_honeyfs"
	}
	if req.Target != "cowrie_honeyfs" {
		http.Error(w, "unsupported target (only cowrie_honeyfs is implemented today)", http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(req.Path)
	username := strings.TrimSpace(req.Username)
	password := req.Password
	memo := strings.TrimSpace(req.Memo)
	if path == "" || username == "" || password == "" || memo == "" {
		http.Error(w, "path, username, password, and memo are all required", http.StatusBadRequest)
		return
	}
	// Belt-and-suspenders alongside honeyfs-implant's own
	// resolveHoneyfsPath containment check (main.go, #1553) -- reject the
	// obviously-bad shapes here too so a malformed path fails fast with a
	// clear message instead of a generic implant error.
	if strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		http.Error(w, `path must be relative to the honeyfs root and must not contain ".."`, http.StatusBadRequest)
		return
	}
	template := req.ContentTemplate
	if strings.TrimSpace(template) == "" {
		template = defaultCredentialContentTemplate
	}

	content := renderCredentialContent(template, username, password)
	if _, err := s.honeyfsImplant.implant(path, []byte(content), memo); err != nil {
		s.auditConfig(identity, r, "credentials.create", []string{path}, "error")
		http.Error(w, "implant failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	record := credentialRecord{
		ID:              newCredentialID(),
		Target:          req.Target,
		Path:            path,
		Username:        username,
		Password:        password,
		ContentTemplate: template,
		Memo:            memo,
		CreatedBy:       firstNonEmpty(identity.Username, identity.Subject),
		CreatedAt:       time.Now().UTC(),
	}
	if !s.credentials.save(record) {
		// The file is already implanted on the honeypot; only our own
		// bookkeeping record failed to save. Say so plainly rather than
		// implying the whole operation failed -- an operator retrying
		// blind could otherwise plant a second, orphaned credential file.
		http.Error(w, "credential was implanted but could not be saved to history -- check before retrying to avoid planting a duplicate", http.StatusInternalServerError)
		return
	}
	s.auditConfig(identity, r, "credentials.create", []string{path}, "success")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(record)
}

// credentialRotateRequest is the (optional) JSON body for POST
// /api/settings/credentials/{id}/rotate.
type credentialRotateRequest struct {
	// Password is optional -- empty generates a fresh random password
	// server-side, matching the design comment's "rotate every N days? on-
	// demand?" framing: an operator can either supply a specific new value
	// or just ask for a rotation and let the dashboard pick one.
	Password string `json:"password"`
}

func (s *store) serveCredentialRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.adminSettingsIdentity(w, r, true)
	if !ok {
		return
	}
	if s.honeyfsImplant == nil || s.credentials == nil {
		http.Error(w, "credential rotation is not configured on this host", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	record, found := s.credentials.get(id)
	if !found {
		http.NotFound(w, r)
		return
	}

	var req credentialRotateRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, credentialsRequestMaxBody)).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	newPassword := strings.TrimSpace(req.Password)
	if newPassword == "" {
		generated, err := generateCredentialPassword()
		if err != nil {
			http.Error(w, "failed to generate a new password", http.StatusInternalServerError)
			return
		}
		newPassword = generated
	}

	content := renderCredentialContent(record.ContentTemplate, record.Username, newPassword)
	if _, err := s.honeyfsImplant.implant(record.Path, []byte(content), record.Memo); err != nil {
		s.auditConfig(identity, r, "credentials.rotate", []string{record.Path}, "error")
		http.Error(w, "implant failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	record.Password = newPassword
	record.RotatedBy = firstNonEmpty(identity.Username, identity.Subject)
	record.RotatedAt = time.Now().UTC()
	if !s.credentials.save(record) {
		http.Error(w, "credential was rotated on the honeypot but the new value could not be saved -- check the honeyfs directly", http.StatusInternalServerError)
		return
	}
	s.auditConfig(identity, r, "credentials.rotate", []string{record.Path}, "success")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(record)
}

// credentialLinkTokenRequest is #1487 item 5's entire backend surface --
// bookkeeping only, per the design comment ("a dashboard-side data-model
// concern only ... no new backend mechanism, just bookkeeping"). An empty
// TokenID clears an existing link.
type credentialLinkTokenRequest struct {
	TokenID string `json:"token_id"`
}

func (s *store) serveCredentialLinkToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.adminSettingsIdentity(w, r, true)
	if !ok {
		return
	}
	if s.credentials == nil {
		http.Error(w, "credential storage is not configured on this host", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	record, found := s.credentials.get(id)
	if !found {
		http.NotFound(w, r)
		return
	}
	var req credentialLinkTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, credentialsRequestMaxBody)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	tokenID := strings.TrimSpace(req.TokenID)
	if tokenID != "" {
		if s.canarytokensHistory == nil {
			http.Error(w, "canarytoken history is not configured on this host", http.StatusServiceUnavailable)
			return
		}
		if _, found := s.canarytokensHistory.get(tokenID); !found {
			http.Error(w, "unknown canarytoken id", http.StatusBadRequest)
			return
		}
	}
	record.LinkedTokenID = tokenID
	if !s.credentials.save(record) {
		http.Error(w, "failed to save the link", http.StatusInternalServerError)
		return
	}
	action := "credentials.link-token"
	if tokenID == "" {
		action = "credentials.unlink-token"
	}
	s.auditConfig(identity, r, action, []string{record.Path}, "success")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(record)
}
