package main

// credentials_manager.go -- #1487 items 3/5: dashboard-owned record of
// every credential provisioned/rotated live into a honeypot's filesystem
// via honeyfs-implant (#1553). Direct structural copy of
// canarytokensManager's own shape (canarytokens_manager.go): a dedicated
// Elasticsearch index, the same docGet/docIndex/errESConflict optimistic-
// concurrency retry loop, keyed by a generated ID (unlike canarytokens'
// own stable platform-issued token value, a credential has no natural
// unique key of its own -- Path alone isn't guaranteed unique across
// re-provisioning attempts, so newCredentialID mints one).
//
// Item 5 (link a canarytoken to a credential) is bookkeeping only, per the
// #1487 design comment: "store which canarytokens_manager.go-tracked token
// id is associated with which credential/file path ... no new backend
// mechanism, just bookkeeping." LinkedTokenID below is exactly that -- an
// optional soft reference into canarytokensRecordIndex, validated against
// canarytokensManager.get() at write time by credentials_api.go's
// serveCredentialLinkToken, but never enforced at the storage layer itself
// (a deleted token would just leave a dangling, harmless reference).

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const credentialsRecordIndex = "dashboard-credentials-v1"

// credentialRecord is the Elasticsearch-persisted shape. Unlike
// canarytokensRecord's AuthToken (a real platform-management credential
// that must never reach a browser), Username/Password/ContentTemplate here
// are not a secret to protect from the operator -- they ARE the bait
// content itself. #1487 item 4 asked for exactly this visibility ("what
// the file's actual content looks like"), so this record is encoded
// straight into API responses with no redaction, gated only by the same
// admin+same-origin guard every other /api/settings/* write already
// requires (credentials_api.go's adminSettingsIdentity calls).
type credentialRecord struct {
	ID string `json:"id"`
	// Target names which implant mechanism planted this credential.
	// "cowrie_honeyfs" is the only value this pass implements; a future
	// Beelzebub passwordRegex-config target (per the #1487 design comment)
	// would add a new value here rather than overload Path's meaning.
	Target          string    `json:"target"`
	Path            string    `json:"path"` // honeyfs-root-relative, e.g. "home/mwagner/.aws/credentials"
	Username        string    `json:"username"`
	Password        string    `json:"password"`
	ContentTemplate string    `json:"content_template"` // {{username}}/{{password}} placeholders
	Memo            string    `json:"memo"`
	LinkedTokenID   string    `json:"linked_token_id,omitempty"` // #1487 item 5
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	RotatedBy       string    `json:"rotated_by,omitempty"`
	RotatedAt       time.Time `json:"rotated_at,omitempty"`
}

type credentialsManager struct {
	es *esClient
}

// newCredentialsManager returns nil when es is nil (Elasticsearch not
// configured) -- every call site already treats a nil manager as
// "credential provisioning unavailable", the same posture
// newCanarytokensManager takes.
func newCredentialsManager(es *esClient) *credentialsManager {
	if es == nil {
		return nil
	}
	return &credentialsManager{es: es}
}

const credentialsWriteRetries = 5

// newCredentialID mints a random, opaque record ID -- same shape as
// reports_store.go's newReportID (crypto/rand, hex-encoded, prefixed for
// readability in logs/URLs).
func newCredentialID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(fmt.Sprintf("generate credential id: %v", err))
	}
	return "cred_" + hex.EncodeToString(raw[:])
}

func (m *credentialsManager) save(r credentialRecord) bool {
	if m == nil {
		return false
	}
	for attempt := 0; attempt < credentialsWriteRetries; attempt++ {
		hit, found, err := m.es.docGet(credentialsRecordIndex, r.ID)
		seqNo, primaryTerm := int64(0), int64(0)
		if err == nil && found {
			seqNo, primaryTerm = hit.SeqNo, hit.PrimaryTerm
		}
		body, err := json.Marshal(r)
		if err != nil {
			return false
		}
		err = m.es.docIndex(credentialsRecordIndex, r.ID, body, !found, seqNo, primaryTerm)
		if err == nil {
			return true
		}
		if err != errESConflict {
			return false
		}
	}
	return false
}

func (m *credentialsManager) get(id string) (credentialRecord, bool) {
	if m == nil {
		return credentialRecord{}, false
	}
	hit, found, err := m.es.docGet(credentialsRecordIndex, id)
	if err != nil || !found {
		return credentialRecord{}, false
	}
	var r credentialRecord
	if json.Unmarshal(hit.Source, &r) != nil {
		return credentialRecord{}, false
	}
	return r, true
}

// list returns every provisioned credential, newest first. A non-nil error
// means the query itself failed (transport/ES error) -- distinct from a nil
// slice with a nil error, which means no credentials have been provisioned
// yet (mirrors canarytokensManager.list's own outage-vs-empty distinction).
func (m *credentialsManager) list() ([]credentialRecord, error) {
	if m == nil {
		return nil, nil
	}
	hits, err := m.es.docSearchAll(credentialsRecordIndex, 1000)
	if err != nil {
		return nil, err
	}
	out := make([]credentialRecord, 0, len(hits))
	for _, hit := range hits {
		var r credentialRecord
		if json.Unmarshal(hit.Source, &r) == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// defaultCredentialContentTemplate is used whenever an operator doesn't
// supply their own template at provision time -- a plain two-line
// credentials file, the simplest possible honeyfs artifact shape.
const defaultCredentialContentTemplate = "username={{username}}\npassword={{password}}\n"

// renderCredentialContent substitutes {{username}}/{{password}} placeholders
// in the stored template -- run identically at provision time and at every
// rotation (design comment on #1487: "Rotation = calling implant again with
// new content"), so a credential's rendered file shape never changes across
// a rotation, only the password value inside it.
func renderCredentialContent(template, username, password string) string {
	out := strings.ReplaceAll(template, "{{username}}", username)
	out = strings.ReplaceAll(out, "{{password}}", password)
	return out
}

// credentialPasswordAlphabet excludes visually-ambiguous look-alikes
// (0/O, 1/l/I) -- this password is bait content an operator may need to
// read back off a screen, not a real secret requiring maximum entropy.
const credentialPasswordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*"

// generateCredentialPassword returns a fresh random password for rotation
// -- used when an operator asks to rotate without supplying a specific new
// value (design comment on #1487: "rotate every N days? on-demand?" --
// this is the "on-demand, dashboard picks a value" path).
func generateCredentialPassword() (string, error) {
	const length = 20
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = credentialPasswordAlphabet[int(b)%len(credentialPasswordAlphabet)]
	}
	return string(out), nil
}
