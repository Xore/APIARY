package main

// settings_users.go — the dashboard-owned user projection and per-user
// preferences store (roadmap §3). The projection is diagnostic only: it is
// never used for authorization, which always goes through live auth-backend
// introspection. Preferences are typed, validated, and strictly isolated per
// immutable subject.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// maxProjectedUsers caps the projection. Beyond the cap the least recently
// seen record is evicted; its preferences go with it (roadmap Milestone F
// covers orphan-preference retention for deleted accounts).
const maxProjectedUsers = 1000

// projectionWriteInterval throttles last_seen persistence so a page load
// does not rewrite the store on every request.
const projectionWriteInterval = 5 * time.Minute

type userProjection struct {
	Subject            string          `json:"subject"`
	LastUsername       string          `json:"last_username"`
	LastDisplayName    string          `json:"last_display_name,omitempty"`
	RoleSnapshot       string          `json:"role_snapshot"`
	FirstSeen          time.Time       `json:"first_seen_at"`
	LastSeen           time.Time       `json:"last_seen_at"`
	PreferencesVersion int             `json:"preferences_version"`
	Preferences        userPreferences `json:"preferences"`
}

type usersDocument struct {
	Users []userProjection `json:"users"`
}

// userStore wraps the generic atomic store with projection- and
// preference-specific semantics.
type userStore struct {
	inner *atomicSettingsStore[usersDocument]
	audit *auditLogger
}

func newUserStore(path string, audit *auditLogger) *userStore {
	return &userStore{
		inner: newAtomicSettingsStore(path, usersDocument{}, validateUsersDocument),
		audit: audit,
	}
}

func validateUsersDocument(doc usersDocument) error {
	seen := map[string]bool{}
	for _, user := range doc.Users {
		if !validSubject(user.Subject) {
			return fmt.Errorf("%w: user projection contains an invalid subject", errSettingsValidation)
		}
		if seen[user.Subject] {
			return fmt.Errorf("%w: duplicate projection for subject %s", errSettingsValidation, user.Subject)
		}
		seen[user.Subject] = true
		if user.LastUsername == "" {
			return fmt.Errorf("%w: user projection is missing a username", errSettingsValidation)
		}
		if err := validatePreferences(user.Preferences); err != nil {
			return err
		}
	}
	return nil
}

// Upsert records an authenticated request against the projection. It is
// best-effort: callers invoke it after a successful introspection and ignore
// the error, because a full disk must not break authentication. Writes are
// throttled to projectionWriteInterval unless identity material changed.
func (u *userStore) Upsert(identity authenticatedIdentity) {
	if u == nil || !validSubject(identity.Subject) {
		return
	}
	now := time.Now().UTC()
	_, _, err := u.inner.Update("", func(doc *usersDocument) error {
		for i := range doc.Users {
			user := &doc.Users[i]
			if user.Subject != identity.Subject {
				continue
			}
			materialChange := user.LastUsername != identity.Username ||
				user.LastDisplayName != identity.DisplayName ||
				user.RoleSnapshot != identity.Role
			if !materialChange && now.Sub(user.LastSeen) < projectionWriteInterval {
				return errNoProjectionWrite
			}
			user.LastUsername = identity.Username
			user.LastDisplayName = identity.DisplayName
			user.RoleSnapshot = identity.Role
			user.LastSeen = now
			return nil
		}
		doc.Users = append(doc.Users, userProjection{
			Subject:            identity.Subject,
			LastUsername:       identity.Username,
			LastDisplayName:    identity.DisplayName,
			RoleSnapshot:       identity.Role,
			FirstSeen:          now,
			LastSeen:           now,
			PreferencesVersion: settingsSchemaVersion,
			Preferences:        defaultPreferences(),
		})
		if len(doc.Users) > maxProjectedUsers {
			sort.SliceStable(doc.Users, func(i, j int) bool {
				return doc.Users[i].LastSeen.Before(doc.Users[j].LastSeen)
			})
			doc.Users = doc.Users[len(doc.Users)-maxProjectedUsers:]
		}
		return nil
	})
	if err != nil && !errors.Is(err, errNoProjectionWrite) {
		// Persistence failures surface through ReadOnly on the inner store;
		// the request that triggered the upsert proceeds regardless.
		return
	}
}

var errNoProjectionWrite = errors.New("projection already current")

// Preferences returns one subject's preferences with the ETag of the
// underlying document.
func (u *userStore) Preferences(subject string) (userPreferences, string, bool) {
	doc, etag := u.inner.Get()
	for _, user := range doc.Users {
		if user.Subject == subject {
			return user.Preferences, etag, true
		}
	}
	return userPreferences{}, "", false
}

// Projections returns a copy of every projected user, newest activity first.
// Used by the read-only administrator users pane.
func (u *userStore) Projections() []userProjection {
	doc, _ := u.inner.Get()
	users := make([]userProjection, len(doc.Users))
	copy(users, doc.Users)
	sort.SliceStable(users, func(i, j int) bool {
		return users[i].LastSeen.After(users[j].LastSeen)
	})
	return users
}

// UpdatePreferences applies mutate to one subject's preferences with
// optimistic concurrency and writes an audit record. A subject that has no
// projection yet cannot write preferences — the projection is created by the
// first authenticated request, so this also enforces "no preference writes
// without a trusted subject".
func (u *userStore) UpdatePreferences(actor authenticatedIdentity, ifMatch, requestID, clientIP string, mutate func(*userPreferences) error) (string, error) {
	event := auditEvent{
		Actor:     actor.Subject,
		Username:  actor.Username,
		RequestID: requestID,
		ClientIP:  clientIP,
		Action:    "preferences.update",
	}
	etag, changed, err := u.inner.Update(ifMatch, func(doc *usersDocument) error {
		for i := range doc.Users {
			if doc.Users[i].Subject != actor.Subject {
				continue
			}
			return mutate(&doc.Users[i].Preferences)
		}
		return errUnknownRecord
	})
	event.Result = "success"
	switch {
	case errors.Is(err, errStaleRevision):
		event.Result = "conflict"
	case errors.Is(err, errUnknownRecord), errors.Is(err, errSettingsValidation):
		event.Result = "invalid"
	case err != nil:
		event.Result = "error"
	}
	if err == nil {
		event.Fields = changed
	}
	event.Revision = u.inner.Revision()
	u.audit.log(event)
	if err != nil {
		return "", err
	}
	return etag, nil
}

// ResetPreferences restores compiled defaults for one subject.
func (u *userStore) ResetPreferences(actor authenticatedIdentity, ifMatch, requestID, clientIP string) (string, error) {
	return u.UpdatePreferences(actor, ifMatch, requestID, clientIP, func(p *userPreferences) error {
		*p = defaultPreferences()
		return nil
	})
}

// ---------------------------------------------------------------------------
// Service wiring
// ---------------------------------------------------------------------------

// settingsService bundles the three stores owned by the dashboard. It is
// created once at startup; routes for the settings APIs attach to it in
// Milestones C and E.
type settingsService struct {
	config  *atomicSettingsStore[dashboardConfig]
	users   *userStore
	audit   *auditLogger
	history *configHistory
	writes  *writeLimiter
}

func newSettingsService(configPath, usersPath, auditPath, historyPath string) *settingsService {
	audit := newAuditLogger(auditPath)
	service := &settingsService{
		config:  newAtomicSettingsStore(configPath, defaultDashboardConfig(), validateConfig),
		users:   newUserStore(usersPath, audit),
		audit:   audit,
		history: newConfigHistory(historyPath),
		writes:  newWriteLimiter(),
	}
	if service.config.Degraded() {
		fmt.Printf("dashboard: settings config store at %s unreadable — serving defaults read-only\n", configPath)
	} else if service.config.Recovered() {
		fmt.Printf("dashboard: settings config store recovered from backup generation at %s\n", configPath)
	}
	if service.users.inner.Degraded() {
		fmt.Printf("dashboard: settings users store at %s unreadable — serving defaults read-only\n", usersPath)
	} else if service.users.inner.Recovered() {
		fmt.Printf("dashboard: settings users store recovered from backup generation at %s\n", usersPath)
	}
	// Seed the configuration history with the loaded revision so the initial
	// state stays rollback-able even before the first administrator write.
	if service.history != nil && len(service.history.read(1)) == 0 {
		payload, _ := service.config.Get()
		if raw, err := json.Marshal(payload); err == nil {
			service.history.append(configHistoryEntry{
				Revision: service.config.Revision(),
				Actor:    "system",
				Username: "system",
				Action:   "seed",
				Payload:  raw,
			})
		}
	}
	return service
}
