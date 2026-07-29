package main

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func testIdentity(subject, username, role string) authenticatedIdentity {
	return authenticatedIdentity{
		Subject:    subject,
		Username:   username,
		Role:       role,
		Generation: 1,
	}
}

func newTestUserStore(t *testing.T) *userStore {
	t.Helper()
	dir := t.TempDir()
	audit := newAuditLogger(filepath.Join(dir, "audit.jsonl"))
	return newUserStore(filepath.Join(dir, "users.json"), audit)
}

func TestProjectionUpsertCreatesAndRefreshes(t *testing.T) {
	users := newTestUserStore(t)
	identity := testIdentity("subject-aaaa-bbbb-cccc", "analyst", "user")
	users.Upsert(identity)
	projections := users.Projections()
	if len(projections) != 1 {
		t.Fatalf("expected one projection, got %d", len(projections))
	}
	first := projections[0]
	if first.Subject != identity.Subject || first.LastUsername != "analyst" ||
		first.RoleSnapshot != "user" || first.FirstSeen.IsZero() || first.LastSeen.IsZero() {
		t.Fatalf("unexpected projection: %+v", first)
	}
	if err := validatePreferences(first.Preferences); err != nil {
		t.Fatalf("new projections must carry valid default preferences: %v", err)
	}

	// A rename and a role change are reflected on the next upsert.
	renamed := identity
	renamed.Username = "senior-analyst"
	renamed.Role = "admin"
	users.Upsert(renamed)
	projections = users.Projections()
	if len(projections) != 1 || projections[0].LastUsername != "senior-analyst" || projections[0].RoleSnapshot != "admin" {
		t.Fatalf("upsert did not refresh identity material: %+v", projections)
	}
	if !projections[0].FirstSeen.Equal(first.FirstSeen) {
		t.Fatal("upsert must preserve first_seen_at")
	}
}

func TestProjectionUpsertThrottlesRepeatedWrites(t *testing.T) {
	users := newTestUserStore(t)
	identity := testIdentity("subject-throttle-0001", "analyst", "user")
	users.Upsert(identity)
	revisionAfterCreate := users.inner.Revision()
	users.Upsert(identity) // within the throttle window: no rewrite
	if users.inner.Revision() != revisionAfterCreate {
		t.Fatal("throttled upsert must not rewrite the store")
	}
}

func TestProjectionRejectsInvalidSubjects(t *testing.T) {
	users := newTestUserStore(t)
	users.Upsert(testIdentity("bad subject!", "analyst", "user"))
	users.Upsert(testIdentity("short", "analyst", "user"))
	if len(users.Projections()) != 0 {
		t.Fatal("invalid subjects must not be projected")
	}
}

func TestPreferencesRoundTripAndIsolation(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000001", "alice", "user")
	bob := testIdentity("subject-bob-00000001", "bob", "admin")
	users.Upsert(alice)
	users.Upsert(bob)

	_, etag, ok := users.Preferences(alice.Subject)
	if !ok {
		t.Fatal("alice projection missing")
	}
	if _, err := users.UpdatePreferences(alice, etag, "req-1", "203.0.113.10", func(p *userPreferences) error {
		p.Theme = "dark"
		p.RowsPerPage = 100
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	alicePrefs, _, _ := users.Preferences(alice.Subject)
	bobPrefs, _, _ := users.Preferences(bob.Subject)
	if alicePrefs.Theme != "dark" || alicePrefs.RowsPerPage != 100 {
		t.Fatalf("alice preferences not updated: %+v", alicePrefs)
	}
	if bobPrefs.Theme == "dark" || bobPrefs.RowsPerPage == 100 {
		t.Fatalf("alice's write leaked into bob's preferences: %+v", bobPrefs)
	}

	// Persistence across a store reload.
	reloaded := newUserStore(users.inner.path, users.audit)
	reloadedPrefs, _, ok := reloaded.Preferences(alice.Subject)
	if !ok || reloadedPrefs.Theme != "dark" {
		t.Fatal("preferences did not survive a restart")
	}
}

func TestPreferencesRequireAProjectedSubject(t *testing.T) {
	users := newTestUserStore(t)
	stranger := testIdentity("subject-stranger-000", "stranger", "user")
	_, err := users.UpdatePreferences(stranger, "", "req-2", "", func(p *userPreferences) error {
		p.Theme = "dark"
		return nil
	})
	if !errors.Is(err, errUnknownRecord) {
		t.Fatalf("preference write without projection must fail closed, got %v", err)
	}
}

func TestPreferencesValidationFailureLeavesStoreUntouched(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000002", "alice", "user")
	users.Upsert(alice)
	_, err := users.UpdatePreferences(alice, "", "req-3", "", func(p *userPreferences) error {
		p.RefreshInterval = 1 // outside the bounded choice set
		return nil
	})
	if !errors.Is(err, errSettingsValidation) {
		t.Fatalf("invalid preferences must be rejected, got %v", err)
	}
	prefs, _, _ := users.Preferences(alice.Subject)
	if prefs.RefreshInterval != defaultPreferences().RefreshInterval {
		t.Fatal("rejected preference write changed stored state")
	}
}

func TestPreferencesETagConflict(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000003", "alice", "user")
	users.Upsert(alice)
	_, stale, _ := users.Preferences(alice.Subject)
	if _, err := users.UpdatePreferences(alice, stale, "req-4", "", func(p *userPreferences) error {
		p.Theme = "dark"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.UpdatePreferences(alice, stale, "req-5", "", func(p *userPreferences) error {
		p.Theme = "light"
		return nil
	}); !errors.Is(err, errStaleRevision) {
		t.Fatalf("stale preference ETag must conflict, got %v", err)
	}
}

func TestResetPreferencesRestoresDefaults(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000004", "alice", "user")
	users.Upsert(alice)
	if _, err := users.UpdatePreferences(alice, "", "req-6", "", func(p *userPreferences) error {
		p.Theme = "light"
		p.NotifySound = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.ResetPreferences(alice, "", "req-7", ""); err != nil {
		t.Fatal(err)
	}
	prefs, _, _ := users.Preferences(alice.Subject)
	if prefs.Theme != defaultPreferences().Theme || prefs.NotifySound {
		t.Fatalf("reset did not restore defaults: %+v", prefs)
	}
}

func TestProjectionCapEvictsLeastRecentlySeen(t *testing.T) {
	users := newTestUserStore(t)
	// Seed the document directly to avoid 1001 serialized Update cycles.
	if _, _, err := users.inner.Update("", func(doc *usersDocument) error {
		base := time.Now().UTC()
		for i := 0; i < maxProjectedUsers; i++ {
			doc.Users = append(doc.Users, userProjection{
				Subject:      "subject-seed-" + strconv.Itoa(10000+i),
				LastUsername: "seed",
				FirstSeen:    base.Add(time.Duration(i) * time.Second),
				LastSeen:     base.Add(time.Duration(i) * time.Second),
				Preferences:  defaultPreferences(),
			})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	users.Upsert(testIdentity("subject-newcomer-000", "newcomer", "user"))
	projections := users.Projections()
	if len(projections) != maxProjectedUsers {
		t.Fatalf("projection cap not enforced: %d records", len(projections))
	}
	for _, user := range projections {
		if user.Subject == "subject-seed-10000" {
			t.Fatal("the least recently seen projection was not evicted")
		}
	}
	found := false
	for _, user := range projections {
		if user.Subject == "subject-newcomer-000" {
			found = true
		}
	}
	if !found {
		t.Fatal("new projection missing after eviction")
	}
}

func TestAuditRecordsPreferenceOutcomes(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000005", "alice", "user")
	users.Upsert(alice)
	if _, err := users.UpdatePreferences(alice, "", "req-8", "203.0.113.20", func(p *userPreferences) error {
		p.Theme = "dark"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.UpdatePreferences(alice, `"r0-000000000000"`, "req-9", "", func(p *userPreferences) error {
		return nil
	}); !errors.Is(err, errStaleRevision) {
		t.Fatalf("expected conflict, got %v", err)
	}
	events := users.audit.read(10)
	if len(events) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(events))
	}
	if events[0].Result != "conflict" || events[1].Result != "success" {
		t.Fatalf("unexpected audit results: %+v", events)
	}
	success := events[1]
	if success.Actor != alice.Subject || success.Username != "alice" ||
		success.ClientIP != "203.0.113.20" || success.Action != "preferences.update" {
		t.Fatalf("audit event missing actor context: %+v", success)
	}
	// Users live inside a dotted path; the audit must name fields, not values.
	foundTheme := false
	for _, field := range success.Fields {
		if field == "users" {
			foundTheme = true
		}
		if field == "dark" {
			t.Fatal("audit field names must not contain values")
		}
	}
	if !foundTheme && len(success.Fields) == 0 {
		t.Fatal("successful update must record changed field names")
	}
}
