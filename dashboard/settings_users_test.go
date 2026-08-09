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
		Subject:  subject,
		Username: username,
		Role:     role,
	}
}

func newTestUserStore(t *testing.T) *userStore {
	t.Helper()
	dir := t.TempDir()
	audit := newAuditLogger(filepath.Join(dir, "audit.jsonl"))
	return newUserStore(filepath.Join(dir, "users.json"), audit)
}

// TestUpsertSeedsSiteDefaultTimezone (#282): a brand new subject's own
// Timezone preference starts as the operator's current
// behavior.default_timezone, not a hardcoded "browser" literal -- the "real
// site-wide default concept" #282 asked for. An empty/invalid site default
// (e.g. a degraded config store) must still fall back to the compiled
// "browser" default rather than seeding an unvalidated value.
func TestUpsertSeedsSiteDefaultTimezone(t *testing.T) {
	users := newTestUserStore(t)
	withSite := testIdentity("subject-with-site-default", "analyst", "user")
	users.Upsert(withSite, "Europe/Berlin")
	prefs, _, found := users.Preferences(withSite.Subject)
	if !found {
		t.Fatal("projection was not created")
	}
	if prefs.Timezone != "Europe/Berlin" {
		t.Fatalf("timezone = %q, want the site default Europe/Berlin", prefs.Timezone)
	}

	noSite := testIdentity("subject-no-site-default", "analyst", "user")
	users.Upsert(noSite, "")
	prefs2, _, found := users.Preferences(noSite.Subject)
	if !found {
		t.Fatal("projection was not created")
	}
	if prefs2.Timezone != "browser" {
		t.Fatalf("timezone = %q, want the compiled fallback \"browser\" for an empty site default", prefs2.Timezone)
	}
}

func TestProjectionUpsertCreatesAndRefreshes(t *testing.T) {
	users := newTestUserStore(t)
	identity := testIdentity("subject-aaaa-bbbb-cccc", "analyst", "user")
	users.Upsert(identity, "")
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
	users.Upsert(renamed, "")
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
	users.Upsert(identity, "")
	revisionAfterCreate := users.inner.Revision()
	users.Upsert(identity, "") // within the throttle window: no rewrite
	if users.inner.Revision() != revisionAfterCreate {
		t.Fatal("throttled upsert must not rewrite the store")
	}
}

func TestProjectionRejectsInvalidSubjects(t *testing.T) {
	users := newTestUserStore(t)
	users.Upsert(testIdentity("bad subject!", "analyst", "user"), "")
	users.Upsert(testIdentity("short", "analyst", "user"), "")
	if len(users.Projections()) != 0 {
		t.Fatal("invalid subjects must not be projected")
	}
}

func TestPreferencesRoundTripAndIsolation(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000001", "alice", "user")
	bob := testIdentity("subject-bob-00000001", "bob", "admin")
	users.Upsert(alice, "")
	users.Upsert(bob, "")

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
	users.Upsert(alice, "")
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
	users.Upsert(alice, "")
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

// #177: this is the exact bug reported live -- a compressing intermediary
// (Traefik's compress middleware, in production) rewrites this dashboard's
// own strong ETag to a weak one on its way to the browser, which echoes it
// back verbatim as If-Match. Before this was fixed, EVERY preference save
// ever attempted failed as a false conflict, unconditionally, even on a
// single tab's very first attempt, because the comparison was a naive
// byte-for-byte match against a value that could never carry the W/ prefix.
func TestPreferencesAcceptsWeakETagFromIfMatch(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000009", "alice", "user")
	users.Upsert(alice, "")
	_, etag, _ := users.Preferences(alice.Subject)
	weak := "W/" + etag
	if _, err := users.UpdatePreferences(alice, weak, "req-weak-1", "", func(p *userPreferences) error {
		p.HighContrast = true
		return nil
	}); err != nil {
		t.Fatalf("a weak-prefixed If-Match for the current ETag must be accepted, got %v", err)
	}
	prefs, _, _ := users.Preferences(alice.Subject)
	if !prefs.HighContrast {
		t.Fatal("update did not apply")
	}
}

// A weak-prefixed but otherwise stale preferences ETag must still conflict.
func TestPreferencesRejectsStaleWeakETag(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000010", "alice", "user")
	users.Upsert(alice, "")
	_, stale, _ := users.Preferences(alice.Subject)
	if _, err := users.UpdatePreferences(alice, stale, "req-weak-2", "", func(p *userPreferences) error {
		p.Theme = "dark"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.UpdatePreferences(alice, "W/"+stale, "req-weak-3", "", func(p *userPreferences) error {
		p.Theme = "light"
		return nil
	}); !errors.Is(err, errStaleRevision) {
		t.Fatalf("a stale weak-prefixed ETag must still conflict, got %v", err)
	}
}

func TestResetPreferencesRestoresDefaults(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000004", "alice", "user")
	users.Upsert(alice, "")
	if _, err := users.UpdatePreferences(alice, "", "req-6", "", func(p *userPreferences) error {
		p.Theme = "light"
		p.NotifySound = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.ResetPreferences(alice, "", "req-7", "", ""); err != nil {
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
	users.Upsert(testIdentity("subject-newcomer-000", "newcomer", "user"), "")
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

// #156: a held preferences ETag must survive unrelated activity elsewhere in
// the shared users document -- another subject's projection Upsert (e.g.
// their own session's routine last_seen_at bookkeeping) must never make an
// unrelated subject's save look like a concurrent edit.
func TestPreferencesETagUnaffectedByOtherSubjectActivity(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000006", "alice", "user")
	bob := testIdentity("subject-bob-00000002", "bob", "user")
	users.Upsert(alice, "")
	users.Upsert(bob, "")

	_, aliceEtag, ok := users.Preferences(alice.Subject)
	if !ok {
		t.Fatal("alice projection missing")
	}

	// Bob's own projection changes materially (a role change, forcing past
	// the upsert throttle) and writes his own preferences -- neither should
	// touch alice's token.
	bobPromoted := bob
	bobPromoted.Role = "admin"
	users.Upsert(bobPromoted, "")
	if _, err := users.UpdatePreferences(bobPromoted, "", "req-bob-1", "", func(p *userPreferences) error {
		p.Theme = "dark"
		return nil
	}); err != nil {
		t.Fatalf("bob's own update must succeed: %v", err)
	}

	if _, err := users.UpdatePreferences(alice, aliceEtag, "req-alice-1", "", func(p *userPreferences) error {
		p.HighContrast = true
		return nil
	}); err != nil {
		t.Fatalf("alice's save was falsely treated as a conflict after bob's unrelated activity: %v", err)
	}
}

// #156: a genuine two-session conflict on the SAME subject's preferences
// must still be caught -- and the losing session must be able to reload the
// latest values and retry successfully, without losing its own change if it
// re-applies it on top of the fresh state.
func TestPreferencesConflictReloadAndRetry(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000007", "alice", "user")
	users.Upsert(alice, "")

	_, sessionAEtag, _ := users.Preferences(alice.Subject)
	sessionBEtag := sessionAEtag

	// Session B (e.g. a second browser tab) saves first.
	if _, err := users.UpdatePreferences(alice, sessionBEtag, "req-b-1", "", func(p *userPreferences) error {
		p.Theme = "dark"
		return nil
	}); err != nil {
		t.Fatalf("session B's save must succeed: %v", err)
	}

	// Session A, still holding the pre-B token, must be told about the
	// genuine conflict rather than silently overwriting session B's change.
	if _, err := users.UpdatePreferences(alice, sessionAEtag, "req-a-1", "", func(p *userPreferences) error {
		p.HighContrast = true
		return nil
	}); !errors.Is(err, errStaleRevision) {
		t.Fatalf("a real second-session write must conflict, got %v", err)
	}

	// Session A reloads and retries: the retry must succeed and must not
	// lose session B's theme change.
	_, freshEtag, _ := users.Preferences(alice.Subject)
	if _, err := users.UpdatePreferences(alice, freshEtag, "req-a-2", "", func(p *userPreferences) error {
		p.HighContrast = true
		return nil
	}); err != nil {
		t.Fatalf("retry after reload must succeed: %v", err)
	}
	final, _, _ := users.Preferences(alice.Subject)
	if final.Theme != "dark" || !final.HighContrast {
		t.Fatalf("retry must preserve the other session's change: %+v", final)
	}
}

// #156: several saves in a row from one session, each chaining the
// previously returned ETag, must all succeed -- this is the ordinary
// "change a few preferences one after another" path the bug report
// described as consistently failing.
func TestPreferencesRapidSequentialUpdatesFromOneSession(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000008", "alice", "user")
	users.Upsert(alice, "")

	_, etag, _ := users.Preferences(alice.Subject)
	edits := []func(*userPreferences){
		func(p *userPreferences) { p.HighContrast = true },
		func(p *userPreferences) { p.Theme = "dark" },
		func(p *userPreferences) { p.Density = "compact" },
		func(p *userPreferences) { p.RowsPerPage = 100 },
	}
	for i, edit := range edits {
		next, err := users.UpdatePreferences(alice, etag, "req-seq-"+strconv.Itoa(i), "", func(p *userPreferences) error {
			edit(p)
			return nil
		})
		if err != nil {
			t.Fatalf("rapid sequential update %d failed: %v", i, err)
		}
		etag = next
	}
	final, _, _ := users.Preferences(alice.Subject)
	if !final.HighContrast || final.Theme != "dark" || final.Density != "compact" || final.RowsPerPage != 100 {
		t.Fatalf("sequential updates did not all apply: %+v", final)
	}
}

func TestAuditRecordsPreferenceOutcomes(t *testing.T) {
	users := newTestUserStore(t)
	alice := testIdentity("subject-alice-000005", "alice", "user")
	users.Upsert(alice, "")
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
