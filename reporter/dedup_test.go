package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDedupCooldownWindow(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	recent, err := st.recentlyReported("203.0.113.7", "abuseipdb", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if recent {
		t.Fatal("an IP never reported should not be 'recently reported'")
	}

	if err := st.markReported("203.0.113.7", "abuseipdb", "login", time.Now()); err != nil {
		t.Fatal(err)
	}
	recent, err = st.recentlyReported("203.0.113.7", "abuseipdb", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !recent {
		t.Fatal("an IP just marked reported should be within the cooldown window")
	}

	// A zero/negative window means "not recently" is trivially always true
	// once enough wall-clock time has passed -- but marking it far in the
	// past should fall outside even a real window.
	if err := st.markReported("198.51.100.9", "abuseipdb", "login", time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	recent, err = st.recentlyReported("198.51.100.9", "abuseipdb", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if recent {
		t.Fatal("a report from 48h ago should be outside a 24h cooldown window")
	}
}

func TestDedupIsolatedPerService(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.markReported("203.0.113.7", "abuseipdb", "login", time.Now()); err != nil {
		t.Fatal(err)
	}
	recent, err := st.recentlyReported("203.0.113.7", "blocklist.de", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if recent {
		t.Fatal("a report to one service must not suppress reporting the same IP to a different service")
	}
}

func TestTailOffsetRoundTrip(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	inode, offset, err := st.tailOffset("/logs/cowrie/cowrie.json")
	if err != nil {
		t.Fatal(err)
	}
	if inode != 0 || offset != 0 {
		t.Fatalf("a path never seen before should read back (0, 0), got (%d, %d)", inode, offset)
	}

	if err := st.saveTailOffset("/logs/cowrie/cowrie.json", 12345, 6789); err != nil {
		t.Fatal(err)
	}
	inode, offset, err = st.tailOffset("/logs/cowrie/cowrie.json")
	if err != nil {
		t.Fatal(err)
	}
	if inode != 12345 || offset != 6789 {
		t.Fatalf("got (%d, %d), want (12345, 6789)", inode, offset)
	}

	// A rotation: same path, new inode, offset resets to 0 in the caller's
	// logic (tail.go), but the store itself just persists whatever it's told.
	if err := st.saveTailOffset("/logs/cowrie/cowrie.json", 99999, 42); err != nil {
		t.Fatal(err)
	}
	inode, offset, err = st.tailOffset("/logs/cowrie/cowrie.json")
	if err != nil {
		t.Fatal(err)
	}
	if inode != 99999 || offset != 42 {
		t.Fatalf("got (%d, %d), want (99999, 42) after overwrite", inode, offset)
	}
}
