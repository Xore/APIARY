package main

import (
	"os"
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

// TestVacuumDropsReportsPastCooldownKeepsRecent covers #2342: a reports row
// past cooldown can never again affect recentlyReported's answer, so it
// must be dropped -- but a row still inside the window must survive, or
// vacuum would break cooldown suppression for an IP that happens to poll
// right after a restart.
func TestVacuumDropsReportsPastCooldownKeepsRecent(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cooldown := 24 * time.Hour
	if err := st.markReported("198.51.100.9", "abuseipdb", "login", time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.markReported("203.0.113.7", "abuseipdb", "login", time.Now()); err != nil {
		t.Fatal(err)
	}

	reportsDropped, _, err := st.vacuum(cooldown)
	if err != nil {
		t.Fatal(err)
	}
	if reportsDropped != 1 {
		t.Fatalf("reportsDropped = %d, want 1", reportsDropped)
	}

	recentOld, err := st.recentlyReported("198.51.100.9", "abuseipdb", cooldown)
	if err != nil {
		t.Fatal(err)
	}
	if recentOld {
		t.Fatal("the 48h-old row should have been dropped, not merely stale")
	}
	var stillThere int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM reports WHERE ip = ?`, "198.51.100.9").Scan(&stillThere); err != nil {
		t.Fatal(err)
	}
	if stillThere != 0 {
		t.Fatal("the 48h-old row is still physically present after vacuum")
	}

	recentNew, err := st.recentlyReported("203.0.113.7", "abuseipdb", cooldown)
	if err != nil {
		t.Fatal(err)
	}
	if !recentNew {
		t.Fatal("a row inside the cooldown window must survive vacuum")
	}
}

// TestVacuumDropsTailOffsetsForDeletedFilesKeepsLiveOnes covers #2342's
// load-bearing half, per the issue's own warning: purging by age alone and
// dropping a tail_offsets row for a file that still exists would make the
// reporter re-read that file from offset zero and re-report everything in
// it. Existence, not age, must gate this table.
func TestVacuumDropsTailOffsetsForDeletedFilesKeepsLiveOnes(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	dir := t.TempDir()
	livePath := filepath.Join(dir, "cowrie.json")
	rotatedAwayPath := filepath.Join(dir, "eve-2026-08-20-00.json")

	if err := os.WriteFile(livePath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// rotatedAwayPath is deliberately never created -- simulates a
	// Suricata eve-*.json rotation that log-maintenance.sh has since
	// pruned from disk.

	if err := st.saveTailOffset(livePath, 111, 3); err != nil {
		t.Fatal(err)
	}
	if err := st.saveTailOffset(rotatedAwayPath, 222, 999); err != nil {
		t.Fatal(err)
	}

	_, tailOffsetsDropped, err := st.vacuum(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tailOffsetsDropped != 1 {
		t.Fatalf("tailOffsetsDropped = %d, want 1", tailOffsetsDropped)
	}

	liveInode, liveOffset, err := st.tailOffset(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if liveInode != 111 || liveOffset != 3 {
		t.Fatalf("live file's tail_offsets row was disturbed: got (%d, %d), want (111, 3) -- a live file's offset must never be dropped", liveInode, liveOffset)
	}

	goneInode, goneOffset, err := st.tailOffset(rotatedAwayPath)
	if err != nil {
		t.Fatal(err)
	}
	if goneInode != 0 || goneOffset != 0 {
		t.Fatalf("rotated-away file's row survived vacuum: got (%d, %d), want (0, 0)", goneInode, goneOffset)
	}
}
