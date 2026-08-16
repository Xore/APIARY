package main

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite" // pure Go, no cgo -- keeps the FROM scratch/CGO_ENABLED=0 build every other Go service in this repo uses
)

// store is the SQLite-backed dedup/cooldown tracker the plan doc calls for.
// One row per (ip, service) pair with the last time it was reported --
// simpler than the plan doc's original per-day-bucket primary key, and
// equivalent for this purpose: what matters is "was this IP reported to
// this service within the cooldown window", which a single last-seen
// timestamp answers directly without needing one row per day.
type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS reports (
			ip TEXT NOT NULL,
			service TEXT NOT NULL,
			last_reported_at INTEGER NOT NULL,
			event_kind TEXT,
			PRIMARY KEY (ip, service)
		)`); err != nil {
		db.Close()
		return nil, err
	}
	// Tail offsets live in the same DB as the dedup state: both are this
	// reporter's only persistent memory of what it has already seen, and
	// restarting the container must not mean re-walking every log file's
	// entire history from byte 0.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tail_offsets (
			path TEXT NOT NULL PRIMARY KEY,
			inode INTEGER NOT NULL,
			offset INTEGER NOT NULL
		)`); err != nil {
		db.Close()
		return nil, err
	}
	s := &store{db: db}
	if err := s.ensureGreynoiseTable(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) Close() error { return s.db.Close() }

// recentlyReported reports whether ip was reported to service within
// window, per the plan doc's cooldown/dedup requirement.
func (s *store) recentlyReported(ip, service string, window time.Duration) (bool, error) {
	var last int64
	err := s.db.QueryRow(
		`SELECT last_reported_at FROM reports WHERE ip = ? AND service = ?`, ip, service,
	).Scan(&last)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return time.Since(time.Unix(last, 0)) < window, nil
}

// markReported records ip as reported to service now. Called for both a
// real report and a dry-run "would have reported" decision -- dry-run mode
// still needs working cooldowns so a repeat run against the same log
// history doesn't print the same "would report" line for every event from
// one still-hot IP.
func (s *store) markReported(ip, service, kind string, at time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO reports (ip, service, last_reported_at, event_kind) VALUES (?, ?, ?, ?)
		ON CONFLICT (ip, service) DO UPDATE SET last_reported_at = excluded.last_reported_at, event_kind = excluded.event_kind`,
		ip, service, at.Unix(), kind)
	return err
}

// tailOffset returns the last-read (inode, offset) for path, or (0, 0) if
// this reporter has never seen it before -- read from byte 0 in that case.
func (s *store) tailOffset(path string) (inode uint64, offset int64, err error) {
	err = s.db.QueryRow(`SELECT inode, offset FROM tail_offsets WHERE path = ?`, path).Scan(&inode, &offset)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return inode, offset, err
}

func (s *store) saveTailOffset(path string, inode uint64, offset int64) error {
	_, err := s.db.Exec(`
		INSERT INTO tail_offsets (path, inode, offset) VALUES (?, ?, ?)
		ON CONFLICT (path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset`,
		path, inode, offset)
	return err
}
