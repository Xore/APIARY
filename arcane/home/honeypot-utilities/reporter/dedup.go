package main

import (
	"database/sql"
	"os"
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

// vacuum prunes reporter state that has aged past the point it can still
// affect a decision (#2342): reports/tail_offsets rows accumulate forever
// otherwise, inside a 128MB-limited container whose sqlite volume this
// reporter may run against for months without a restart.
//
// Called once at startup rather than on the poll cycle: this reporter's
// growth rate is one row per (unique IP, service) pair and one row per
// rotated log filename, both slow relative to a 30s poll interval, and
// running a full-table scan against tail_offsets (below) on every poll
// would burn far more CPU than the leak it prevents ever costs in a
// 128MB budget.
//
// reportsDropped and tailOffsetsDropped are returned for the caller to
// log -- an operator watching this container for the first time after
// upgrading needs to see the backlog actually get cleared, not just trust
// that it will eventually.
func (s *store) vacuum(cooldown time.Duration) (reportsDropped, tailOffsetsDropped int64, err error) {
	// reports: a row's only purpose is answering "was this IP reported to
	// this service within `cooldown`" (recentlyReported). Once
	// last_reported_at is older than cooldown, the row can never again
	// change that answer -- a later report re-upserts a fresh timestamp
	// anyway (markReported's ON CONFLICT). cooldown is therefore the row's
	// exact natural retention window; nothing shorter is safe (it could
	// still be inside the window) and nothing longer keeps dead weight.
	// Deliberately NOT mirrored off JSON_RETENTION_MINUTES -- that knob
	// governs on-disk JSON log retention (log-maintenance.sh), an
	// unrelated concern with an unrelated default (days, not this store's
	// hours-scale cooldown); reusing its value here would either purge
	// live cooldown rows early (if shorter than cooldown) or leave dead
	// rows around for days for no reason (if longer).
	cutoff := time.Now().Add(-cooldown).Unix()
	res, err := s.db.Exec(`DELETE FROM reports WHERE last_reported_at < ?`, cutoff)
	if err != nil {
		return 0, 0, err
	}
	reportsDropped, err = res.RowsAffected()
	if err != nil {
		return 0, 0, err
	}

	// tail_offsets: a row is dead exactly when the file it names no longer
	// exists on disk -- rotated away and since pruned by log-maintenance.sh
	// (fixed-path sensors, which self-rotate in place per #120 and so
	// rarely if ever hit this) or by Suricata's own hourly eve-*.json
	// rotation (the actual growth vector: one new row per hour, forever,
	// for a reporter that never restarts). Age has nothing to do with
	// it -- a still-live file's offset must never be dropped even if the
	// reporter hasn't restarted in months, or the next poll re-reads it
	// from byte 0 and re-reports its entire history. This is the
	// load-bearing half of the fix: checking existence, not age, for this
	// table specifically.
	rows, err := s.db.Query(`SELECT path FROM tail_offsets`)
	if err != nil {
		return reportsDropped, 0, err
	}
	var stale []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			rows.Close()
			return reportsDropped, 0, err
		}
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			stale = append(stale, path)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return reportsDropped, 0, err
	}
	rows.Close()

	for _, path := range stale {
		if _, err := s.db.Exec(`DELETE FROM tail_offsets WHERE path = ?`, path); err != nil {
			return reportsDropped, tailOffsetsDropped, err
		}
		tailOffsetsDropped++
	}
	return reportsDropped, tailOffsetsDropped, nil
}
