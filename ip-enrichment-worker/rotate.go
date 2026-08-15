package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func getenvInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// outputWriter is one source's enriched-output file, self-rotating the same
// way multipot/main.go's logger (#120) and http-honeypot's own writer
// already do: close, rename aside with a timestamp suffix, reopen fresh at
// the same path once the file crosses maxBytes. Filebeat's file_identity
// defaults to inode/device rather than path, so its harvester stays
// attached to the renamed file through EOF and picks up the fresh one via
// the same glob that already covers the original name -- no lost or
// duplicated lines, no coordination needed with the harvester.
//
// #1389: OUT_DIR/*.json (this worker's own output -- cowrie.json and
// dionaea-incident.json in particular) had no rotation at all before this,
// unlike the raw sensor writers it reads from, growing unbounded (3.86GB/
// 2.18GB after 6 days on the live homeserver). Each source runs on its own
// single goroutine (runSource), so unlike logger.rotate() this needs no
// mutex of its own.
type outputWriter struct {
	f    *os.File
	path string
	size int64
	max  int64
}

func newOutputWriter(path string, maxBytes int64) (*outputWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	w := &outputWriter{f: f, path: path, max: maxBytes}
	if st, err := f.Stat(); err == nil {
		w.size = st.Size()
	}
	return w, nil
}

// rotate closes the current file, renames it aside, and reopens a fresh
// file at the original path. On any failure it leaves w.f as whatever it
// was before (a still-open, over-threshold file is better than losing the
// descriptor and silently dropping every subsequent write).
func (w *outputWriter) rotate() {
	if w.f == nil {
		return
	}
	if err := w.f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "ip-enrichment-worker: close %q for rotation: %v\n", w.path, err)
	}
	// Second-granularity timestamps collide when two rotations happen within
	// the same wall-clock second (confirmed live while testing this exact
	// pattern for #1389's Dionaea half: a small enough max_bytes rotates
	// more than once a second, and the second os.Rename silently replaces
	// the first rotated file, losing everything in it). Disambiguate with a
	// counter suffix instead of trusting the clock alone.
	target := w.path + "." + time.Now().UTC().Format("20060102-150405")
	if _, err := os.Stat(target); err == nil {
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s.%d", target, n)
			if _, err := os.Stat(candidate); err != nil {
				target = candidate
				break
			}
		}
	}
	if err := os.Rename(w.path, target); err != nil {
		fmt.Fprintf(os.Stderr, "ip-enrichment-worker: rename %q for rotation: %v\n", w.path, err)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ip-enrichment-worker: reopen %q after rotation: %v\n", w.path, err)
		return
	}
	w.f = f
	w.size = 0
}

// write reports whether every line was written successfully, checking the
// rotation threshold once up front (not mid-batch): a batch straddling the
// threshold finishes in the file it started in rather than splitting a
// tick's writes across two files for no benefit. On a partial/failed write
// the caller must not advance/persist its input offset, or the unwritten
// lines are gone for good.
func (w *outputWriter) write(name string, lines [][]byte) bool {
	if w.max > 0 && w.size >= w.max {
		w.rotate()
	}
	for _, line := range lines {
		n1, err := w.f.Write(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ip-enrichment-worker: %s: write output %s: %v\n", name, w.path, err)
			return false
		}
		n2, err := w.f.Write([]byte("\n"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ip-enrichment-worker: %s: write output %s: %v\n", name, w.path, err)
			return false
		}
		w.size += int64(n1 + n2)
	}
	return true
}

func (w *outputWriter) Close() error {
	if w.f == nil {
		return nil
	}
	return w.f.Close()
}
