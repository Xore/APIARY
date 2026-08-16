package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"
)

// tailer polls a fixed set of files for new lines, the same file-tailing
// approach docs/ip-reporting-plan.md's "Resolved design decisions" settled
// on over a Redis pub-sub bus: this reporter's cooldown windows are hours,
// not milliseconds, so polling the files the stack already writes is
// simpler than adding a message bus for it.
//
// Rotation-aware by construction: #120 gave several of these logs their own
// self-rotation (close, rename aside, reopen fresh at the same path). A
// tailer that only remembers a byte offset would silently stop advancing
// after a rotation, since the file at that path is now a different,
// zero-length file. Tracking inode alongside offset (matching how
// Filebeat's own file_identity already protects the rest of this stack's
// ingest pipeline through the same rotations) detects that the file at a
// path changed underneath it and starts the new one from byte 0 instead of
// trying to seek past its end.
type tailer struct {
	st *store
}

func newTailer(st *store) *tailer { return &tailer{st: st} }

// poll reads whatever new lines exist in path since it was last polled,
// calling fn for each one. Errors opening/stating the file are returned to
// the caller to log and skip -- a missing or momentarily-unreadable sensor
// log is not fatal to the whole reporter.
func (t *tailer) poll(path string, fn func(line []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	inode := inodeOf(fi)

	lastInode, lastOffset, err := t.st.tailOffset(path)
	if err != nil {
		return err
	}

	start := lastOffset
	if lastInode != 0 && lastInode != inode {
		// The file at this path is not the one we left off in -- rotated
		// underneath us. Read the new one from the beginning.
		start = 0
	}
	if start > fi.Size() {
		// The file is shorter than where we left off: truncated in place
		// rather than rotated (shouldn't happen to anything this reporter
		// tails, since #120 moved these logs to rename-based rotation, but
		// failing safe here means starting over rather than seeking past
		// EOF and reading nothing forever).
		start = 0
	}

	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	offset := start
	for sc.Scan() {
		line := sc.Bytes()
		offset += int64(len(line)) + 1 // +1 for the newline Scanner strips
		if len(line) == 0 {
			continue
		}
		fn(line)
	}
	// #890: a scan error (in practice always bufio.ErrTooLong -- a line over
	// the 1MB buffer cap) used to leave offset at the last successfully
	// consumed line with no further handling. Since nothing about that
	// offset or the file on disk changes before the next poll, re-opening
	// and re-scanning from the same byte hit the exact same oversized line
	// again -- not a retry, a permanent stall silently dropping every event
	// in this file from that point on, on every sensor this reporter tails.
	if err := sc.Err(); err != nil {
		skipped, serr := skipOversizedLine(f, offset)
		if serr != nil {
			return serr
		}
		if skipped == 0 {
			// The line hasn't finished being written yet (no terminating
			// newline seen at EOF) -- do not claim bytes for a boundary we
			// haven't actually observed. The next poll re-attempts the skip
			// from this same offset once more of the line has landed.
			return t.st.saveTailOffset(path, inode, offset)
		}
		log.Printf("reporter: %s: skipped an oversized log line (%d bytes) at offset %d that exceeded the scanner buffer", path, skipped, offset)
		offset += skipped
	}
	return t.st.saveTailOffset(path, inode, offset)
}

// skipOversizedLine seeks f to offset and reads raw, uncapped bytes up to
// and including the next newline, reporting how many bytes were consumed --
// used to step past a line bufio.Scanner refused to buffer. Returns 0 (not
// an error) if no newline is found before EOF, since the line may simply
// still be in flight.
func skipOversizedLine(f *os.File, offset int64) (int64, error) {
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}
	chunk, err := bufio.NewReader(f).ReadBytes('\n')
	if err == nil {
		return int64(len(chunk)), nil
	}
	if err == io.EOF {
		return 0, nil
	}
	return 0, err
}

// pollGlob is poll's counterpart for a sensor whose log rotates by creating
// a brand new file rather than rename-and-reopen at a fixed path -- eve.json
// (#69): Suricata rotates it hourly into eve-<timestamp>.json (see
// vps/suricata/suricata.yaml), a new filename each time, not the same path
// growing forever. poll's own per-path inode/offset tracking already
// handles this correctly with zero new store schema: each distinct
// eve-*.json filename is naturally its own key, so a file that stops
// growing (rotated out) is simply never touched again, and a newly created
// one starts fresh from byte 0 the first time this glob picks it up.
func (t *tailer) pollGlob(pattern string, fn func(line []byte)) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	var firstErr error
	for _, path := range matches {
		if err := t.poll(path, fn); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
