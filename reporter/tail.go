package main

import (
	"bufio"
	"io"
	"os"
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
	// A scan error (e.g. a line longer than the buffer) still leaves offset
	// at the last successfully consumed line -- save progress rather than
	// losing it, and let the next poll retry from there.
	return t.st.saveTailOffset(path, inode, offset)
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
