package main

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
)

// loadOffset reads a previously persisted byte offset for an input file, so
// a worker restart resumes where it left off instead of either re-reading
// (and re-appending duplicate lines to an already-partially-written output
// file) or silently skipping whatever arrived while it was down. Returns
// (0, false) when no state exists yet -- callers treat that as "start at
// EOF" (see main.go), not "start at 0": these input files can be large and
// long-lived, and a first run has no reason to walk their entire history
// when every already-shipped document is already correctly handled by the
// dashboard's existing (still-present) fallback join.
func loadOffset(statePath string) (int64, bool) {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func saveOffset(statePath string, offset int64) error {
	return os.WriteFile(statePath, []byte(strconv.FormatInt(offset, 10)), 0o640)
}

// readNewLines reads every complete (newline-terminated) line from path
// starting at offset. A trailing partial line (the sensor's write was still
// in flight) is left unconsumed so the next call re-reads it whole once
// it's complete -- never lost, never split. If the file is now shorter than
// offset (a rename-based rotation reopened a fresh file at the same path,
// e.g. cowrie's daily CowrieDailyLogFile), this resumes from the start of
// the new file rather than erroring or blocking forever on an offset that
// no longer exists.
func readNewLines(path string, offset int64) (lines [][]byte, newOffset int64, err error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, offset, err
	}
	if st.Size() < offset {
		offset = 0
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, offset, err
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, offset, err
	}

	last := bytes.LastIndexByte(data, '\n')
	if last < 0 {
		return nil, offset, nil
	}
	complete := data[:last+1]
	newOffset = offset + int64(len(complete))
	for _, line := range bytes.Split(complete, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		lines = append(lines, line)
	}
	return lines, newOffset, nil
}
