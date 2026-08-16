package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// buildTTYLog assembles a synthetic cowrie ttylog binary matching
// src/cowrie/core/ttylog.py's TTYSTRUCT = "<iLiiLL" exactly: a fixed
// 24-byte little-endian header (op, tty, length, direction, sec, usec)
// per record, OPEN first, WRITE records with a payload, CLOSE last.
func buildTTYLog(t *testing.T, records []struct {
	op        int32
	direction int32
	sec       uint32
	usec      uint32
	data      string
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	write := func(op, length, direction int32, sec, usec uint32, data string) {
		header := make([]byte, ttyRecordHeaderSize)
		binary.LittleEndian.PutUint32(header[0:], uint32(op))
		binary.LittleEndian.PutUint32(header[4:], 0) // tty, unused
		binary.LittleEndian.PutUint32(header[8:], uint32(length))
		binary.LittleEndian.PutUint32(header[12:], uint32(direction))
		binary.LittleEndian.PutUint32(header[16:], sec)
		binary.LittleEndian.PutUint32(header[20:], usec)
		buf.Write(header)
		buf.WriteString(data)
	}
	write(ttyOpOpen, 0, 0, 0, 0, "")
	for _, r := range records {
		write(r.op, int32(len(r.data)), r.direction, r.sec, r.usec, r.data)
	}
	write(ttyOpClose, 0, 0, 0, 0, "")
	return buf.Bytes()
}

func TestParseTTYLogKeepsPreferredDirectionAndInteract(t *testing.T) {
	raw := buildTTYLog(t, []struct {
		op        int32
		direction int32
		sec       uint32
		usec      uint32
		data      string
	}{
		{ttyOpWrite, ttyDirOutput, 100, 0, "$ "},
		{ttyOpWrite, ttyDirInput, 100, 100000, "ls"}, // dropped: not the preferred direction
		{ttyOpWrite, ttyDirInteract, 100, 200000, "ls"},
		{ttyOpWrite, ttyDirOutput, 100, 500000, "file1 file2\n"},
	})

	records, err := parseTTYLog(raw)
	if err != nil {
		t.Fatalf("parseTTYLog: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 kept records (2 output + 1 interact), got %d: %+v", len(records), records)
	}
	if string(records[0].data) != "$ " || records[0].direction != ttyDirOutput {
		t.Errorf("record 0 = %+v", records[0])
	}
	if string(records[1].data) != "ls" || records[1].direction != ttyDirInteract {
		t.Errorf("record 1 (interact) = %+v", records[1])
	}
	if string(records[2].data) != "file1 file2\n" {
		t.Errorf("record 2 = %+v", records[2])
	}
}

func TestParseTTYLogTruncatedRecordErrors(t *testing.T) {
	raw := buildTTYLog(t, nil)
	// Corrupt: claim a WRITE with a length that overruns the buffer.
	corrupt := raw[:len(raw)-ttyRecordHeaderSize] // drop the CLOSE record
	header := make([]byte, ttyRecordHeaderSize)
	binary.LittleEndian.PutUint32(header[0:], uint32(ttyOpWrite))
	binary.LittleEndian.PutUint32(header[8:], 999999) // absurd length, no data follows
	corrupt = append(corrupt, header...)

	if _, err := parseTTYLog(corrupt); err == nil {
		t.Fatal("expected an error for a truncated/corrupt record, got nil")
	}
}

func TestTTYToAsciicastProducesValidHeaderAndEvents(t *testing.T) {
	raw := buildTTYLog(t, []struct {
		op        int32
		direction int32
		sec       uint32
		usec      uint32
		data      string
	}{
		{ttyOpWrite, ttyDirOutput, 1000, 0, "hello"},
		{ttyOpWrite, ttyDirOutput, 1001, 500000, " world\n"},
	})
	records, err := parseTTYLog(raw)
	if err != nil {
		t.Fatalf("parseTTYLog: %v", err)
	}
	cast := ttyToAsciicast(records)
	lines := strings.Split(strings.TrimRight(string(cast), "\n"), "\n")
	if len(lines) != 3 { // header + 2 events
		t.Fatalf("expected 3 lines (header + 2 events), got %d:\n%s", len(lines), cast)
	}
	var header map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("header not valid JSON: %v", err)
	}
	if header["version"].(float64) != 2 {
		t.Errorf("expected version 2, got %v", header["version"])
	}

	var ev0 []any
	if err := json.Unmarshal([]byte(lines[1]), &ev0); err != nil {
		t.Fatalf("event 0 not valid JSON: %v", err)
	}
	if ev0[0].(float64) != 0 {
		t.Errorf("first event should be at t=0 (relative to session start), got %v", ev0[0])
	}
	if ev0[1] != "o" {
		t.Errorf("expected event type \"o\", got %v", ev0[1])
	}
	if ev0[2] != "hello" {
		t.Errorf("expected data %q, got %q", "hello", ev0[2])
	}

	var ev1 []any
	if err := json.Unmarshal([]byte(lines[2]), &ev1); err != nil {
		t.Fatalf("event 1 not valid JSON: %v", err)
	}
	if got := ev1[0].(float64); got < 1.49 || got > 1.51 {
		t.Errorf("expected second event ~1.5s after the first, got %v", got)
	}
}

func TestTTYToAsciicastSanitizesInvalidUTF8(t *testing.T) {
	records := []ttyRecord{{direction: ttyDirOutput, seconds: 0, data: []byte{0xff, 0xfe, 'a'}}}
	cast := ttyToAsciicast(records)
	if !json.Valid(bytes.Split(cast, []byte("\n"))[1]) {
		t.Fatalf("event line is not valid JSON after sanitizing invalid UTF-8: %s", cast)
	}
}

func TestTTYRecordsToJSONRelativeTiming(t *testing.T) {
	records := []ttyRecord{
		{seconds: 500.0, data: []byte("a")},
		{seconds: 502.25, data: []byte("b")},
	}
	out := ttyRecordsToJSON(records)
	if out[0].T != 0 {
		t.Errorf("first record should be t=0, got %v", out[0].T)
	}
	if out[1].T != 2.25 {
		t.Errorf("second record should be t=2.25, got %v", out[1].T)
	}
}
