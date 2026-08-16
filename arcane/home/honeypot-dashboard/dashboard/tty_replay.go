package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// Cowrie's own binary TTY log format (src/cowrie/core/ttylog.py,
// TTYSTRUCT = "<iLiiLL"): a fixed 24-byte little-endian record header --
// op (int32), tty (uint32, unused here), length (int32), direction (int32),
// sec (uint32), usec (uint32) -- followed by `length` bytes of data when
// op == ttyOpWrite. Confirmed directly against upstream source rather than
// inferred from behavior.
const ttyRecordHeaderSize = 24

const (
	ttyOpOpen  = 1
	ttyOpClose = 2
	ttyOpWrite = 3
)

const (
	ttyDirInput    = 1
	ttyDirOutput   = 2
	ttyDirInteract = 3
)

type ttyRecord struct {
	direction int32
	seconds   float64
	data      []byte
}

// parseTTYLog replays cowrie's own src/cowrie/scripts/asciinema.py
// conversion algorithm: the first direction seen on a WRITE record becomes
// the "preferred" direction (almost always ttyDirOutput -- what the
// attacker's terminal actually displayed, since cowrie's shell emulation
// echoes typed input back as output too), and every record in that
// direction, plus any ttyDirInteract record (an executed command, always
// shown regardless of direction), is kept in order. Bare ttyDirInput
// keystrokes are dropped, same as upstream's default conversion.
func parseTTYLog(raw []byte) ([]ttyRecord, error) {
	var records []ttyRecord
	var prefDir int32
	pos := 0
	for pos+ttyRecordHeaderSize <= len(raw) {
		op := int32(binary.LittleEndian.Uint32(raw[pos:]))
		length := int32(binary.LittleEndian.Uint32(raw[pos+8:]))
		direction := int32(binary.LittleEndian.Uint32(raw[pos+12:]))
		sec := binary.LittleEndian.Uint32(raw[pos+16:])
		usec := binary.LittleEndian.Uint32(raw[pos+20:])
		pos += ttyRecordHeaderSize

		if op == ttyOpClose {
			break
		}
		if op != ttyOpWrite {
			continue
		}
		if length < 0 || pos+int(length) > len(raw) {
			return records, fmt.Errorf("truncated record at offset %d", pos)
		}
		data := raw[pos : pos+int(length)]
		pos += int(length)

		if prefDir == 0 && direction != ttyDirInteract {
			prefDir = direction
		}
		if direction == prefDir || direction == ttyDirInteract {
			records = append(records, ttyRecord{
				direction: direction,
				seconds:   float64(sec) + float64(usec)/1e6,
				data:      data,
			})
		}
	}
	return records, nil
}

// ttyToAsciicast renders records as an asciinema v2 cast file (newline-
// delimited JSON: one header object, then one [elapsed, "o", data] array
// per record) -- a format the standalone `asciinema play`/upload tooling
// already understands, so this dashboard doesn't need to embed its own
// terminal emulator to make a recording replayable.
func ttyToAsciicast(records []ttyRecord) []byte {
	var buf bytes.Buffer
	header := map[string]any{
		"version": 2,
		"width":   80,
		"height":  24,
		"env":     map[string]string{"TERM": "xterm-256color", "SHELL": "/bin/bash"},
	}
	var start float64
	if len(records) > 0 {
		start = records[0].seconds
		header["timestamp"] = int64(start)
	}
	if hb, err := json.Marshal(header); err == nil {
		buf.Write(hb)
		buf.WriteByte('\n')
	}
	for _, rec := range records {
		elapsed := rec.seconds - start
		if elapsed < 0 {
			elapsed = 0
		}
		// Attacker-controlled bytes are not guaranteed valid UTF-8; replace
		// rather than fail so one malformed session doesn't break the whole
		// cast file.
		text := strings.ToValidUTF8(string(rec.data), "�")
		if line, err := json.Marshal([]any{elapsed, "o", text}); err == nil {
			buf.Write(line)
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

type ttyLogDoc struct {
	Shasum       string `json:"shasum"`
	SizeBytes    int64  `json:"size_bytes"`
	TTYLogBase64 string `json:"ttylog_base64"`
}

const cowrieTTYLogIndex = "cowrie-ttylog-v1"

// ttyRecordJSON is one playback record as the in-browser viewer's JS
// consumes it -- T in seconds from session start, Data already
// UTF-8-sanitized (see ttyToAsciicast's comment on attacker-controlled
// bytes).
type ttyRecordJSON struct {
	T    float64 `json:"t"`
	Data string  `json:"data"`
}

func ttyRecordsToJSON(records []ttyRecord) []ttyRecordJSON {
	out := make([]ttyRecordJSON, 0, len(records))
	var start float64
	if len(records) > 0 {
		start = records[0].seconds
	}
	for _, rec := range records {
		elapsed := rec.seconds - start
		if elapsed < 0 {
			elapsed = 0
		}
		out = append(out, ttyRecordJSON{T: elapsed, Data: strings.ToValidUTF8(string(rec.data), "�")})
	}
	return out
}

type ttyReplayPageData struct {
	pageMeta
	Shasum    string
	SizeBytes int64
	// #1268 "ask 2": the Attacker replay tab needs to know who made this
	// recording, which the recording itself (keyed purely by content hash)
	// never carries. HasAttacker is false when no in-memory event still
	// references this shasum (log-tail-bounded cache rolled it off) or the
	// resolved source IP fails attackerData's own netip.ParseAddr guard --
	// the tab degrades to an explanatory empty state rather than a zero-value
	// Attacker rendering as a broken-looking page.
	HasAttacker    bool
	Attacker       attackerPage
	MapTileURL     string
	MapAttribution string
	MapLat         float64
	MapLon         float64
	MapHasPoint    bool
	// ShasumLink lets the timeline template flag "this recording" among
	// the attacker's other events -- storedEvent.TTYReplay holds the full
	// "/tty/<hash>" link (classify.go's own #612/#638 comment), not the
	// bare Shasum above, and html/template has no string-concatenation
	// operator to rebuild that comparison value inline.
	ShasumLink string
}

// ttyRecordingSourceIP finds the storedEvent that produced this recording --
// the same in-memory scan recordingsData (recordings.go) already does over
// the whole cache, narrowed to one shasum match. No new index/query: this
// reads the identical s.getEvents() cache every other listing page on this
// dashboard already uses.
func (s *store) ttyRecordingSourceIP(shasum string) (storedEvent, bool) {
	// classify.go sets TTYReplay to the full "/tty/<hash>" link (its own
	// #612/#638 comment, and recordingsData/recordings.html render it
	// directly as an href) -- not the bare hash this function's own
	// caller works with, so the comparison has to rebuild that same link
	// rather than compare against shasum directly.
	want := "/tty/" + shasum
	for _, e := range s.getEvents() {
		if e.TTYReplay == want {
			return e, true
		}
	}
	return storedEvent{}, false
}

// fetchTTYLog is the one place that talks to cowrie-ttylog-v1 and decodes
// the stored base64 -- every /tty/ route below is a thin wrapper around it.
func (s *store) fetchTTYLog(shasum string) (doc ttyLogDoc, raw []byte, status int, errMsg string) {
	if s.es == nil {
		return ttyLogDoc{}, nil, http.StatusServiceUnavailable, "Elasticsearch is required to serve TTY recordings and is not configured"
	}
	hit, found, err := s.es.docGet(cowrieTTYLogIndex, shasum)
	if err != nil {
		return ttyLogDoc{}, nil, http.StatusBadGateway, "Elasticsearch lookup failed: " + err.Error()
	}
	if !found {
		return ttyLogDoc{}, nil, http.StatusNotFound, "TTY recording not found — it may not have been mirrored into Elasticsearch yet"
	}
	if err := json.Unmarshal(hit.Source, &doc); err != nil {
		return ttyLogDoc{}, nil, http.StatusInternalServerError, "malformed TTY log document"
	}
	raw, err = base64.StdEncoding.DecodeString(doc.TTYLogBase64)
	if err != nil {
		return ttyLogDoc{}, nil, http.StatusInternalServerError, "corrupt TTY log document"
	}
	return doc, raw, http.StatusOK, ""
}

// serveTTYReplay serves a cowrie TTY session recording purely from its
// Elasticsearch mirror (es-results-importer's cowrie_ttylog source) -- per
// #638, the dashboard must never open this file on the host directly, even
// though it's sitting right there on the bind mount #611 added.
//
// Routes (all under /tty/<shasum>):
//
//	/tty/<shasum>       in-browser terminal viewer (this handler renders the
//	                    page; the page's own JS fetches .json and plays it back)
//	/tty/<shasum>.json  playback records for the viewer
//	/tty/<shasum>.cast  asciinema v2 cast file, for real replay/upload tooling
//	/tty/<shasum>.raw   the original cowrie ttylog binary, unmodified
func (s *store) serveTTYReplay(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
	name := strings.TrimPrefix(r.URL.Path, "/tty/")
	var suffix string
	for _, ext := range []string{".json", ".cast", ".raw"} {
		if strings.HasSuffix(name, ext) {
			suffix = ext
			name = strings.TrimSuffix(name, ext)
			break
		}
	}
	shasum := name
	if !hashName.MatchString(shasum) {
		http.NotFound(w, r)
		return
	}

	if suffix == "" {
		// The viewer page itself doesn't need the recording yet -- its own
		// JS fetches /tty/<shasum>.json once loaded. Rendering the shell
		// immediately (rather than blocking on an ES round trip here) means
		// a slow/unavailable ES surfaces as a normal in-page fetch error,
		// not a broken page load.
		data := &ttyReplayPageData{Shasum: shasum, ShasumLink: "/tty/" + shasum}
		snap := s.get()
		data.MapTileURL, data.MapAttribution = snap.MapTileURL, snap.MapAttribution
		if event, ok := s.ttyRecordingSourceIP(shasum); ok {
			if attacker, ok := s.attackerData(event.SrcIP); ok {
				data.HasAttacker = true
				data.Attacker = attacker
			}
			// event.Lat/Lon come from the same GeoIP enrichment
			// aggregate.go already ran at ingest time (geo.Lat/geo.Lon,
			// aggregate.go:176-177) -- no separate s.geo.lookup call
			// needed here.
			if event.Lat != 0 || event.Lon != 0 {
				data.MapLat, data.MapLon, data.MapHasPoint = event.Lat, event.Lon, true
			}
		}
		renderPage(w, tmpl, "tty-replay", data)
		return
	}

	doc, raw, status, errMsg := s.fetchTTYLog(shasum)
	if errMsg != "" {
		http.Error(w, errMsg, status)
		return
	}

	switch suffix {
	case ".raw":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+shasum+`.ttylog"`)
		_, _ = w.Write(raw)
	case ".cast":
		records, err := parseTTYLog(raw)
		if err != nil {
			http.Error(w, "could not parse TTY log: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/x-asciicast+json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+shasum+`.cast"`)
		_, _ = w.Write(ttyToAsciicast(records))
	case ".json":
		records, err := parseTTYLog(raw)
		if err != nil {
			http.Error(w, "could not parse TTY log: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"shasum":     doc.Shasum,
			"size_bytes": doc.SizeBytes,
			"records":    ttyRecordsToJSON(records),
		})
	}
}
