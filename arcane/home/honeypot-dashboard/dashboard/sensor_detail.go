package main

// sensor_detail.go -- #1538: a per-sensor detail view. events.go's /events
// page (and every KPI/table across the dashboard) only ever shows the
// generic, cross-sensor `event` shape classify.go normalizes every sensor
// down to -- exactly the gap #1538 names: an operator watching mailoney
// catch a phish can see "envelope" / "mail-body" in the generic event
// list, but not the sender, the recipients, or the mail body itself.
//
// This file is the design pass' first real slice, not the whole rollout.
// Surveying classify.go and ip-enrichment-worker/canonical.go (this
// session's sibling worker, which already promotes a subset of these same
// per-sensor fields into canonical_* keys for a *different* purpose --
// TopCreds/TopCommands aggregation, #1197/#1202) turned up a clear split:
//
//   - mailoney (classify.go's "mailoney (#1422)" branch): genuinely
//     distinct structured data. mailoney/json_log_patch.py emits three flat
//     event kinds per SMTP session -- "login" (AUTH PLAIN username/
//     password), "envelope" (the raw "MAIL FROM:"/"RCPT TO:" command line),
//     "mail-body" (size/truncated/body_path plus up to 512 bytes of the
//     actual body as body_preview) -- all tagged with the same session_id.
//     None of that (sender, recipients, or the body itself) rides on
//     classify.go's `event` struct; only a human-readable one-line
//     ev.detail summary does. Implemented below: loadMailoneySessions
//     groups the three event kinds by session_id into one mailoneySession
//     per SMTP conversation.
//
//   - http-honeypot (main.go's own `event` struct in
//     arcane/home/honeypot-http/http-honeypot): also genuinely distinct --
//     method/host/path/query/headers/body/status/tarpit fields per request,
//     none of which classify.go's http/tanner branch (~line 1009) surfaces
//     beyond a "METHOD path" summary line. Implemented below:
//     loadHTTPHoneypotRequests reads the raw per-request fields directly.
//
//   - tanner (classify.go's shared tanner_report.json/http-honeypot
//     branch, ~line 1009, gated on `ev.sensor == "tanner"` at line 1074):
//     shares http-honeypot's method/path/headers request-log shape, but
//     carries its own richer fields http-honeypot never sets -- post_data
//     (the emulator's matched attack payload, e.g. a SQLi/XSS/cmd_exec
//     string), cookies (session-hijack/injection payloads), and the
//     detection itself (response_msg.response.message.detection.
//     {name,payload.value} -- tannerDetectionName/tannerDetectionPayload
//     in classify.go), a nested object BaseHandler.get_emulation_result()
//     writes only when one of tanner's 10 emulators actually matched --
//     not a flat per-request field the way http-honeypot's own fields
//     are. Implemented below: loadTannerRequests reads these directly,
//     same discipline as loadHTTPHoneypotRequests, no classify.go reuse.
//
// Deliberately NOT covered by this slice (see the #1538 issue comment and
// this PR's description for the fuller reasoning):
//
//   - cowrie: already has dedicated per-session surfaces (session.html /
//     page_session.go groups a whole SSH session chronologically,
//     tty_replay.html replays the actual terminal). A third "cowrie tab"
//     here would duplicate those, not add new structured data.
//   - dionaea: its distinct fields (credentials[0], exploit/shellcode
//     download metadata) are payload-hash-centric and already surface
//     through /payloads' own captured-file detail view.
//   - every sensor promoteCanonicalFields' own doc comment already
//     excludes from field-promotion (dns-honeypot, every conpot persona,
//     wordpot's template-matched fields, etc.): confirmed to have no
//     structured field beyond what ev.detail already renders as a single
//     line, so a dedicated tab would show nothing classify.go doesn't
//     already summarize.
//
// Extension pattern for the next sensor: add a query/group function here
// (loadXSensorY, same shape as the three below -- term-filter honeypot-v2-*
// on event.sensor, read the raw honeypot.* fields the sensor's own source
// actually writes, no classify.go involvement), a field to sensorDetailPage,
// a populate call in sensorDetailData, and one more <button data-dashboard-
// tab="sd-...">/<div data-dashboard-panel="sd-..."> pair in ui/sensors.html
// -- hp-app.js's tab controller (static/hp-app.js's "workspace tabs"
// section) already drives any number of panels generically from the DOM,
// no JS change needed.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

// sensorRawEventCap bounds a single raw-event query this file issues --
// same reasoning as esEventsPageSize/esEventsMaxPages (events_es.go): a
// plain, unpaginated query capped well under Elasticsearch's own
// max_result_window, wide enough to cover a real burst within
// esOverviewWindow without this page's query cost scaling unbounded with
// attacker traffic volume the way #880 already fixed for the aggregate
// rebuild path.
const sensorRawEventCap = 3000

// mailoneySessionCap bounds how many grouped SMTP sessions render on the
// page -- a session table row is far heavier (envelope lines, a body
// preview) than a flat event-list row, so this stays well under
// sensorRawEventCap.
const mailoneySessionCap = 150

// httpHoneypotRequestCap bounds how many raw HTTP requests render on the
// page, same reasoning as mailoneySessionCap.
const httpHoneypotRequestCap = 300

// tannerRequestCap bounds how many raw tanner requests render on the page,
// same reasoning as httpHoneypotRequestCap.
const tannerRequestCap = 300

// mailoneySession groups mailoney/json_log_patch.py's three flat event
// kinds ("login", "envelope", "mail-body") by their shared session_id into
// one SMTP conversation -- the sender/recipient/body view #1538 names
// mailoney as the driving example for.
type mailoneySession struct {
	SessionID string
	When      string // latest event's @timestamp seen for this session
	IP        string
	Port      string
	LoggedIn  bool
	User      string
	Pass      string
	// MailFrom/RcptTo hold the raw "mail from:"/"rcpt to:" command lines in
	// the order the SMTP conversation sent them -- a session can (and in
	// practice with a real MTA handshake does) send more than one RCPT TO.
	MailFrom []string
	RcptTo   []string
	// BodySize/Truncated/BodyPath/BodyPreview mirror mail-body's own fields
	// exactly (json_log_patch.py's BODY_NEW): BodyPreview is capped at 512
	// bytes there, not here -- this page shows exactly what mailoney chose
	// to log, no further truncation.
	BodySize    int64
	Truncated   bool
	BodyPath    string
	BodyPreview string
}

// httpHoneypotRequest mirrors one http-honeypot request exactly as
// arcane/home/honeypot-http/http-honeypot/main.go's own `event` struct
// writes it -- field names intentionally identical, not reinterpreted,
// same discipline auth_events.go's authFailureEvent doc comment describes
// for auth-events-worker's own record shape.
type httpHoneypotRequest struct {
	When        string
	IP          string
	Method      string
	Host        string
	Path        string
	Query       string
	UserAgent   string
	Headers     map[string]string
	Body        string
	Username    string
	Password    string
	AuthType    string
	Status      int
	Category    string
	Tarpitted   bool
	TarpitBytes int
	TarpitMS    int64
}

// tannerRequest mirrors one tanner_report.json request as tanner's own
// json_log_patch.py/BaseHandler write it -- the same method/path/headers
// request-log shape http-honeypot uses (classify.go's shared branch,
// ~line 1009), plus the fields only tanner ever sets: PostData/Cookies
// (raw request-side data an emulator inspects) and DetectionName/
// DetectionPayload (the emulator's own verdict + captured execution
// result, dug out of the nested response_msg.response.message.detection
// object by classify.go's tannerDetectionName/tannerDetectionPayload --
// mirrored here rather than imported, since those two helpers return a
// single formatted string for ev.detail's one-line summary, not the
// structured fields this page wants to show separately).
type tannerRequest struct {
	When             string
	IP               string
	Method           string
	Path             string
	UserAgent        string
	Headers          map[string]string
	Username         string
	Password         string
	Tarpitted        bool
	TarpitBytes      int
	TarpitMS         int64
	PostData         map[string]string
	Cookies          map[string]string
	DetectionName    string
	DetectionPayload string
}

// sensorRawHit is the shared _search response shape both query functions
// below unmarshal into: the same {@timestamp, honeypot:{...}} envelope
// loadSensorEventsES already reads (events_es.go), just without routing
// the honeypot.* payload through classify() -- this page wants the raw
// per-sensor fields classify() deliberately collapses into ev.detail, not
// the normalized shape.
type sensorRawHit struct {
	Source struct {
		Timestamp string         `json:"@timestamp"`
		Honeypot  map[string]any `json:"honeypot"`
	} `json:"_source"`
}

// querySensorRaw runs a single, unpaginated term-filtered search against
// honeypot-v2-* for event.sensor == sensor, newest-or-oldest first per
// sortDesc, capped at sensorRawEventCap and esOverviewWindow -- the same
// index/window every other ES-sourced sensor query in this dashboard uses
// (events_es.go, es_aggregate.go), just without loadSensorEventsES's
// PIT/search_after pagination machinery: a single bounded page is enough
// for a detail view (as opposed to the aggregate rebuild path, which must
// account for every event).
func querySensorRaw(es *esClient, sensor string, sortDesc bool) ([]sensorRawHit, bool) {
	if es == nil {
		return nil, false
	}
	order := "asc"
	if sortDesc {
		order = "desc"
	}
	body, err := json.Marshal(map[string]any{
		"size": sensorRawEventCap,
		"sort": []map[string]any{{"@timestamp": order}},
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []map[string]any{
					{"term": map[string]any{"event.sensor": sensor}},
					{"range": map[string]any{"@timestamp": map[string]any{"gte": esOverviewWindow}}},
				},
			},
		},
	})
	if err != nil {
		return nil, false
	}
	b, err := es.searchBody("/honeypot-v2-*/_search", body)
	if err != nil {
		return nil, false
	}
	var v struct {
		Hits struct {
			Hits []sensorRawHit `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil, false
	}
	return v.Hits.Hits, true
}

// loadMailoneySessions groups mailoney's raw login/envelope/mail-body
// events by session_id. Queried oldest-first so MailFrom/RcptTo accumulate
// in the SMTP conversation's real order, then re-sorted newest-session-first
// for display -- the same "query order != display order" split
// buildViaMap's own doc comment (classify.go) uses for the same reason.
func (s *store) loadMailoneySessions() ([]mailoneySession, bool) {
	hits, ok := querySensorRaw(s.es, "mailoney", false)
	if !ok {
		return nil, false
	}

	order := make([]string, 0, len(hits))
	bySession := map[string]*mailoneySession{}
	for _, h := range hits {
		e := h.Source.Honeypot
		if e == nil {
			continue
		}
		sid := str(e["session_id"])
		if sid == "" {
			continue
		}
		sess, seen := bySession[sid]
		if !seen {
			sess = &mailoneySession{SessionID: sid, IP: str(e["src_ip"]), Port: num(e["src_port"])}
			bySession[sid] = sess
			order = append(order, sid)
		}
		sess.When = h.Source.Timestamp
		switch str(e["event"]) {
		case "login":
			sess.LoggedIn = true
			sess.User, sess.Pass = str(e["username"]), str(e["password"])
		case "envelope":
			cmd := strings.TrimSpace(str(e["command"]))
			switch lower := strings.ToLower(cmd); {
			case strings.HasPrefix(lower, "mail from"):
				sess.MailFrom = append(sess.MailFrom, cmd)
			case strings.HasPrefix(lower, "rcpt to"):
				sess.RcptTo = append(sess.RcptTo, cmd)
			}
		case "mail-body":
			sess.BodySize = int64(numFloat(e["size"]))
			if truncated, ok := e["truncated"].(bool); ok {
				sess.Truncated = truncated
			}
			sess.BodyPath = str(e["body_path"])
			sess.BodyPreview = str(e["body_preview"])
		}
	}

	sessions := make([]mailoneySession, 0, len(order))
	for _, sid := range order {
		sessions = append(sessions, *bySession[sid])
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].When > sessions[j].When })
	if len(sessions) > mailoneySessionCap {
		sessions = sessions[:mailoneySessionCap]
	}
	return sessions, true
}

// loadHTTPHoneypotRequests reads http-honeypot's raw per-request fields
// directly -- no session grouping needed, unlike mailoney: every request
// is already a complete, self-contained record (main.go's ServeHTTP writes
// one event per request, not a multi-line conversation).
func (s *store) loadHTTPHoneypotRequests() ([]httpHoneypotRequest, bool) {
	hits, ok := querySensorRaw(s.es, "http-honeypot", true)
	if !ok {
		return nil, false
	}

	out := make([]httpHoneypotRequest, 0, len(hits))
	for _, h := range hits {
		e := h.Source.Honeypot
		if e == nil {
			continue
		}
		req := httpHoneypotRequest{
			When:        h.Source.Timestamp,
			IP:          str(e["src_ip"]),
			Method:      str(e["method"]),
			Host:        str(e["host"]),
			Path:        str(e["path"]),
			Query:       str(e["query"]),
			UserAgent:   str(e["user_agent"]),
			Headers:     headerMap(e["headers"]),
			Body:        str(e["body"]),
			Username:    str(e["username"]),
			Password:    str(e["password"]),
			AuthType:    str(e["auth_type"]),
			Status:      int(numFloat(e["status"])),
			Category:    str(e["category"]),
			TarpitBytes: int(numFloat(e["tarpit_bytes"])),
			TarpitMS:    int64(numFloat(e["tarpit_ms"])),
		}
		if tarpitted, ok := e["tarpitted"].(bool); ok {
			req.Tarpitted = tarpitted
		}
		out = append(out, req)
		if len(out) >= httpHoneypotRequestCap {
			break
		}
	}
	return out, true
}

// loadTannerRequests reads tanner's raw per-request fields directly, same
// no-grouping posture as loadHTTPHoneypotRequests (every tanner_report.json
// record is already a complete request), but pulling the extra fields only
// tanner carries: PostData/Cookies (raw maps, key-cased like classify.go's
// own #575 cookie handling via stringMap, not lowercased like headers) and
// the nested detection object (response_msg.response.message.detection --
// present only when one of tanner's emulators actually matched, per
// tannerDetectionName/tannerDetectionPayload's own doc comments in
// classify.go). The legacy tanner "peer" session-report shape (classify.go
// ~line 972, no method/category field) is skipped here the same way
// promoteWebRequestFields (ip-enrichment-worker/canonical.go) skips it: it
// carries none of these per-request fields, only a paths[]/attack_types[]
// summary already visible in the generic /events list.
func (s *store) loadTannerRequests() ([]tannerRequest, bool) {
	hits, ok := querySensorRaw(s.es, "tanner", true)
	if !ok {
		return nil, false
	}

	out := make([]tannerRequest, 0, len(hits))
	for _, h := range hits {
		e := h.Source.Honeypot
		if e == nil {
			continue
		}
		if str(e["method"]) == "" && str(e["category"]) == "" {
			continue // legacy "peer" shape -- no per-request fields to show
		}
		if str(e["category"]) == "startup" {
			continue
		}
		hdr := headerMap(e["headers"])
		// Real client IP rides in CF/proxy headers when fronted by
		// Cloudflare, same preference order as classify.go's shared
		// tanner_report.json/http-honeypot branch (~line 1041) -- the
		// transport-level src_ip is Cloudflare's own edge IP otherwise.
		ip := firstNonEmpty(headerVal(hdr, "cf-connecting-ip"), headerVal(hdr, "x-real-ip"),
			firstHop(headerVal(hdr, "x-forwarded-for")), str(e["src_ip"]))
		req := tannerRequest{
			When:             h.Source.Timestamp,
			IP:               ip,
			Method:           str(e["method"]),
			Path:             str(e["path"]),
			UserAgent:        headerVal(hdr, "user-agent"),
			Headers:          hdr,
			Username:         str(e["username"]),
			Password:         str(e["password"]),
			TarpitBytes:      int(numFloat(e["tarpit_bytes"])),
			TarpitMS:         int64(numFloat(e["tarpit_ms"])),
			PostData:         stringMap(e["post_data"]),
			Cookies:          stringMap(e["cookies"]),
			DetectionName:    tannerDetectionName(e),
			DetectionPayload: tannerDetectionPayload(e),
		}
		if tarpitted, ok := e["tarpitted"].(bool); ok {
			req.Tarpitted = tarpitted
		}
		out = append(out, req)
		if len(out) >= tannerRequestCap {
			break
		}
	}
	return out, true
}

// sensorDetailPage is /sensors' page data. All sensor slices are queried
// live, synchronously, on each request -- same posture as auth_events.go's
// authEventsData/deadLetters (elastic.go): a bounded, single-page ES query
// per load, no background cache, appropriate for a detail view an operator
// opens occasionally rather than a KPI polled every few seconds.
type sensorDetailPage struct {
	pageMeta
	Generated    time.Time
	Enabled      bool
	Mailoney     []mailoneySession
	HTTPRequests []httpHoneypotRequest
	Tanner       []tannerRequest
}

func (s *store) sensorDetailData(r *http.Request) sensorDetailPage {
	page := sensorDetailPage{Generated: time.Now(), Enabled: s.es != nil}
	if s.es == nil {
		return page
	}
	if sessions, ok := s.loadMailoneySessions(); ok {
		page.Mailoney = sessions
	}
	if reqs, ok := s.loadHTTPHoneypotRequests(); ok {
		page.HTTPRequests = reqs
	}
	if reqs, ok := s.loadTannerRequests(); ok {
		page.Tanner = reqs
	}
	return page
}
