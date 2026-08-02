package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// blocklistDeService maps a sensor + event kind to Blocklist.de's own
// "service" vocabulary (https://www.blocklist.de/en/httpreports.html?help=,
// confirmed against fail2ban's own real config/action.d/blocklist_de.conf).
// Unlike AbuseIPDB's behavior-based categories, Blocklist.de's vocabulary
// names the *daemon/protocol* being attacked (ssh, ftp, mail, a handful of
// specific web CMSes) -- a narrower, single-host-fail2ban-shaped model that
// doesn't fit most of this stack's sensor mix cleanly.
//
// cowrie is the one confident, unambiguous fit: it emulates an SSH server,
// full stop, so login/command events map to "ssh". Every other sensor is
// deliberately left unmapped (returns ""), not because nothing reportable
// happens there, but because Blocklist.de's vocabulary can't represent it
// honestly:
//   - dionaea speaks several protocols (SMB/FTP/TFTP/MSSQL/MySQL/...) but this
//     reporter's event.Kind is just "download" regardless of which one --
//     there's no per-protocol signal left to pick a service from.
//   - http-honeypot/api-honeypot serve several personas (a generic "NexusAI"
//     login form, a phpMyAdmin-styled page, Tomcat Manager, a fake API
//     gateway...), and only requests to wp-login.php/wp-admin/xmlrpc.php are
//     genuinely WordPress -- that distinction exists in the sensor's own
//     classify() but doesn't survive into this reporter's coarse
//     "login"/"scan" Kind vocabulary (event.go's kindOf). Reporting every
//     generic login-form hit as "wp-bruteforce" would misrepresent the
//     target to Blocklist.de.
//   - multipot/conpot/dnp3 are port scans and ICS protocol probes;
//     Blocklist.de has no scan or SCADA/ICS category at all.
//   - suricata's alert categories are behavior-based (same shape as
//     AbuseIPDB's), not protocol-based, and this reporter doesn't carry the
//     alert's actual dest-port/proto through to Kind, so there's no reliable
//     way to pick a specific daemon from it either.
//
// Same conservative-by-default rule as categorize.go: an unrecognized or
// ambiguous (sensor, kind) maps to "" ("not reportable to this service"),
// not a guessed catch-all.
func blocklistDeService(sensor, kind string) string {
	if sensor == "cowrie" && (kind == "login" || kind == "command") {
		return "ssh"
	}
	return ""
}

// blocklistDeReport is one would-be (or real) Blocklist.de submission.
type blocklistDeReport struct {
	IP      string
	Service string
	Sensor  string
	Kind    string
	Logs    string
	At      time.Time
}

// blocklistDeSender mirrors report.go's sender interface for this second,
// independent reporting destination -- see report.go's own doc comment for
// why the type capable of a real network call is deliberately isolated
// behind an interface like this rather than reached directly.
type blocklistDeSender interface {
	send(r blocklistDeReport) (dryRun bool, err error)
}

// dryRunBlocklistDeSender is the default, same shape as report.go's
// dryRunSender: no http.Client field at all, only ever writes to the audit
// log.
type dryRunBlocklistDeSender struct {
	audit *auditLog
}

func (s dryRunBlocklistDeSender) send(r blocklistDeReport) (bool, error) {
	s.audit.log(auditEntry{
		Action: "would_report", Service: "blocklistde", IP: r.IP,
		Sensor: r.Sensor, Kind: r.Kind, At: r.At,
	})
	return true, nil
}

// blocklistDeReportURL and the request shape in send() below are taken
// directly from fail2ban's own real, production
// config/action.d/blocklist_de.conf -- not blocklist.de's own docs, which
// show a plain-http GET example nobody actually battle-tested this against.
// fail2ban's real usage is HTTPS, POST, form-encoded body, format=text.
//
// What is NOT independently verified here: the shape of a json/php response
// body on success or failure -- there is no public example of either.
// fail2ban's own reference implementation doesn't parse the response body at
// all; it relies solely on curl --fail (an HTTP status code check) as its
// only success signal. liveBlocklistDeSender does the same below: HTTP
// status code is the only signal this code trusts.
const blocklistDeReportURL = "https://www.blocklist.de/en/httpreports.html"

// liveBlocklistDeSender is the only type in this binary that can reach
// Blocklist.de. newBlocklistDeSender only ever constructs one when the
// caller has explicitly opted in AND supplied both a sender identity and an
// API key -- same live-gate discipline as report.go's liveSender.
type liveBlocklistDeSender struct {
	email  string // Blocklist.de's own "server" param -- the reporting sender's identity, historically an email address
	apiKey string
	client *http.Client
	audit  *auditLog
}

func (s liveBlocklistDeSender) send(r blocklistDeReport) (bool, error) {
	form := url.Values{
		"server":  {s.email},
		"apikey":  {s.apiKey},
		"service": {r.Service},
		"ip":      {r.IP},
		"logs":    {r.Logs},
		"format":  {"text"},
	}
	req, err := http.NewRequest(http.MethodPost, blocklistDeReportURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		s.audit.log(auditEntry{Action: "report_error", Service: "blocklistde", IP: r.IP, Error: err.Error(), At: r.At})
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		err := fmt.Errorf("blocklistde: HTTP %d", resp.StatusCode)
		s.audit.log(auditEntry{Action: "report_error", Service: "blocklistde", IP: r.IP, Error: err.Error(), At: r.At})
		return false, err
	}
	s.audit.log(auditEntry{
		Action: "reported", Service: "blocklistde", IP: r.IP,
		Sensor: r.Sensor, Kind: r.Kind, At: r.At,
	})
	return false, nil
}

// newBlocklistDeSender mirrors newSender's exact live-gate rule: both live
// AND a real sender identity+API key are required, either one missing falls
// back to dry-run, never the other way around.
func newBlocklistDeSender(live bool, email, apiKey string, audit *auditLog) blocklistDeSender {
	if live && email != "" && apiKey != "" {
		return liveBlocklistDeSender{email: email, apiKey: apiKey, client: &http.Client{Timeout: 10 * time.Second}, audit: audit}
	}
	return dryRunBlocklistDeSender{audit: audit}
}
