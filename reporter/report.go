package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// report is one would-be (or real) AbuseIPDB submission.
type report struct {
	IP         string
	Categories []int
	Comment    string
	Sensor     string
	Kind       string
	At         time.Time
}

// sender is the only interface allowed to turn a report into outbound
// network traffic. #68 / WORK-LEDGER.md rule 7: production reporting
// requires separate explicit authorization, enforced by a test, not
// convention -- so the type that can reach the network is deliberately
// isolated behind this interface, and newSender (below) is the single
// place that decides which implementation the rest of the program gets.
type sender interface {
	send(r report) (dryRun bool, err error)
}

// dryRunSender is the default and holds nothing capable of a network call --
// no http.Client field exists on this type at all. It only ever writes to
// the audit log.
type dryRunSender struct {
	audit *auditLog
}

func (s dryRunSender) send(r report) (bool, error) {
	s.audit.log(auditEntry{
		Action: "would_report", Service: "abuseipdb", IP: r.IP,
		Categories: r.Categories, Sensor: r.Sensor, Kind: r.Kind, At: r.At,
	})
	return true, nil
}

// liveSender is the only type in this binary that holds an *http.Client
// capable of reaching AbuseIPDB. newSender only ever constructs one when
// the caller has explicitly opted in AND supplied a real API key -- see
// newSender's doc comment for the exact gate.
type liveSender struct {
	apiKey string
	client *http.Client
	audit  *auditLog
}

const abuseIPDBReportURL = "https://api.abuseipdb.com/api/v2/report"

func (s liveSender) send(r report) (bool, error) {
	body, _ := json.Marshal(map[string]any{
		"ip":         r.IP,
		"categories": r.Categories,
		"comment":    r.Comment,
	})
	req, err := http.NewRequest(http.MethodPost, abuseIPDBReportURL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Key", s.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		s.audit.log(auditEntry{Action: "report_error", Service: "abuseipdb", IP: r.IP, Error: err.Error(), At: r.At})
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		err := fmt.Errorf("abuseipdb: HTTP %d", resp.StatusCode)
		s.audit.log(auditEntry{Action: "report_error", Service: "abuseipdb", IP: r.IP, Error: err.Error(), At: r.At})
		return false, err
	}
	s.audit.log(auditEntry{
		Action: "reported", Service: "abuseipdb", IP: r.IP,
		Categories: r.Categories, Sensor: r.Sensor, Kind: r.Kind, At: r.At,
	})
	return false, nil
}

// newSender is the one function in this program allowed to decide whether
// the reporter can reach the network. Per #68/WORK-LEDGER.md rule 7, live
// reporting requires the operator to explicitly set REPORTER_LIVE=1 *and*
// have a real API key configured -- either one missing falls back to
// dry-run, never the other way around. There is no code path here that
// upgrades a dry-run decision into a live one implicitly.
func newSender(live bool, apiKey string, audit *auditLog) sender {
	if live && apiKey != "" {
		return liveSender{apiKey: apiKey, client: &http.Client{Timeout: 10 * time.Second}, audit: audit}
	}
	return dryRunSender{audit: audit}
}
