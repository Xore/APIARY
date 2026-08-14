package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type workbenchModelComponent struct {
	Status string   `json:"status"`
	Codes  []string `json:"codes,omitempty"`
}

type workbenchModelStatus struct {
	SchemaVersion int                                `json:"schema_version"`
	CheckedAt     string                             `json:"checked_at"`
	Overall       string                             `json:"overall"`
	Codes         []string                           `json:"codes,omitempty"`
	Slots         map[string]workbenchModelComponent `json:"slots,omitempty"`
	Runtime       workbenchModelComponent            `json:"runtime"`
	Host          workbenchModelComponent            `json:"host"`
	AdvisoryOnly  bool                               `json:"advisory_only"`
	Available     bool                               `json:"-"`
	Reason        string                             `json:"-"`
}

// loadWorkbenchModelStatus consumes only the fixed local Unix-socket adapter.
// It cannot dial a browser-supplied address and it cannot access the owner-only
// host artifact directly. Drift is advisory: callers render it but never feed
// it into analyzer applicability or ingestion decisions.
func loadWorkbenchModelStatus() workbenchModelStatus {
	status := workbenchModelStatus{Overall: "unavailable", AdvisoryOnly: true, Reason: "model-status adapter is not configured"}
	socket := filepath.Clean(strings.TrimSpace(os.Getenv("MODEL_STATUS_SOCKET")))
	if socket == "." || !filepath.IsAbs(socket) || strings.Contains(socket, "..") {
		return status
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}}
	// This Transport is built fresh per call and discarded after one request,
	// so its idle connection must be closed explicitly (#1339): Body.Close()
	// alone only returns the connection to THIS transport's own idle pool --
	// it doesn't close the underlying socket -- and with the transport itself
	// then unreferenced except by the pooled conn's own readLoop goroutine,
	// nothing would ever call CloseIdleConnections for it otherwise, leaking
	// one goroutine and one open Unix-socket fd per call indefinitely.
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("http://model-status/v1/status")
	if err != nil {
		status.Reason = "model-status adapter is unavailable"
		return status
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		status.Reason = "model-status adapter returned an invalid response"
		return status
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return workbenchModelStatus{Overall: "unavailable", AdvisoryOnly: true, Reason: "model-status adapter returned an invalid schema"}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || !validWorkbenchModelStatus(status) {
		return workbenchModelStatus{Overall: "unavailable", AdvisoryOnly: true, Reason: "model-status adapter returned an invalid schema"}
	}
	status.Available = true
	status.Reason = "read-only host adapter"
	return status
}

func validWorkbenchModelStatus(status workbenchModelStatus) bool {
	if status.SchemaVersion != 1 || !status.AdvisoryOnly || !validModelState(status.Overall) || len(status.Slots) > 3 || len(status.Codes) > 32 {
		return false
	}
	for name, slot := range status.Slots {
		if name != "ghidra" && name != "sessions" && name != "revdeck" {
			return false
		}
		if !validModelState(slot.Status) || len(slot.Codes) > 32 {
			return false
		}
	}
	for _, component := range []workbenchModelComponent{status.Runtime, status.Host} {
		if component.Status != "" && !validModelState(component.Status) || len(component.Codes) > 32 {
			return false
		}
	}
	return true
}

func validModelState(value string) bool {
	return value == "approved" || value == "drift" || value == "unavailable"
}
