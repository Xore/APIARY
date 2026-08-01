package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// services_control.go -- the dashboard's only path to hp-services-adapter
// (#197). Mirrors workbench_model_status.go's transport exactly: a fixed
// local AF_UNIX socket, never a browser-supplied address, with the response
// schema validated field-by-field before anything here is trusted. Unlike
// the read-only model-status adapter, this one accepts actions (start/stop/
// restart) -- the adapter itself holds the real allowlist and is the only
// thing with docker.sock; this client just carries the request and refuses
// to forward anything the adapter's own schema doesn't recognize.

type serviceStatus struct {
	Name         string `json:"name"`
	State        string `json:"state"`
	Health       string `json:"health,omitempty"`
	ExitCode     *int   `json:"exit_code"`
	StartedAt    string `json:"started_at,omitempty"`
	RestartCount *int   `json:"restart_count"`
}

var validServiceStates = map[string]bool{
	"running": true, "exited": true, "restarting": true, "paused": true,
	"created": true, "removing": true, "dead": true, "not_found": true, "unknown": true,
}

func validServiceStatus(s serviceStatus) bool {
	return strings.TrimSpace(s.Name) != "" && validServiceStates[s.State]
}

func servicesAdapterSocket() (string, bool) {
	socket := filepath.Clean(strings.TrimSpace(os.Getenv("SERVICES_ADAPTER_SOCKET")))
	if socket == "." || !filepath.IsAbs(socket) || strings.Contains(socket, "..") {
		return "", false
	}
	return socket, true
}

func servicesAdapterClient(timeout time.Duration) (*http.Client, string, bool) {
	socket, ok := servicesAdapterSocket()
	if !ok {
		return nil, "", false
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return client, socket, true
}

// loadServicesStatus fetches the current allowlisted-container inventory
// from hp-services-adapter. The bool return distinguishes "the adapter isn't
// configured or reachable" from "it returned zero services" -- callers must
// not render an empty pane as if it were an authoritative empty state.
func loadServicesStatus() ([]serviceStatus, bool, string) {
	client, _, ok := servicesAdapterClient(8 * time.Second)
	if !ok {
		return nil, false, "services adapter is not configured"
	}
	response, err := client.Get("http://services-adapter/v1/services")
	if err != nil {
		return nil, false, "services adapter is unavailable"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return nil, false, "services adapter returned an invalid response"
	}
	var payload struct {
		Services []serviceStatus `json:"services"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 256<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, false, "services adapter returned an invalid schema"
	}
	for _, service := range payload.Services {
		if !validServiceStatus(service) {
			return nil, false, "services adapter returned an invalid schema"
		}
	}
	return payload.Services, true, ""
}

var validServiceActions = map[string]bool{"start": true, "stop": true, "restart": true}

// performServiceAction asks hp-services-adapter to start/stop/restart one
// container. The adapter itself enforces the real allowlist and returns 403
// for anything not on it -- this only pre-validates the action verb so an
// obviously-bad request never leaves the dashboard.
func performServiceAction(name, action string) (bool, int, string) {
	if strings.TrimSpace(name) == "" || !validServiceActions[action] {
		return false, http.StatusBadRequest, "unsupported action"
	}
	client, _, ok := servicesAdapterClient(15 * time.Second)
	if !ok {
		return false, http.StatusServiceUnavailable, "services adapter is not configured"
	}
	request, err := http.NewRequest(http.MethodPost, "http://services-adapter/v1/services/"+url.PathEscape(name)+"/"+action, nil)
	if err != nil {
		return false, http.StatusInternalServerError, "could not build request"
	}
	response, err := client.Do(request)
	if err != nil {
		return false, http.StatusServiceUnavailable, "services adapter is unavailable"
	}
	defer response.Body.Close()
	var payload struct {
		OK     bool   `json:"ok"`
		Action string `json:"action"`
		Name   string `json:"name"`
		Error  string `json:"error"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<10))
	decoder.DisallowUnknownFields()
	_ = decoder.Decode(&payload)
	if response.StatusCode != http.StatusOK || !payload.OK {
		reason := payload.Error
		if reason == "" {
			reason = fmt.Sprintf("services adapter returned %d", response.StatusCode)
		}
		return false, response.StatusCode, reason
	}
	return true, http.StatusOK, ""
}

const maxServiceLogLines = 1000

// fetchServiceLogs tails one container's log through hp-services-adapter.
// lines is clamped the same way the adapter itself clamps it -- belt and
// suspenders, since the adapter is the actual enforcement point.
func fetchServiceLogs(name string, lines int) (string, int, string) {
	if strings.TrimSpace(name) == "" {
		return "", http.StatusBadRequest, "missing service name"
	}
	if lines <= 0 {
		lines = 200
	}
	if lines > maxServiceLogLines {
		lines = maxServiceLogLines
	}
	client, _, ok := servicesAdapterClient(15 * time.Second)
	if !ok {
		return "", http.StatusServiceUnavailable, "services adapter is not configured"
	}
	response, err := client.Get(fmt.Sprintf("http://services-adapter/v1/services/%s/logs?lines=%d", url.PathEscape(name), lines))
	if err != nil {
		return "", http.StatusServiceUnavailable, "services adapter is unavailable"
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", response.StatusCode, fmt.Sprintf("services adapter returned %d", response.StatusCode)
	}
	var payload struct {
		Name  string `json:"name"`
		Lines int    `json:"lines"`
		Log   string `json:"log"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return "", http.StatusBadGateway, "services adapter returned an invalid schema"
	}
	return payload.Log, http.StatusOK, ""
}
