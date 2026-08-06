package main

import (
	"html/template"
	"net/http"
	"path/filepath"
	"regexp"
)

// windowsSandboxLiveJob (#805) reports the SHA-256 of a Windows-sandbox
// detonation currently in progress, or "" if none is. run_pending.sh
// claims one request at a time by renaming {sha}.request to
// {sha}.request.running before it starts the guest (the same
// claim-before-work pattern honeypot-ghidra-worker.py uses), and the
// single-VM/flock design (run_pending.sh's own comment: "a second
// concurrent detonation would revert the snapshot out from under the
// first") means at most one such file can exist at a time.
var windowsRunningRequestRE = regexp.MustCompile(`^([a-f0-9]{64})\.request\.running$`)

func windowsSandboxLiveJob() string {
	dir := sandboxRequestDir(targetWindows)
	if dir == "" {
		return ""
	}
	entries, err := readDirNames(dir)
	if err != nil {
		return ""
	}
	for _, name := range entries {
		if m := windowsRunningRequestRE.FindStringSubmatch(name); m != nil {
			return m[1]
		}
	}
	return ""
}

// serveSandboxVNC (#805) serves the read-only live-view page: vendored
// noVNC's core, pointed at the operator-configured bridge WebSocket URL.
// The dashboard itself never touches libvirt or the VNC stream -- it only
// tells the browser where to connect, the same "dashboard writes/reads a
// narrow spool, a host-side worker holds the real access" split every
// other sandbox/Ghidra route in this file already follows. Gated the same
// way raw PCAP/diagnostics downloads are (requireAdmin): watching a live
// malware detonation is at least as sensitive as downloading its capture.
func (s *store) serveSandboxVNC(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
	if !requireAdmin(w, r) {
		return
	}
	bridgeWS := getenv("SANDBOX_VNC_BRIDGE_WS", "")
	if bridgeWS == "" {
		http.Error(w, "the VNC bridge is not configured on this host (SANDBOX_VNC_BRIDGE_WS unset)", http.StatusNotFound)
		return
	}
	sha := windowsSandboxLiveJob()
	if sha == "" {
		http.Error(w, "no Windows-sandbox detonation is currently running", http.StatusNotFound)
		return
	}
	data := sandboxVNCPageData{SHA256: sha, BridgeWS: bridgeWS}
	renderPage(w, tmpl, "sandbox-vnc", &data)
}

type sandboxVNCPageData struct {
	pageMeta
	SHA256   string
	BridgeWS string
}

func readDirNames(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, filepath.Base(m))
	}
	return names, nil
}
