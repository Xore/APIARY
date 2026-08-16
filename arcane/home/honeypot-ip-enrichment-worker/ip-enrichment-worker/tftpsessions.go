package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

// buildTftpSessionMap reads tftp-relay's own session log (#747) -- a
// {relay_port, client_ip} line per TFTP session, written the moment the
// relay opens its upstream socket to dionaea. That local port is exactly
// the src_port dionaea's own connection log will show for the resulting
// session (TFTP's own contract: the server replies from a fresh ephemeral
// port, but the client's port stays fixed for the session -- here, "client"
// from dionaea's point of view is this relay's upstream socket, confirmed
// live against a real probe). Same "read the whole file every refresh
// tick" simplicity as buildViaMap; TFTP session volume is low enough that
// this doesn't need portbridge's rotation-aware two-generation read.
func buildTftpSessionMap(logsDir string) viaMap {
	m := viaMap{}
	f, err := os.Open(filepath.Join(logsDir, "tftp-relay", "sessions.json"))
	if err != nil {
		return m
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e map[string]any
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		ip, _ := e["client_ip"].(string)
		if ip == "" {
			continue
		}
		port, ok := e["relay_port"].(float64)
		if !ok || port == 0 {
			continue
		}
		m[int(port)] = ip
	}
	return m
}

// isTftpRelayRecord reports whether e is one of dionaea's TFTP connection
// events, relayed through tftp-relay (#747). These carry the relay
// container's own internal address as src_ip, never the tunnel peer IP --
// TFTP reaches dionaea over a plain UDP forward, not the WireGuard/
// portbridge tunnel every other affected sensor goes through -- so they
// need a different trigger than the tunnelPeerIP check in enrichLine, and a
// different port-to-real-IP map (tftpSessionMap, joined against
// tftp-relay's own session log instead of portbridge's).
func isTftpRelayRecord(e map[string]any, persona string) bool {
	if persona != "dionaea" {
		return false
	}
	conn, ok := e["connection"].(map[string]any)
	if !ok {
		return false
	}
	proto, _ := conn["protocol"].(string)
	return proto == "TftpServerHandler"
}
