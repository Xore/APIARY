package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type session struct {
	conn   *net.UDPConn
	mu     sync.RWMutex
	target *net.UDPAddr
}

func main() {
	listen := getenv("LISTEN_ADDR", ":1069")
	target, err := net.ResolveUDPAddr("udp4", getenv("TFTP_TARGET", "dionaea:69"))
	if err != nil {
		log.Fatal(err)
	}
	server, err := net.ListenUDP("udp4", mustAddr(listen))
	if err != nil {
		log.Fatal(err)
	}
	sessionLog := openSessionLog(getenv("SESSION_LOG", "/logs/sessions.json"))
	if sessionLog != nil {
		defer sessionLog.Close()
	}
	log.Printf("tftp relay %s -> %s", listen, target)
	var lock sync.Mutex
	sessions := map[string]*session{}
	buf := make([]byte, 65535)
	for {
		n, client, readErr := server.ReadFromUDP(buf)
		if readErr != nil {
			continue
		}
		key := client.String()
		lock.Lock()
		current := sessions[key]
		if current == nil {
			upstream, listenErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
			if listenErr != nil {
				lock.Unlock()
				continue
			}
			current = &session{conn: upstream, target: target}
			sessions[key] = current
			// #747: dionaea sees every TFTP session as coming from this
			// relay's own upstream socket, never the real client -- its
			// own connection log has no way to recover client.IP once the
			// packet leaves this process. Recording {relay_port, client_ip}
			// the moment that socket is opened (this port is exactly what
			// dionaea will log as src_port for the resulting session, per
			// TFTP's own "server replies from a fresh ephemeral port, but
			// the client's own port stays fixed for the session" contract)
			// lets ip-enrichment-worker join on it the same way it already
			// joins portbridge's via_port for every other affected sensor.
			logSession(sessionLog, upstream.LocalAddr().(*net.UDPAddr).Port, client.IP.String())
			go relayReplies(server, client, key, current, sessions, &lock)
		}
		lock.Unlock()
		current.mu.RLock()
		peer := current.target
		current.mu.RUnlock()
		current.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_, _ = current.conn.WriteToUDP(buf[:n], peer)
	}
}

func relayReplies(server *net.UDPConn, client *net.UDPAddr, key string, current *session, sessions map[string]*session, lock *sync.Mutex) {
	buf := make([]byte, 65535)
	for {
		n, peer, err := current.conn.ReadFromUDP(buf)
		if err != nil {
			lock.Lock()
			delete(sessions, key)
			lock.Unlock()
			_ = current.conn.Close()
			return
		}
		current.mu.Lock()
		current.target = peer
		current.mu.Unlock()
		_, _ = server.WriteToUDP(buf[:n], client)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func mustAddr(value string) *net.UDPAddr {
	address, err := net.ResolveUDPAddr("udp4", value)
	if err != nil {
		log.Fatal(err)
	}
	return address
}

// openSessionLog opens the session log for appending. Returns nil (not a
// fatal error) if the path can't be opened -- logging every real TFTP
// session's attribution is important but must never be why the relay
// itself refuses to start or stops forwarding traffic.
func openSessionLog(path string) *os.File {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("tftp relay: session log %s unavailable, continuing without it: %v", path, err)
		return nil
	}
	return f
}

func logSession(f *os.File, relayPort int, clientIP string) {
	if f == nil {
		return
	}
	line, err := json.Marshal(map[string]any{
		"relay_port": relayPort,
		"client_ip":  clientIP,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return
	}
	line = append(line, '\n')
	_, _ = f.Write(line)
}
