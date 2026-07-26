package main

import (
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
