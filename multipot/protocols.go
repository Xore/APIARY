package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// bumpDeadline gives a handler more time after each successful interaction so a
// chatty-but-slow attacker isn't cut off mid-session.
func bumpDeadline(c net.Conn) {
	c.SetDeadline(time.Now().Add(45 * time.Second))
}

func readLine(r *bufio.Reader) (string, bool) {
	line, err := r.ReadString('\n')
	if line == "" && err != nil {
		return "", false
	}
	return strings.TrimRight(line, "\r\n"), err == nil
}

/* ---------------- FTP (port 21) ----------------
   vsFTPd-style banner; capture USER/PASS, always "530 Login incorrect". */

func handleFTP(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufio.NewReader(c)
	fmt.Fprint(c, "220 (vsFTPd 3.0.5)\r\n")

	var user string
	for {
		line, ok := readLine(r)
		if line == "" && !ok {
			return
		}
		bumpDeadline(c)
		cmd, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(cmd) {
		case "USER":
			user = arg
			fmt.Fprint(c, "331 Please specify the password.\r\n")
		case "PASS":
			log.emit(event{Proto: "ftp", Port: port, SrcIP: ip, Event: "login",
				Username: user, Password: arg})
			fmt.Fprint(c, "530 Login incorrect.\r\n")
		case "QUIT":
			fmt.Fprint(c, "221 Goodbye.\r\n")
			return
		case "SYST":
			fmt.Fprint(c, "215 UNIX Type: L8\r\n")
		case "":
			return
		default:
			log.emit(event{Proto: "ftp", Port: port, SrcIP: ip, Event: "command", Command: line})
			fmt.Fprint(c, "530 Please login with USER and PASS.\r\n")
		}
	}
}

/* ---------------- SMTP (port 25) ----------------
   Postfix-style banner; capture AUTH LOGIN / AUTH PLAIN credentials. */

func handleSMTP(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufio.NewReader(c)
	fmt.Fprint(c, "220 mail01.nexusai.local ESMTP Postfix (Ubuntu)\r\n")

	for {
		line, ok := readLine(r)
		if line == "" && !ok {
			return
		}
		bumpDeadline(c)
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			fmt.Fprint(c, "250-mail01.nexusai.local\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n")
		case strings.HasPrefix(up, "AUTH LOGIN"):
			fmt.Fprint(c, "334 VXNlcm5hbWU6\r\n") // base64("Username:")
			userB64, _ := readLine(r)
			fmt.Fprint(c, "334 UGFzc3dvcmQ6\r\n") // base64("Password:")
			passB64, _ := readLine(r)
			log.emit(event{Proto: "smtp", Port: port, SrcIP: ip, Event: "login",
				Username: b64(userB64), Password: b64(passB64)})
			fmt.Fprint(c, "535 5.7.8 Error: authentication failed\r\n")
		case strings.HasPrefix(up, "AUTH PLAIN"):
			// Either "AUTH PLAIN <b64>" inline, or a follow-up line.
			payload := strings.TrimSpace(line[len("AUTH PLAIN"):])
			if payload == "" {
				fmt.Fprint(c, "334 \r\n")
				payload, _ = readLine(r)
			}
			u, p := decodeAuthPlain(payload)
			log.emit(event{Proto: "smtp", Port: port, SrcIP: ip, Event: "login",
				Username: u, Password: p})
			fmt.Fprint(c, "535 5.7.8 Error: authentication failed\r\n")
		case strings.HasPrefix(up, "MAIL FROM"), strings.HasPrefix(up, "RCPT TO"):
			log.emit(event{Proto: "smtp", Port: port, SrcIP: ip, Event: "envelope", Command: line})
			fmt.Fprint(c, "250 2.1.0 Ok\r\n")
		case strings.HasPrefix(up, "QUIT"):
			fmt.Fprint(c, "221 2.0.0 Bye\r\n")
			return
		default:
			fmt.Fprint(c, "250 2.0.0 Ok\r\n")
		}
	}
}

func b64(s string) string {
	if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s)); err == nil {
		return string(dec)
	}
	return s
}

// AUTH PLAIN payload decodes to "authzid\0authcid\0password".
func decodeAuthPlain(payload string) (user, pass string) {
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return payload, ""
	}
	parts := strings.Split(string(dec), "\x00")
	if len(parts) >= 3 {
		return parts[1], parts[2]
	}
	return string(dec), ""
}

/* ---------------- Redis (port 6379) ----------------
   Speaks enough RESP to capture AUTH passwords and the cron/SLAVEOF/MODULE
   payloads that Redis attacks drop. Answers +OK/+PONG to keep them talking. */

func handleRedis(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufio.NewReader(c)
	for {
		args, ok := readRESP(r)
		if !ok {
			return
		}
		if len(args) == 0 {
			continue
		}
		bumpDeadline(c)
		cmd := strings.ToUpper(args[0])
		full := strings.Join(args, " ")
		switch cmd {
		case "AUTH":
			pass := ""
			user := "default"
			if len(args) == 2 {
				pass = args[1]
			} else if len(args) >= 3 {
				user, pass = args[1], args[2]
			}
			log.emit(event{Proto: "redis", Port: port, SrcIP: ip, Event: "login",
				Username: user, Password: pass})
			fmt.Fprint(c, "+OK\r\n")
		case "PING":
			fmt.Fprint(c, "+PONG\r\n")
		case "INFO":
			log.emit(event{Proto: "redis", Port: port, SrcIP: ip, Event: "command", Command: cmd})
			body := "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 5.15.0-119-generic x86_64\r\n" +
				"process_id:1842\r\ntcp_port:6379\r\nconfig_file:/etc/redis/redis.conf\r\n" +
				"# Replication\r\nrole:master\r\nmaster_replid:02f63ec18c499e901f91d9cb3cbf29d345a18d78\r\n" +
				"# Clients\r\nconnected_clients:12\r\n# Keyspace\r\ndb0:keys=18443,expires=15221,avg_ttl=1874032\r\n"
			fmt.Fprintf(c, "$%d\r\n%s\r\n", len(body), body)
		case "DBSIZE":
			fmt.Fprint(c, ":18443\r\n")
		case "SELECT":
			fmt.Fprint(c, "+OK\r\n")
		case "KEYS":
			// Look like a portal cache holding sessions / rate-limit / order data.
			writeRESPArray(c, []string{
				"sess:9f2a7c4e1b8d6035", "sess:3b4f8e02d6c5a1b9",
				"cache:orders:recent", "cache:catalog:v3",
				"rate:ip:203.0.113.88", "queue:email:pending",
			})
		case "TYPE":
			fmt.Fprint(c, "+string\r\n")
		case "TTL":
			fmt.Fprint(c, ":3600\r\n")
		case "CONFIG":
			// CONFIG GET <param> — answer plausibly; CONFIG SET falls to default.
			if len(args) >= 3 && strings.EqualFold(args[1], "GET") {
				val := map[string]string{
					"dir": "/var/lib/redis", "maxmemory": "536870912",
					"maxmemory-policy": "allkeys-lru", "save": "3600 1 300 100",
				}[strings.ToLower(args[2])]
				log.emit(event{Proto: "redis", Port: port, SrcIP: ip, Event: "command", Command: full})
				writeRESPArray(c, []string{args[2], val})
			} else {
				log.emit(event{Proto: "redis", Port: port, SrcIP: ip, Event: "command", Command: full})
				fmt.Fprint(c, "+OK\r\n")
			}
		case "GET":
			fmt.Fprint(c, "$-1\r\n") // key miss — realistic and harmless
		case "QUIT":
			fmt.Fprint(c, "+OK\r\n")
			return
		default:
			// CONFIG SET, SET, SLAVEOF, MODULE LOAD, etc. — the interesting stuff.
			log.emit(event{Proto: "redis", Port: port, SrcIP: ip, Event: "command", Command: full})
			fmt.Fprint(c, "+OK\r\n")
		}
	}
}

// writeRESPArray sends a RESP array of bulk strings (nil entries -> $-1).
func writeRESPArray(c net.Conn, items []string) {
	fmt.Fprintf(c, "*%d\r\n", len(items))
	for _, it := range items {
		if it == "" {
			fmt.Fprint(c, "$-1\r\n")
			continue
		}
		fmt.Fprintf(c, "$%d\r\n%s\r\n", len(it), it)
	}
}

// readRESP parses one command: either a RESP array (*N ...) or an inline line.
func readRESP(r *bufio.Reader) ([]string, bool) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, false
	}
	if prefix != '*' {
		// Inline command: read the rest of the line.
		rest, ok := readLine(r)
		if !ok && rest == "" {
			return nil, false
		}
		line := strings.TrimSpace(string(prefix) + rest)
		if line == "" {
			return []string{}, true
		}
		return strings.Fields(line), true
	}
	countLine, ok := readLine(r)
	if !ok && countLine == "" {
		return nil, false
	}
	n := atoiSafe(countLine)
	if n <= 0 || n > 1024 {
		return []string{}, true
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if _, err := r.ReadByte(); err != nil { // '$'
			return out, len(out) > 0
		}
		lenLine, _ := readLine(r)
		blen := atoiSafe(lenLine)
		if blen < 0 || blen > 1<<20 {
			return out, true
		}
		buf := make([]byte, blen)
		if _, err := readFull(r, buf); err != nil {
			return out, len(out) > 0
		}
		readLine(r) // trailing CRLF
		out = append(out, string(buf))
	}
	return out, true
}

/* ---------------- MySQL (port 3306) ----------------
   Send a v10 server greeting, read the login packet, capture the username,
   answer with "Access denied". Password arrives hashed, so it is not logged. */

func handleMySQL(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	c.Write(buildMySQLGreeting())

	// Client login request packet: 4-byte header then payload; username is a
	// NUL-terminated string starting at payload offset 32. Read straight from
	// the conn (no bufio) so byte offsets stay exact.
	header := make([]byte, 4)
	if _, err := readFull(c, header); err != nil {
		return
	}
	plen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if plen <= 0 || plen > 1<<16 {
		return
	}
	payload := make([]byte, plen)
	if _, err := readFull(c, payload); err != nil {
		return
	}
	user := ""
	if len(payload) > 32 {
		if i := indexByte(payload[32:], 0); i >= 0 {
			user = string(payload[32 : 32+i])
		}
	}
	log.emit(event{Proto: "mysql", Port: port, SrcIP: ip, Event: "login", Username: user})

	// ERR packet (seq 2): 0xff, code 1045, '#', SQLSTATE, message.
	msg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: YES)", user, ip)
	body := []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}
	body = append(body, []byte(msg)...)
	c.Write(append(mysqlHeader(len(body), 2), body...))
}

func buildMySQLGreeting() []byte {
	var b []byte
	b = append(b, 10) // protocol version
	b = append(b, []byte("8.0.36")...)
	b = append(b, 0)
	b = append(b, 0x0b, 0, 0, 0)             // thread id
	b = append(b, []byte("abcdefgh")...)     // auth-plugin-data part 1
	b = append(b, 0)                         // filler
	b = append(b, 0xff, 0xf7)                // capability flags (low)
	b = append(b, 0x21)                      // charset utf8
	b = append(b, 0x02, 0x00)                // status flags
	b = append(b, 0xff, 0x81)                // capability flags (high)
	b = append(b, 21)                        // auth plugin data len
	b = append(b, make([]byte, 10)...)       // reserved
	b = append(b, []byte("ijklmnopqrst")...) // auth-plugin-data part 2 (12) ...
	b = append(b, 0)                         // ... NUL-terminated (13)
	b = append(b, []byte("mysql_native_password")...)
	b = append(b, 0)
	return append(mysqlHeader(len(b), 0), b...)
}

func mysqlHeader(n, seq int) []byte {
	return []byte{byte(n), byte(n >> 8), byte(n >> 16), byte(seq)}
}

/* ---------------- PostgreSQL (port 5432) ----------------
   Read the startup message (captures the user), request a cleartext password,
   capture it, then return an auth-failed error. */

func handlePostgres(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufioReader(c)

	// StartupMessage: Int32 len, Int32 protocol, then key\0value\0...\0
	lenBuf := make([]byte, 4)
	if _, err := readFull(r, lenBuf); err != nil {
		return
	}
	msgLen := int(binary.BigEndian.Uint32(lenBuf))
	if msgLen < 8 || msgLen > 1<<16 {
		return
	}
	body := make([]byte, msgLen-4)
	if _, err := readFull(r, body); err != nil {
		return
	}
	params := parsePGParams(body[4:]) // skip the 4-byte protocol version
	user := params["user"]

	// AuthenticationCleartextPassword: 'R' Int32(8) Int32(3)
	c.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})

	// PasswordMessage: 'p' Int32(len) password\0
	tag := make([]byte, 1)
	if _, err := readFull(r, tag); err == nil && tag[0] == 'p' {
		pl := make([]byte, 4)
		if _, err := readFull(r, pl); err == nil {
			n := int(binary.BigEndian.Uint32(pl)) - 4
			if n > 0 && n < 1024 {
				pw := make([]byte, n)
				readFull(r, pw)
				log.emit(event{Proto: "postgres", Port: port, SrcIP: ip, Event: "login",
					Username: user, Password: strings.TrimRight(string(pw), "\x00")})
			}
		}
	} else {
		log.emit(event{Proto: "postgres", Port: port, SrcIP: ip, Event: "login", Username: user})
	}

	// ErrorResponse
	writePGError(c, user, ip)
}

func parsePGParams(b []byte) map[string]string {
	out := map[string]string{}
	parts := strings.Split(string(b), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "" {
			break
		}
		out[parts[i]] = parts[i+1]
	}
	return out
}

func writePGError(c net.Conn, user, ip string) {
	msg := fmt.Sprintf("password authentication failed for user \"%s\"", user)
	fields := "SFATAL\x00C28P01\x00M" + msg + "\x00\x00"
	payload := append([]byte{}, []byte(fields)...)
	buf := make([]byte, 5)
	buf[0] = 'E'
	binary.BigEndian.PutUint32(buf[1:], uint32(len(payload)+4))
	c.Write(append(buf, payload...))
}

/* ---------------- VNC (port 5900) ----------------
   Exchange RFB versions, offer VNC auth, capture the challenge response. */

func handleVNC(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufioReader(c)
	c.Write([]byte("RFB 003.008\n"))

	clientVer := make([]byte, 12)
	if _, err := readFull(r, clientVer); err != nil {
		return
	}
	log.emit(event{Proto: "vnc", Port: port, SrcIP: ip, Event: "handshake",
		Client: strings.TrimSpace(string(clientVer))})

	// Offer exactly one security type: 2 (VNC authentication).
	c.Write([]byte{1, 2})
	sel := make([]byte, 1)
	if _, err := readFull(r, sel); err != nil {
		return
	}
	// Real VNC servers generate a fresh challenge for every connection.
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return
	}
	c.Write(challenge)
	resp := make([]byte, 16)
	if _, err := readFull(r, resp); err == nil {
		log.emit(event{Proto: "vnc", Port: port, SrcIP: ip, Event: "auth_attempt",
			Data: fmt.Sprintf("%x", resp)})
	}
	// SecurityResult = failed (1)
	c.Write([]byte{0, 0, 0, 1})
}

/* ---------------- Elasticsearch (port 9200) ----------------
   Minimal HTTP: log the request line, return a believable ES root document. */

func handleElastic(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufioReader(c)
	reqLine, _ := readLine(r)
	// Drain headers.
	for {
		h, ok := readLine(r)
		if h == "" || !ok {
			break
		}
	}
	log.emit(event{Proto: "elasticsearch", Port: port, SrcIP: ip, Event: "http_request", Command: reqLine})

	body := `{
  "name" : "es-logs-01",
  "cluster_name" : "nexusai-logging-prod",
  "cluster_uuid" : "V1dQfSe2QByOMRPYk1gS3A",
  "version" : {
    "number" : "7.17.9",
    "build_flavor" : "default",
    "lucene_version" : "8.11.1"
  },
  "tagline" : "You Know, for Search"
}`
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

/* ---------------- Docker Engine API (port 2375) ----------------
   A deliberately unauthenticated build node. It exposes plausible read-only
   inventory and records mutation attempts without ever executing them. */

func handleDocker(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufioReader(c)
	reqLine, _ := readLine(r)
	for {
		h, ok := readLine(r)
		if h == "" || !ok {
			break
		}
	}
	log.emit(event{Proto: "docker", Port: port, SrcIP: ip, Event: "http_request", Command: reqLine})
	parts := strings.Fields(reqLine)
	path := "/"
	if len(parts) > 1 {
		path = parts[1]
	}
	body := `{"message":"page not found"}`
	status := "404 Not Found"
	switch {
	case path == "/version":
		status = "200 OK"
		body = `{"Platform":{"Name":"Docker Engine - Community"},"Version":"25.0.5","ApiVersion":"1.44","MinAPIVersion":"1.24","GitCommit":"5dc9bcc","GoVersion":"go1.21.8","Os":"linux","Arch":"amd64","KernelVersion":"5.15.0-119-generic","Name":"build01"}`
	case path == "/info":
		status = "200 OK"
		body = `{"ID":"NEXUSAI-BUILD01","Containers":7,"ContainersRunning":4,"ContainersPaused":0,"ContainersStopped":3,"Images":23,"Driver":"overlay2","Name":"build01","OperatingSystem":"Ubuntu 22.04.4 LTS","Architecture":"x86_64","NCPU":16,"MemTotal":67373383680}`
	case strings.HasSuffix(path, "/containers/json"):
		status = "200 OK"
		body = `[{"Id":"4a6f9b2d71ce","Names":["/gitlab-runner"],"Image":"gitlab/gitlab-runner:alpine-v17.1.0","State":"running","Status":"Up 12 days"},{"Id":"92de51c71fa8","Names":["/registry-cache"],"Image":"registry:2.8.3","State":"running","Status":"Up 12 days"}]`
	}
	fmt.Fprintf(c, "HTTP/1.1 %s\r\nApi-Version: 1.44\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: Docker/25.0.5 (linux)\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body)
}

/* ---------------- Generic (raw byte logger) ----------------
   For protocols we don't emulate (MSSQL/TDS, MongoDB wire, Docker API): read
   what the client sends and log a printable + hex preview. */

func handleGeneric(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _ := c.Read(buf)
	if n > 0 {
		data := buf[:n]
		log.emit(event{Proto: protoForPort(port), Port: port, SrcIP: ip, Event: "data",
			Bytes: n, Data: printable(data)})
	}
}

func protoForPort(port int) string {
	switch port {
	case 1433:
		return "mssql"
	case 27017:
		return "mongodb"
	case 2375:
		return "docker"
	default:
		return "tcp"
	}
}

/* ---------------- small helpers ---------------- */

func printable(b []byte) string {
	var sb strings.Builder
	for _, ch := range b {
		if ch >= 0x20 && ch < 0x7f {
			sb.WriteByte(ch)
		} else {
			sb.WriteByte('.')
		}
	}
	s := sb.String()
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

func atoiSafe(s string) int {
	n := 0
	neg := false
	s = strings.TrimSpace(s)
	for i, ch := range s {
		if i == 0 && ch == '-' {
			neg = true
			continue
		}
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	if neg {
		return -n
	}
	return n
}

func indexByte(b []byte, target byte) int {
	for i, ch := range b {
		if ch == target {
			return i
		}
	}
	return -1
}

func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// bufioReader wraps a conn once per call site; fine for our short handlers.
func bufioReader(c net.Conn) *bufio.Reader {
	return bufio.NewReader(c)
}

/* ---------------- POP3 (port 110) ----------------
   #238: ported from heralding's pop3.py -- a textbook line-based command
   loop (USER/PASS/QUIT), structurally identical to handleFTP above. Always
   rejects auth, logs the attempt. */

func handlePOP3(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufio.NewReader(c)
	fmt.Fprint(c, "+OK POP3 server ready\r\n")

	var user string
	for {
		line, ok := readLine(r)
		if line == "" && !ok {
			return
		}
		bumpDeadline(c)
		cmd, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(cmd) {
		case "USER":
			user = arg
			fmt.Fprint(c, "+OK\r\n")
		case "PASS":
			log.emit(event{Proto: "pop3", Port: port, SrcIP: ip, Event: "login",
				Username: user, Password: arg})
			fmt.Fprint(c, "-ERR authentication failed\r\n")
		case "QUIT":
			fmt.Fprint(c, "+OK Goodbye\r\n")
			return
		case "":
			return
		default:
			log.emit(event{Proto: "pop3", Port: port, SrcIP: ip, Event: "command", Command: line})
			fmt.Fprint(c, "-ERR unknown command\r\n")
		}
	}
}

/* ---------------- IMAP (port 143) ----------------
   #238: ported from heralding's imap.py -- same shape as POP3 above, but
   IMAP's tagged-command convention means every response must echo back the
   client's own tag rather than a fixed prefix. Always rejects LOGIN, logs
   the attempt. */

func handleIMAP(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufio.NewReader(c)
	fmt.Fprint(c, "* OK IMAP4rev1 Service Ready\r\n")

	for {
		line, ok := readLine(r)
		if line == "" && !ok {
			return
		}
		bumpDeadline(c)
		tag, rest, _ := strings.Cut(line, " ")
		if tag == "" {
			return
		}
		cmd, arg, _ := strings.Cut(rest, " ")
		switch strings.ToUpper(cmd) {
		case "CAPABILITY":
			fmt.Fprint(c, "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
			fmt.Fprintf(c, "%s OK CAPABILITY completed\r\n", tag)
		case "LOGIN":
			// arg is `"user" "pass"` or `user pass`, quoted or not -- either
			// way the two space-separated tokens are what's worth logging,
			// not a fully RFC 3501 quoted-string parse.
			user, pass, _ := strings.Cut(arg, " ")
			log.emit(event{Proto: "imap", Port: port, SrcIP: ip, Event: "login",
				Username: strings.Trim(user, `"`), Password: strings.Trim(pass, `"`)})
			fmt.Fprintf(c, "%s NO LOGIN failed\r\n", tag)
		case "LOGOUT":
			fmt.Fprint(c, "* BYE IMAP4rev1 Server logging out\r\n")
			fmt.Fprintf(c, "%s OK LOGOUT completed\r\n", tag)
			return
		case "":
			fmt.Fprintf(c, "%s BAD command unrecognized\r\n", tag)
		default:
			log.emit(event{Proto: "imap", Port: port, SrcIP: ip, Event: "command", Command: line})
			fmt.Fprintf(c, "%s BAD command unrecognized\r\n", tag)
		}
	}
}

/* ---------------- SOCKS5 (port 1080) ----------------
   #238: ported from heralding's socks5.py -- RFC 1928's handshake (version +
   method negotiation, always advertise "no auth required" to keep the
   client talking) followed by the connect request, whose target
   host:port is exactly what's worth logging (proxy-abuse scanning wants to
   know what the attacker meant to reach through us). The connect always
   fails: this is a sensor, never an actual proxy. */

func handleSOCKS5(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufio.NewReader(c)
	bumpDeadline(c)

	header := make([]byte, 2)
	if _, err := readFull(r, header); err != nil || header[0] != 0x05 {
		return
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := readFull(r, methods); err != nil {
		return
	}
	log.emit(event{Proto: "socks5", Port: port, SrcIP: ip, Event: "handshake",
		Data: fmt.Sprintf("%d methods offered", nmethods)})
	// Version 5, method 0x00 (no authentication required).
	c.Write([]byte{0x05, 0x00})

	req := make([]byte, 4)
	if _, err := readFull(r, req); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		return
	}
	var target string
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := readFull(r, addr); err != nil {
			return
		}
		target = net.IP(addr).String()
	case 0x03: // domain name
		lenByte := make([]byte, 1)
		if _, err := readFull(r, lenByte); err != nil {
			return
		}
		name := make([]byte, lenByte[0])
		if _, err := readFull(r, name); err != nil {
			return
		}
		target = string(name)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := readFull(r, addr); err != nil {
			return
		}
		target = net.IP(addr).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := readFull(r, portBytes); err != nil {
		return
	}
	targetPort := int(portBytes[0])<<8 | int(portBytes[1])
	log.emit(event{Proto: "socks5", Port: port, SrcIP: ip, Event: "connect_request",
		Data: fmt.Sprintf("%s:%d", target, targetPort)})
	// Reply code 5 = connection refused -- never actually proxy anything.
	c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

/* ---------------- ADB (port 5555) ----------------
   #238: ported from ADBHoney. The wire framing itself is simple (a fixed
   24-byte header + payload, six command constants) -- the real breadth is
   the CNXN handshake and OPEN/WRTE/CLSE stream lifecycle. Always completes
   the handshake unauthenticated, matching exactly what ADB.miner/
   Satori-style scanning targets: a device with debugging enabled and no
   authorization required. Logs the client's identity banner and whatever
   destination string / write payload it sends (that's where an attempted
   command shows up, e.g. "shell:cat /proc/cpuinfo"), but never executes
   anything -- there is no real shell behind this, only CLSE. */

const (
	adbCNXN = 0x4e584e43
	adbOPEN = 0x4e45504f
	adbOKAY = 0x59414b4f
	adbCLSE = 0x45534c43
	adbWRTE = 0x45545257
)

type adbMessage struct {
	Command uint32
	Arg0    uint32
	Arg1    uint32
	Data    []byte
}

func readADBMessage(r io.Reader) (adbMessage, error) {
	header := make([]byte, 24)
	if _, err := readFull(r, header); err != nil {
		return adbMessage{}, err
	}
	m := adbMessage{
		Command: binary.LittleEndian.Uint32(header[0:4]),
		Arg0:    binary.LittleEndian.Uint32(header[4:8]),
		Arg1:    binary.LittleEndian.Uint32(header[8:12]),
	}
	dataLen := binary.LittleEndian.Uint32(header[12:16])
	// A real ADB payload is a short shell command or sync path, never
	// anywhere close to this -- reject rather than allocate on a bogus or
	// hostile length field.
	if dataLen > 0 {
		if dataLen > 64*1024 {
			return adbMessage{}, fmt.Errorf("adb payload too large: %d", dataLen)
		}
		m.Data = make([]byte, dataLen)
		if _, err := readFull(r, m.Data); err != nil {
			return adbMessage{}, err
		}
	}
	return m, nil
}

func adbChecksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}

func writeADBMessage(w io.Writer, command, arg0, arg1 uint32, data []byte) {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], command)
	binary.LittleEndian.PutUint32(header[4:8], arg0)
	binary.LittleEndian.PutUint32(header[8:12], arg1)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(data)))
	binary.LittleEndian.PutUint32(header[16:20], adbChecksum(data))
	binary.LittleEndian.PutUint32(header[20:24], command^0xffffffff)
	w.Write(header)
	if len(data) > 0 {
		w.Write(data)
	}
}

func handleADB(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	r := bufioReader(c)
	bumpDeadline(c)

	msg, err := readADBMessage(r)
	if err != nil || msg.Command != adbCNXN {
		return
	}
	identity := strings.TrimRight(string(msg.Data), "\x00")
	log.emit(event{Proto: "adb", Port: port, SrcIP: ip, Event: "handshake", Client: identity})

	banner := []byte("device::ro.product.name=generic;ro.product.model=SM-G960F;ro.product.device=starlte;")
	writeADBMessage(c, adbCNXN, 0x01000000, 4096, banner)

	for {
		bumpDeadline(c)
		msg, err = readADBMessage(r)
		if err != nil {
			return
		}
		switch msg.Command {
		case adbOPEN:
			dest := strings.TrimRight(string(msg.Data), "\x00")
			log.emit(event{Proto: "adb", Port: port, SrcIP: ip, Event: "open", Command: dest})
			// Accept, then close immediately -- there is no real shell
			// behind this stream to write output from.
			writeADBMessage(c, adbOKAY, 1, msg.Arg0, nil)
			writeADBMessage(c, adbCLSE, 1, msg.Arg0, nil)
		case adbWRTE:
			log.emit(event{Proto: "adb", Port: port, SrcIP: ip, Event: "write", Data: string(msg.Data)})
			writeADBMessage(c, adbOKAY, msg.Arg1, msg.Arg0, nil)
		case adbCLSE:
			return
		}
		// AUTH, SYNC, and anything else: neither logged in detail nor
		// replied to -- CNXN/OPEN/WRTE are what carry attacker-controlled
		// content worth capturing.
	}
}

/* ---------------- HL7 / MLLP (port 2575) ----------------
   #238: ported from medpot -- its entire "HL7 protocol handling" is exactly
   this substring check (strings.Contains(buf, "MSH") &&
   strings.Index(buf,"MSH|")==0 in the original), no real MLLP framing or
   segment parsing. Logs the message segment and answers with a minimal
   MLLP-framed ACK (0x0B start, 0x1C 0x0D end) so a real HL7 client sees a
   plausibly-shaped response rather than a naked disconnect. */

func handleHL7(c net.Conn, log *logger, port int) {
	ip := srcIP(c)
	buf := make([]byte, 8192)
	bumpDeadline(c)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		return
	}
	msg := string(buf[:n])
	// Strip MLLP framing bytes (0x0B start, 0x1C 0x0D end) if present --
	// real HL7 clients wrap messages in them, but the segment check below
	// only cares about the content between them.
	msg = strings.Trim(msg, "\x0b\x1c\r\n")
	if !strings.HasPrefix(msg, "MSH|") {
		return
	}
	log.emit(event{Proto: "hl7", Port: port, SrcIP: ip, Event: "message", Data: msg})
	ack := "MSH|^~\\&|MULTIPOT|NEXUSAI|||20260101000000||ACK||P|2.3\rMSA|AA\r"
	fmt.Fprintf(c, "\x0b%s\x1c\r", ack)
}
