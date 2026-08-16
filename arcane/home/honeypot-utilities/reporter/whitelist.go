package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// tunnelPeerIP is the WireGuard address of the VPS edge -- never a real
// attacker. #54: this exact address was once counted as an attacker source
// on the dashboard because a cowrie/dionaea/conpot event's IP recovery
// (joining back to the real source via portbridge's connection log) missed,
// leaving the tunnel peer's own address in the event instead of an empty
// field. This reporter does not attempt that recovery -- it has none of
// dashboard's portbridge-log-join machinery -- so an event whose IP is the
// tunnel peer is exactly the case that bug produced, and the only safe
// response is to never report it, not to guess.
const tunnelPeerIP = "10.8.0.1"

// whitelist decides whether an IP must never be reported: RFC1918/loopback/
// link-local by construction (never valid attacker addresses on the public
// internet), the tunnel peer specifically, plus whatever CIDRs/IPs an
// operator has added to the whitelist file (this stack's own public IPs,
// Tor exits they don't want reported, anything else).
type whitelist struct {
	prefixes []netip.Prefix
}

func loadWhitelist(path string) (*whitelist, error) {
	w := &whitelist{}
	if path == "" {
		return w, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return w, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		p, err := parseEntry(text)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		w.prefixes = append(w.prefixes, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return w, nil
}

// parseEntry accepts either a bare IP (treated as a /32 or /128) or a CIDR,
// matching the plan doc's "CIDR and single IP entries, one per line" format.
func parseEntry(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		return netip.ParsePrefix(text)
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// blocked reports whether ip must never be reported. Fails closed: an
// address that doesn't even parse is treated as blocked rather than passed
// through, and every check here is a reason to skip, never a reason to
// report -- there is no path in this function that can turn a "no" into a
// "yes".
func (w *whitelist) blocked(ip string) (bool, string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return true, "unparseable address"
	}
	addr = addr.Unmap()
	if addr.String() == tunnelPeerIP {
		return true, "tunnel peer, never an attacker (#54)"
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return true, "private/loopback/link-local"
	}
	for _, p := range w.prefixes {
		if p.Contains(addr) {
			return true, "operator whitelist: " + p.String()
		}
	}
	return false, ""
}
