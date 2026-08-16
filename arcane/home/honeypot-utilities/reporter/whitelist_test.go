package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWhitelistBlocksTunnelPeer(t *testing.T) {
	wl, err := loadWhitelist("")
	if err != nil {
		t.Fatal(err)
	}
	// #54: this exact address was once misattributed as an attacker. It
	// must never pass through this reporter regardless of whitelist config.
	blocked, reason := wl.blocked(tunnelPeerIP)
	if !blocked {
		t.Fatalf("tunnel peer %s was not blocked", tunnelPeerIP)
	}
	if reason == "" {
		t.Fatal("blocked with no reason recorded")
	}
}

func TestWhitelistBlocksPrivateLoopbackLinkLocal(t *testing.T) {
	wl, err := loadWhitelist("")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.1.2.3", "192.168.1.1", "172.16.0.5", "127.0.0.1", "169.254.1.1", "::1", "fe80::1"} {
		if blocked, _ := wl.blocked(ip); !blocked {
			t.Errorf("%s should be blocked (private/loopback/link-local)", ip)
		}
	}
}

func TestWhitelistBlocksUnparseableAddressFailClosed(t *testing.T) {
	wl, err := loadWhitelist("")
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := wl.blocked("not-an-ip"); !blocked {
		t.Fatal("unparseable address must fail closed (blocked), not pass through")
	}
}

func TestWhitelistAllowsARealPublicIP(t *testing.T) {
	wl, err := loadWhitelist("")
	if err != nil {
		t.Fatal(err)
	}
	if blocked, reason := wl.blocked("203.0.113.7"); blocked {
		t.Fatalf("a real public IP (TEST-NET-3) was blocked: %s", reason)
	}
}

func TestWhitelistFileCIDRAndBareIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	if err := os.WriteFile(path, []byte("# comment\n\n203.0.113.0/24\n198.51.100.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wl, err := loadWhitelist(path)
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := wl.blocked("203.0.113.99"); !blocked {
		t.Fatal("IP inside the whitelisted CIDR was not blocked")
	}
	if blocked, _ := wl.blocked("198.51.100.7"); !blocked {
		t.Fatal("bare whitelisted IP was not blocked")
	}
	if blocked, _ := wl.blocked("198.51.100.8"); blocked {
		t.Fatal("a neighboring, non-whitelisted IP was blocked")
	}
}

func TestWhitelistRejectsGarbageEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.txt")
	if err := os.WriteFile(path, []byte("not-an-ip-or-cidr\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWhitelist(path); err == nil {
		t.Fatal("want an error for a malformed whitelist entry, got nil")
	}
}
