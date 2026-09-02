package main

import (
	"testing"
	"time"
)

func TestDNP3CRCReferenceVector(t *testing.T) {
	if got := crcDNP([]byte{0x05, 0x64, 0x05, 0xc0, 0x01, 0x00, 0x00, 0x04}); got != 0x21e9 {
		t.Fatalf("crc=%04x", got)
	}
}

func TestStatusResponseSwapsAddresses(t *testing.T) {
	r := statusResponse(1024, 4)
	if len(r) != 10 || r[4] != 0 || r[5] != 4 || r[6] != 4 || r[7] != 0 || r[3] != 0x8b {
		t.Fatalf("bad response: %x", r)
	}
}

// #610: link-layer-only frames (the majority of what this low-interaction
// honeypot's static reply actually provokes) have nothing past the 10-byte
// header to decode -- appFunctionCode must say so rather than reading past
// the slice or guessing.
func TestAppFunctionCodeAbsentOnLinkLayerOnlyFrame(t *testing.T) {
	linkOnly := []byte{0x05, 0x64, 0x05, 0xc0, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00}
	if name, ok := appFunctionCode(linkOnly); ok {
		t.Fatalf("expected no app function on a link-layer-only frame, got %q", name)
	}
}

// A frame with transport header + app control + a known function code
// (READ = 0x01) at offset 12 must decode by name.
func TestAppFunctionCodeDecodesKnownRequestCode(t *testing.T) {
	frame := []byte{
		0x05, 0x64, 0x0c, 0xc0, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, // link header (CRC bytes unchecked here)
		0xc1, // transport header (FIR/FIN/SEQ)
		0xc0, // application control
		0x01, // function code: READ
	}
	name, ok := appFunctionCode(frame)
	if !ok || name != "read" {
		t.Fatalf("appFunctionCode = %q, %v, want \"read\", true", name, ok)
	}
}

// OPERATE (0x04) is the function code an operator most needs to see --
// it's an attempted control-point write, not passive recon.
func TestAppFunctionCodeDecodesOperate(t *testing.T) {
	frame := []byte{
		0x05, 0x64, 0x0c, 0xc0, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00,
		0xc1, 0xc0, 0x04,
	}
	name, ok := appFunctionCode(frame)
	if !ok || name != "operate" {
		t.Fatalf("appFunctionCode = %q, %v, want \"operate\", true", name, ok)
	}
}

// An unrecognized function code still surfaces the raw value rather than
// being silently dropped -- same fallback shape as link_function_N.
func TestAppFunctionCodeFallsBackForUnknownCode(t *testing.T) {
	frame := []byte{
		0x05, 0x64, 0x0c, 0xc0, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00,
		0xc1, 0xc0, 0xfe,
	}
	name, ok := appFunctionCode(frame)
	if !ok || name != "app_function_254" {
		t.Fatalf("appFunctionCode = %q, %v, want \"app_function_254\", true", name, ok)
	}
}

// TestNextAcceptBackoffDoublesAndCaps covers #2328: repeated Accept()
// errors must back off instead of retrying unconditionally (which spins a
// CPU core at 100% under persistent fd exhaustion), and the backoff must
// not grow unbounded. Ported from endlessh-honeypot/main_test.go.
func TestNextAcceptBackoffDoublesAndCaps(t *testing.T) {
	d := time.Duration(0)
	d = nextAcceptBackoff(d)
	if d != 5*time.Millisecond {
		t.Fatalf("first backoff = %s, want 5ms", d)
	}
	d = nextAcceptBackoff(d)
	if d != 10*time.Millisecond {
		t.Fatalf("second backoff = %s, want 10ms", d)
	}
	for i := 0; i < 20; i++ {
		d = nextAcceptBackoff(d)
	}
	if d != maxAcceptBackoff {
		t.Fatalf("backoff after many failures = %s, want it capped at %s", d, maxAcceptBackoff)
	}
}
