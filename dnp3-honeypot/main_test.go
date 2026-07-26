package main

import "testing"

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
