package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestDHPrimeIsRFC3526Group14(t *testing.T) {
	if bl := dhGroup14Prime.BitLen(); bl != 2048 {
		t.Fatalf("bit length = %d, want 2048", bl)
	}
	if !dhGroup14Prime.ProbablyPrime(20) {
		t.Fatal("dhGroup14Prime is not prime")
	}
}

func TestDHKeyExchangeAgreesOnSharedSecret(t *testing.T) {
	a, err := newDHKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newDHKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sa := a.sharedSecret(b.public)
	sb := b.sharedSecret(a.public)
	if sa.Cmp(sb) != 0 {
		t.Fatal("both sides derived different shared secrets")
	}
}

func TestToBytesIsMinimalBigEndianNotZeroPadded(t *testing.T) {
	// 0x01 should encode as a single byte, not padded to any fixed width --
	// matching Python's math.ceil(x.bit_length()/8) behavior exactly.
	got := toBytes(big.NewInt(1))
	if !bytes.Equal(got, []byte{0x01}) {
		t.Fatalf("toBytes(1) = %x, want 01", got)
	}
	got = toBytes(big.NewInt(0x0100))
	if !bytes.Equal(got, []byte{0x01, 0x00}) {
		t.Fatalf("toBytes(256) = %x, want 0100", got)
	}
}

// TestPRFKnownAnswer checks HMAC-SHA256 behaves as prf() expects using a
// standard RFC 4231 HMAC-SHA-256 test vector (test case 1), since prf() is
// nothing more than a thin wrapper -- this pins that wrapper's key/data
// argument order against a citable external reference rather than only
// re-deriving the same computation another way.
func TestPRFKnownAnswer(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	data := []byte("Hi There")
	want := mustHexBytes(t, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	got := prf(key, data)
	if !bytes.Equal(got, want) {
		t.Fatalf("prf() = %x, want %x", got, want)
	}
}

func TestPRFPlusProducesRequestedLengthAndIsDeterministic(t *testing.T) {
	key := []byte("key")
	data := []byte("data")
	out1 := prfPlus(key, data, 100)
	out2 := prfPlus(key, data, 100)
	if len(out1) != 100 {
		t.Fatalf("len = %d, want 100", len(out1))
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("prfPlus is not deterministic for the same inputs")
	}
	// A shorter request for the same key/data must be a strict prefix of
	// the longer one -- prfPlus is a stream construction.
	short := prfPlus(key, data, 32)
	if !bytes.Equal(short, out1[:32]) {
		t.Fatal("prfPlus(n=32) is not a prefix of prfPlus(n=100)")
	}
}

func TestIKEHeaderFieldOffsetsMatchRFC7296(t *testing.T) {
	h := ikeHeader(0x1122334455667788, 0xaabbccddeeff0011, payloadSA, exchangeInit, flagInitiator, 7, 1234)
	if len(h) != 28 {
		t.Fatalf("header length = %d, want 28", len(h))
	}
	if got := binary.BigEndian.Uint64(h[0:8]); got != 0x1122334455667788 {
		t.Fatalf("iSPI = %x", got)
	}
	if got := binary.BigEndian.Uint64(h[8:16]); got != 0xaabbccddeeff0011 {
		t.Fatalf("rSPI = %x", got)
	}
	if h[16] != payloadSA {
		t.Fatalf("next payload = %d, want %d", h[16], payloadSA)
	}
	if h[17] != ikeVersion {
		t.Fatalf("version = %x, want %x", h[17], ikeVersion)
	}
	if h[18] != exchangeInit {
		t.Fatalf("exchange type = %d, want %d", h[18], exchangeInit)
	}
	if h[19] != flagInitiator {
		t.Fatalf("flags = %x, want %x", h[19], flagInitiator)
	}
	if got := binary.BigEndian.Uint32(h[20:24]); got != 7 {
		t.Fatalf("message id = %d, want 7", got)
	}
	if got := binary.BigEndian.Uint32(h[24:28]); got != 1234 {
		t.Fatalf("length = %d, want 1234", got)
	}
}

func TestDefaultSAPayloadHasTwoProposalsIKEThenESP(t *testing.T) {
	sa := defaultSAPayload(payloadKE, 0x0102030405060708, 0xaabbccdd)
	// Payload header.
	length := binary.BigEndian.Uint16(sa[2:4])
	if int(length) != len(sa) {
		t.Fatalf("SA payload header length %d != actual %d", length, len(sa))
	}
	body := sa[payloadHeaderLen:]

	// First proposal: IKE, 8-byte SPI, 4 transforms, marked non-last (2).
	if body[0] != 2 {
		t.Fatalf("proposal 1 last-marker = %d, want 2 (more proposals follow)", body[0])
	}
	num, protocolID, spiLen, numTransforms := body[4], body[5], body[6], body[7]
	if num != 1 || protocolID != protocolIKE || spiLen != 8 || numTransforms != 4 {
		t.Fatalf("proposal 1 header = num=%d proto=%d spiLen=%d transforms=%d", num, protocolID, spiLen, numTransforms)
	}
	gotSPI := binary.BigEndian.Uint64(body[8:16])
	if gotSPI != 0x0102030405060708 {
		t.Fatalf("proposal 1 SPI = %x, want 0102030405060708", gotSPI)
	}
	proposal1Len := binary.BigEndian.Uint16(body[2:4])

	// Second proposal starts right after the first.
	body2 := body[proposal1Len:]
	if body2[0] != 0 {
		t.Fatalf("proposal 2 last-marker = %d, want 0 (final proposal)", body2[0])
	}
	num2, protocolID2, spiLen2, numTransforms2 := body2[4], body2[5], body2[6], body2[7]
	if num2 != 2 || protocolID2 != protocolESP || spiLen2 != 4 || numTransforms2 != 3 {
		t.Fatalf("proposal 2 header = num=%d proto=%d spiLen=%d transforms=%d", num2, protocolID2, spiLen2, numTransforms2)
	}
	gotESPSPI := binary.BigEndian.Uint32(body2[8:12])
	if gotESPSPI != 0xaabbccdd {
		t.Fatalf("proposal 2 SPI = %x, want aabbccdd", gotESPSPI)
	}
}

func TestKEPayloadCarriesGroup14AndPublicKeyBytes(t *testing.T) {
	kp, err := newDHKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ke := kePayload(payloadNonce, kp.public)
	length := binary.BigEndian.Uint16(ke[2:4])
	if int(length) != len(ke) {
		t.Fatalf("KE payload length header %d != actual %d", length, len(ke))
	}
	group := binary.BigEndian.Uint16(ke[4:6])
	if group != dhGroup14ID {
		t.Fatalf("group = %d, want %d", group, dhGroup14ID)
	}
	kexData := ke[8:]
	if !bytes.Equal(kexData, toBytes(kp.public)) {
		t.Fatal("KE payload kex_data doesn't match the key pair's public value")
	}
}

func TestNoncePayloadRoundTrips(t *testing.T) {
	nonce, err := randomNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 {
		t.Fatalf("nonce length = %d, want 32", len(nonce))
	}
	p := noncePayload(payloadNone, nonce)
	if !bytes.Equal(p[payloadHeaderLen:], nonce) {
		t.Fatal("nonce payload body doesn't match the generated nonce")
	}
}

func TestBuildBogusInitReplyIsWellFormed(t *testing.T) {
	packet, kp, err := buildBogusInitReply()
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) < ikeHeaderSize {
		t.Fatalf("packet too short: %d bytes", len(packet))
	}
	totalLen := binary.BigEndian.Uint32(packet[24:28])
	if int(totalLen) != len(packet) {
		t.Fatalf("header length field %d != actual packet length %d", totalLen, len(packet))
	}
	if exchangeType, ok := parseIKEHeader(packet); !ok || exchangeType != exchangeInit {
		t.Fatalf("exchange type = %d ok=%v, want IKE_SA_INIT", exchangeType, ok)
	}
	if packet[19] != flagInitiator {
		t.Fatalf("flags = %x, want initiator flag set (matching upstream's initiator-only library used backwards)", packet[19])
	}
	if kp.public.Sign() == 0 {
		t.Fatal("generated DH key pair has a zero public value")
	}
	// rSPI must be zero: upstream's init_send() never sets it.
	if rSPI := binary.BigEndian.Uint64(packet[8:16]); rSPI != 0 {
		t.Fatalf("rSPI = %x, want 0", rSPI)
	}
}

func TestParseIKEHeaderRejectsShortInput(t *testing.T) {
	if _, ok := parseIKEHeader(make([]byte, 10)); ok {
		t.Fatal("expected parseIKEHeader to reject a too-short input")
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
