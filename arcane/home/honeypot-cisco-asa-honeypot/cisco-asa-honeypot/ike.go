// ike.go ports the crypto/wire-encoding this decoy needs from the
// Cymmetria/ike Python library that t3chn0m4g3/ciscoasa_honeypot's
// ike_server.py depends on (#238, #414). Confirmed directly against both
// repos' actual source before porting -- neither is what the issue's
// original line-count summary suggested:
//
//   - Cymmetria/ike implements only the IKEv2 INITIATOR role, but
//     ike_server.py uses it backwards as a responder: on receiving an
//     attacker's IKE_SA_INIT, it replies with its OWN freshly self-generated
//     IKE_SA_INIT (ignoring the attacker's actual proposal/KE/nonce
//     entirely, iSPI included), then treats the attacker's *next* packet as
//     if it were a peer's response to that bogus message.
//   - The second reply (IKE_AUTH) signs its AUTH payload with an RSA key
//     read from a relative path ("tests/private_key.pem") that only exists
//     inside the ike library's own git checkout, never in an installed
//     package -- confirmed against its setup.py (packages=['ike','ike.util'],
//     tests/ not included). ciscoasa_honeypot's own working directory has
//     no such file either. So in real deployment, generating the IKE_AUTH
//     reply always raises, is caught by the same broad except Exception
//     ike_server.py wraps every state transition in, and that session is
//     simply dropped -- no second reply is ever actually sent.
//
// This file therefore only implements what upstream actually, observably
// does over the wire: real Diffie-Hellman (MODP group 14, RFC 3526) and a
// real nonce for exactly one reply per source address, then silence.
// Reproducing the internal SKEYSEED/keymat computation that upstream also
// performs before failing would add real complexity for zero difference in
// any byte this sensor ever sends -- see main.go's ikeSession for where
// that line is drawn.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
)

// dhGroup14Prime is the RFC 3526 2048-bit MODP group used by upstream's
// DiffieHellman(group=14) default.
var dhGroup14Prime = mustHex(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF")

const dhGenerator = 2

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex constant")
	}
	return n
}

// dhKeyPair mirrors upstream's DiffieHellman: a private key drawn from 64
// random bytes (512 bits, not the full 2048-bit exponent range -- an
// upstream quirk, not a mistake of this port) and a public key of
// generator^private mod p.
type dhKeyPair struct {
	private *big.Int
	public  *big.Int
}

func newDHKeyPair() (dhKeyPair, error) {
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return dhKeyPair{}, err
	}
	priv := new(big.Int).SetBytes(buf)
	pub := new(big.Int).Exp(big.NewInt(dhGenerator), priv, dhGroup14Prime)
	return dhKeyPair{private: priv, public: pub}, nil
}

// sharedSecret mirrors DiffieHellman.derivate(): other^private mod p.
func (k dhKeyPair) sharedSecret(other *big.Int) *big.Int {
	return new(big.Int).Exp(other, k.private, dhGroup14Prime)
}

// toBytes mirrors ike.util.conv.to_bytes: the minimal big-endian encoding
// of a non-negative integer, NOT zero-padded to the group's byte width.
// This exact quirk matters for byte-for-byte fidelity with what upstream's
// Python would have put on the wire.
func toBytes(n *big.Int) []byte {
	if n.Sign() == 0 {
		return nil
	}
	return n.Bytes() // math/big.Int.Bytes() is already minimal big-endian
}

// prf is ike.util.prf.prf: plain HMAC-SHA256.
func prf(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// prfPlus is ike.util.prf.prfplus: T1=PRF(key,S1|data|0x01),
// T2=PRF(key,T1|data|0x02), ... concatenated and truncated to n bytes.
// Unused by any code path this sensor actually reaches (see the package
// doc comment), kept only because it's cheap and documents precisely
// where upstream's real behavior would continue if the AUTH step didn't
// fail first.
func prfPlus(key, data []byte, n int) []byte {
	var ret, prev []byte
	round := byte(1)
	for len(ret) < n {
		in := append(append(append([]byte{}, prev...), data...), round)
		prev = prf(key, in)
		ret = append(ret, prev...)
		round++
	}
	return ret[:n]
}

// --- IKEv2 wire format (RFC 7296 section 3) -------------------------------

const (
	ikeHeaderSize    = 28
	payloadHeaderLen = 4

	payloadNone   = 0
	payloadSA     = 33
	payloadKE     = 34
	payloadNonce  = 40
	exchangeInit  = 34 // IKE_SA_INIT
	exchangeAuth  = 35 // IKE_AUTH
	ikeVersion    = 0x20
	flagInitiator = 0x08

	protocolIKE = 1
	protocolESP = 3

	// Transform type IDs (RFC 7296 3.3.2) and the specific IDs upstream's
	// default SA proposal uses (const.py's TRANSFORMS table).
	transformTypeENCR = 1
	transformTypePRF  = 2
	transformTypeAUTH = 3
	transformTypeDH   = 4
	transformTypeESN  = 5

	encrCamelliaCBC      = 23 // RFC 5529
	prfHMACSHA2_256      = 5  // RFC 4868
	authHMACSHA2_256_128 = 12 // RFC 4868
	dhGroup14ID          = 14
	esnID                = 1
)

// ikeHeader encodes the 28-byte IKEv2 header (RFC 7296 3.1).
func ikeHeader(iSPI, rSPI uint64, nextPayload byte, exchangeType byte, flags byte, messageID uint32, totalLen uint32) []byte {
	b := make([]byte, ikeHeaderSize)
	binary.BigEndian.PutUint64(b[0:8], iSPI)
	binary.BigEndian.PutUint64(b[8:16], rSPI)
	b[16] = nextPayload
	b[17] = ikeVersion
	b[18] = exchangeType
	b[19] = flags
	binary.BigEndian.PutUint32(b[20:24], messageID)
	binary.BigEndian.PutUint32(b[24:28], totalLen)
	return b
}

// payloadHeader encodes the generic 4-byte payload header (RFC 7296 3.2).
func payloadHeader(nextPayload byte, length uint16) []byte {
	b := make([]byte, payloadHeaderLen)
	b[0] = nextPayload
	b[1] = 0 // critical flag, never set here
	binary.BigEndian.PutUint16(b[2:4], length)
	return b
}

// transform encodes one SA proposal transform (RFC 7296 3.3.2), optionally
// with a single 4-byte Type/Value attribute for a key length (used only by
// the ENCR transform, matching upstream's Transform class).
func transform(last bool, transformType byte, transformID uint16, keyLength uint16) []byte {
	const size = 8
	attrLen := 0
	if keyLength > 0 {
		attrLen = 4
	}
	b := make([]byte, size+attrLen)
	if !last {
		b[0] = 3
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(size+attrLen))
	b[4] = transformType
	binary.BigEndian.PutUint16(b[6:8], transformID)
	if keyLength > 0 {
		binary.BigEndian.PutUint16(b[8:10], 0x8000|14) // TV attribute format, type 14 (Key Length)
		binary.BigEndian.PutUint16(b[10:12], keyLength)
	}
	return b
}

// proposal encodes one SA proposal (RFC 7296 3.3.1): IKE proposals carry
// an 8-byte SPI, ESP proposals a 4-byte SPI, matching upstream's
// Proposal.__init__ default spi_len-by-protocol logic.
func proposal(last bool, num byte, protocolID byte, spi uint64, transforms [][]byte) []byte {
	const headerSize = 8
	spiLen := 8
	if protocolID == protocolESP {
		spiLen = 4
	}
	var body []byte
	for _, t := range transforms {
		body = append(body, t...)
	}
	total := headerSize + spiLen + len(body)

	b := make([]byte, headerSize)
	if !last {
		b[0] = 2
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[4] = num
	b[5] = protocolID
	b[6] = byte(spiLen)
	b[7] = byte(len(transforms))

	spiBytes := make([]byte, spiLen)
	if spiLen == 8 {
		binary.BigEndian.PutUint64(spiBytes, spi)
	} else {
		binary.BigEndian.PutUint32(spiBytes, uint32(spi))
	}

	out := make([]byte, 0, total)
	out = append(out, b...)
	out = append(out, spiBytes...)
	out = append(out, body...)
	return out
}

// defaultSAPayload builds the SA payload upstream's payloads.SA() default
// constructor produces when called with no explicit proposals: one IKE
// proposal and one ESP proposal, both offering Camellia-CBC/256 --
// upstream's own (unusual, but real) transform choice, ported exactly
// rather than substituted with a more common AES suite.
func defaultSAPayload(nextPayload byte, ikeSPI uint64, espSPI uint32) []byte {
	ikeProposal := proposal(false, 1, protocolIKE, ikeSPI, [][]byte{
		transform(false, transformTypeENCR, encrCamelliaCBC, 256),
		transform(false, transformTypePRF, prfHMACSHA2_256, 0),
		transform(false, transformTypeAUTH, authHMACSHA2_256_128, 0),
		transform(true, transformTypeDH, dhGroup14ID, 0),
	})
	espProposal := proposal(true, 2, protocolESP, uint64(espSPI), [][]byte{
		transform(false, transformTypeENCR, encrCamelliaCBC, 256),
		transform(false, transformTypeESN, esnID, 0),
		transform(true, transformTypeAUTH, authHMACSHA2_256_128, 0),
	})
	body := append(ikeProposal, espProposal...)
	length := uint16(payloadHeaderLen + len(body))
	return append(payloadHeader(nextPayload, length), body...)
}

// kePayload builds a Key Exchange payload (RFC 7296 3.4) carrying group 14
// and this key pair's public value, encoded via toBytes (not zero-padded).
func kePayload(nextPayload byte, pub *big.Int) []byte {
	kex := toBytes(pub)
	body := make([]byte, 4+len(kex))
	binary.BigEndian.PutUint16(body[0:2], dhGroup14ID)
	copy(body[4:], kex)
	length := uint16(payloadHeaderLen + len(body))
	return append(payloadHeader(nextPayload, length), body...)
}

// noncePayload builds a Nonce payload (RFC 7296 3.9) from raw nonce bytes.
func noncePayload(nextPayload byte, nonce []byte) []byte {
	length := uint16(payloadHeaderLen + len(nonce))
	return append(payloadHeader(nextPayload, length), nonce...)
}

// randomNonce mirrors upstream's default os.urandom(32) IKE nonce.
func randomNonce() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// randomSPI mirrors Proposal's own random-SPI generation for an IKE
// proposal (8 bytes) when no explicit spi is given.
func randomSPI() (uint64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func randomESPSPI() (uint32, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// buildBogusInitReply ports IKE.init_send(): a full IKE_SA_INIT packet
// built entirely from freshly-generated local values (SA proposal's own
// random SPI, a fresh DH keypair, a fresh nonce), with rSPI left at 0 and
// the Initiator flag set -- because upstream's library only ever builds
// packets as an initiator, regardless of which role ike_server.py actually
// needs here. It does not look at anything in the attacker's own request
// beyond having decided (by exchange type) to call this at all.
func buildBogusInitReply() ([]byte, dhKeyPair, error) {
	kp, err := newDHKeyPair()
	if err != nil {
		return nil, dhKeyPair{}, err
	}
	ikeSPI, err := randomSPI()
	if err != nil {
		return nil, dhKeyPair{}, err
	}
	espSPI, err := randomESPSPI()
	if err != nil {
		return nil, dhKeyPair{}, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, dhKeyPair{}, err
	}

	sa := defaultSAPayload(payloadKE, ikeSPI, espSPI)
	ke := kePayload(payloadNonce, kp.public)
	no := noncePayload(payloadNone, nonce)

	body := append(append(sa, ke...), no...)
	total := uint32(ikeHeaderSize + len(body))
	header := ikeHeader(ikeSPI, 0, payloadSA, exchangeInit, flagInitiator, 0, total)
	return append(header, body...), kp, nil
}

// parseIKEHeader reads just enough of an inbound datagram to drive the
// (deliberately minimal, see package doc comment) session state machine:
// whether it looks like an IKE packet at all, and its exchange type.
func parseIKEHeader(data []byte) (exchangeType byte, ok bool) {
	if len(data) < ikeHeaderSize {
		return 0, false
	}
	return data[18], true
}

// ikeTransformName maps the handful of transform IDs real-world IKE
// clients/scanners commonly propose to a short human name, per type (RFC
// 7296 3.3.2/3.3.5 registries) -- deliberately not an exhaustive IANA
// table, just enough for the common case; anything unrecognized still
// shows its raw numeric ID rather than being dropped.
func ikeTransformName(transformType byte, id uint16) string {
	names := map[byte]map[uint16]string{
		transformTypeENCR: {2: "DES-CBC", 3: "3DES-CBC", 12: "AES-CBC", 13: "AES-CTR", 20: "AES-GCM-16", 23: "Camellia-CBC"},
		transformTypePRF:  {1: "HMAC-MD5", 2: "HMAC-SHA1", 5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512"},
		transformTypeAUTH: {0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"},
		transformTypeDH:   {1: "768-bit MODP", 2: "1024-bit MODP", 5: "1536-bit MODP", 14: "2048-bit MODP", 19: "256-bit ECP", 20: "384-bit ECP", 21: "521-bit ECP"},
		transformTypeESN:  {0: "No-ESN", 1: "ESN"},
	}
	typeName := map[byte]string{
		transformTypeENCR: "ENCR", transformTypePRF: "PRF", transformTypeAUTH: "AUTH",
		transformTypeDH: "DH", transformTypeESN: "ESN",
	}[transformType]
	if typeName == "" {
		typeName = fmt.Sprintf("type%d", transformType)
	}
	if name, ok := names[transformType][id]; ok {
		return typeName + "=" + name
	}
	return fmt.Sprintf("%s=%d", typeName, id)
}

// parseIKEProposals walks an SA payload's body (RFC 7296 3.3.1/3.3.2) --
// the exact reverse of proposal()/transform() above -- and renders each
// proposal's protocol + transform list as a short summary. Malformed
// substructures stop parsing at that point rather than erroring: this is
// attacker-controlled input from a datagram that already passed the outer
// payload-length check, best-effort is the right failure mode here.
func parseIKEProposals(body []byte) string {
	var proposals []string
	off := 0
	for off+8 <= len(body) {
		length := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		if length < 8 || off+length > len(body) {
			break
		}
		protocolID := body[off+5]
		spiLen := int(body[off+6])
		numTransforms := int(body[off+7])
		proto := fmt.Sprintf("protocol%d", protocolID)
		switch protocolID {
		case protocolIKE:
			proto = "IKE"
		case protocolESP:
			proto = "ESP"
		}

		tOff := off + 8 + spiLen
		var transforms []string
		for i := 0; i < numTransforms && tOff+8 <= off+length; i++ {
			tLen := int(binary.BigEndian.Uint16(body[tOff+2 : tOff+4]))
			if tLen < 8 || tOff+tLen > off+length {
				break
			}
			transforms = append(transforms, ikeTransformName(body[tOff+4], binary.BigEndian.Uint16(body[tOff+6:tOff+8])))
			tOff += tLen
		}
		proposals = append(proposals, proto+"["+strings.Join(transforms, ",")+"]")
		off += length
	}
	return strings.Join(proposals, " ")
}

// parseIKESAInitBody walks the payload chain of an attacker's own
// IKE_SA_INIT (RFC 7296 3.2: generic 4-byte payload header, next-payload
// type for the first payload comes from the fixed header's own byte 16)
// and summarizes the real SA proposal, KE group/public-key length, and
// nonce length the attacker sent -- real recon/fingerprint signal
// (Cymmetria/ike vs. Scapy vs. a custom scanner often differ in exactly
// what they propose here) that upstream's own reply-building code parses
// this same wire format to construct but this sensor's logging never
// read. Read-only: this must never influence what buildBogusInitReply
// sends, only what gets logged alongside it.
func parseIKESAInitBody(data []byte) string {
	if len(data) < ikeHeaderSize {
		return ""
	}
	var parts []string
	payloadType := data[16]
	off := ikeHeaderSize
	for payloadType != payloadNone && off+payloadHeaderLen <= len(data) {
		next := data[off]
		length := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if length < payloadHeaderLen || off+length > len(data) {
			break
		}
		body := data[off+payloadHeaderLen : off+length]
		switch payloadType {
		case payloadSA:
			if sa := parseIKEProposals(body); sa != "" {
				parts = append(parts, "SA: "+sa)
			}
		case payloadKE:
			if len(body) >= 4 {
				group := binary.BigEndian.Uint16(body[0:2])
				parts = append(parts, fmt.Sprintf("KE: group=%d pubkey=%dB", group, len(body)-4))
			}
		case payloadNonce:
			parts = append(parts, fmt.Sprintf("Nonce: %dB", len(body)))
		}
		payloadType = next
		off += length
	}
	return strings.Join(parts, "  ")
}
