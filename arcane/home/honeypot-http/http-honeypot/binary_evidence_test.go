package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// #3212's coverage, in the order the issue states it: a real binary body
// preserved byte-for-byte with its encoding recorded, truncation separated
// from a short body, the hash's scope labelled as what it is, and no
// deserialization of anything that arrived over the socket.
//
// Everything here is offline and inert: the fixtures are bytes this file
// builds, there is no valid object graph among them, and no test reaches the
// network or a running sensor.

// loggedEvent drives one request through ServeHTTP and returns the decoded
// JSON line the sensor actually wrote, so every assertion below is about the
// data a downstream consumer gets rather than about a helper's return value.
func loggedEvent(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	s := &server{log: &logger{out: &buf}, sensor: "http-honeypot"}
	s.ServeHTTP(httptest.NewRecorder(), r)

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("no event was logged")
	}
	// The tarpit writes nothing, but a served response does not either --
	// anything but a single line here means the shape under test changed.
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("expected exactly one JSON line, got:\n%s", line)
	}
	var e map[string]any
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("logged line is not valid JSON: %v\n%s", err, line)
	}
	return e
}

func postRequest(body io.Reader, contentLength string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/index.php", body)
	r.RemoteAddr = "203.0.113.9:54321"
	if contentLength != "" {
		// httptest derives ContentLength from the reader but does not write
		// the header, and declaredLength() reads the claim off the wire.
		r.Header.Set("Content-Length", contentLength)
	}
	return r
}

func str(t *testing.T, e map[string]any, key string) string {
	t.Helper()
	v, ok := e[key].(string)
	if !ok {
		t.Fatalf("event has no string field %q: %v", key, e)
	}
	return v
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestShortBodyAndTruncatedBodyAreDistinguishable is the core of #3212:
// before the capture was described, "the attacker sent 40 bytes" and "we
// kept the first 64 KiB of a 4 MB upload" produced the same record, and
// nothing downstream could tell them apart. Asserted end to end, on the
// logged line, because the defect was in the data rather than in a helper.
func TestShortBodyAndTruncatedBodyAreDistinguishable(t *testing.T) {
	short := bytes.Repeat([]byte("A"), 40)
	bulk := bytes.Repeat([]byte("B"), 4<<20) // the issue's own example

	shortEvent := loggedEvent(t, postRequest(bytes.NewReader(short), "40"))
	bulkEvent := loggedEvent(t, postRequest(bytes.NewReader(bulk), "4194304"))

	if got := str(t, shortEvent, "body_capture_state"); got != captureComplete {
		t.Errorf("40-byte body: body_capture_state = %q, want %q", got, captureComplete)
	}
	if got := shortEvent["body_captured_bytes"]; got != float64(40) {
		t.Errorf("40-byte body: body_captured_bytes = %v, want 40", got)
	}
	if got := shortEvent["body_declared_bytes"]; got != float64(40) {
		t.Errorf("40-byte body: body_declared_bytes = %v, want 40", got)
	}

	if got := str(t, bulkEvent, "body_capture_state"); got != captureTruncated {
		t.Errorf("4 MB body: body_capture_state = %q, want %q", got, captureTruncated)
	}
	if got := bulkEvent["body_captured_bytes"]; got != float64(bodyCaptureMaxBytes) {
		t.Errorf("4 MB body: body_captured_bytes = %v, want %d", got, bodyCaptureMaxBytes)
	}
	if got := bulkEvent["body_declared_bytes"]; got != float64(4<<20) {
		t.Errorf("4 MB body: body_declared_bytes = %v, want %d", got, 4<<20)
	}
	if bulkEvent["body_read_error"] != nil {
		t.Errorf("4 MB body: body_read_error = %v, want none -- it was capped, not failed", bulkEvent["body_read_error"])
	}

	// The two must not merely be labelled differently -- the whole point is
	// that a consumer can tell them apart, which means the records differ.
	if str(t, shortEvent, "body_sha256") == str(t, bulkEvent, "body_sha256") {
		t.Error("a 40-byte body and a clipped 4 MB body hashed the same")
	}
	if str(t, shortEvent, "body_capture_state") == str(t, bulkEvent, "body_capture_state") {
		t.Error("the two captures are indistinguishable in the logged data")
	}
}

// TestCaptureCapBoundaryIsExact pins the boundary the truncation flag depends
// on: exactly at the cap is a complete body, one byte over is a truncated
// one. captureBody reads cap+1 precisely so this can be decided, and a body
// that stops exactly on the limit is the case that cannot be told from a
// complete one without it.
func TestCaptureCapBoundaryIsExact(t *testing.T) {
	cases := []struct {
		name  string
		size  int
		state string
	}{
		{"empty", 0, captureComplete},
		{"one byte", 1, captureComplete},
		{"exactly at the cap", bodyCaptureMaxBytes, captureComplete},
		{"one byte over the cap", bodyCaptureMaxBytes + 1, captureTruncated},
		{"far over the cap", bodyCaptureMaxBytes * 4, captureTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := captureBody(bytes.NewReader(bytes.Repeat([]byte("x"), tc.size)))
			if state := got.state(); state != tc.state {
				t.Fatalf("state() = %q, want %q", state, tc.state)
			}
			// Bounded means bounded, whatever arrived.
			if len(got.Bytes) > bodyCaptureMaxBytes {
				t.Fatalf("captured %d bytes, cap is %d", len(got.Bytes), bodyCaptureMaxBytes)
			}
		})
	}
}

// TestReadErrorIsRecordedNotSwallowed covers the other half of the discarded
// io.ReadAll error: a read that fails under the cap is neither "all of it"
// nor "we stopped at the limit", and the state has to say which.
func TestReadErrorIsRecordedNotSwallowed(t *testing.T) {
	sentinel := errors.New("connection reset by peer")
	partial := bytes.Repeat([]byte("Z"), 100)

	e := loggedEvent(t, postRequest(&failingReader{data: partial, err: sentinel}, ""))

	if got := str(t, e, "body_capture_state"); got != captureUnknown {
		t.Errorf("body_capture_state = %q, want %q", got, captureUnknown)
	}
	if got := str(t, e, "body_read_error"); got != sentinel.Error() {
		t.Errorf("body_read_error = %q, want %q", got, sentinel)
	}
	if got := e["body_captured_bytes"]; got != float64(100) {
		t.Errorf("body_captured_bytes = %v, want the 100 bytes that did arrive", got)
	}
	// The bytes that did arrive are still evidence, and still hashed.
	if got := str(t, e, "body_sha256"); got != sha256Hex(partial) {
		t.Errorf("body_sha256 = %q, want the hash of the 100 captured bytes", got)
	}
}

// failingReader hands over its bytes and then fails, which is what a
// truncated transfer looks like to a server: some data, then a transport
// error rather than a clean end of stream.
type failingReader struct {
	data []byte
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.data) > 0 {
		n := copy(p, f.data)
		f.data = f.data[n:]
		return n, nil
	}
	return 0, f.err
}

// binaryFixture is a real binary body: the Java stream magic followed by
// bytes that are not text. The 0x80 and 0xff are not valid UTF-8 in any
// position, the 0x00 is a NUL inside a payload, and the ED A0 80 triple is a
// surrogate half that UTF-8 forbids. Everything after the magic is inert
// filler -- there is no object graph here, only bytes.
func binaryFixture() []byte {
	return append(append([]byte{}, javaStreamMagic...),
		0x00, 0x80, 0xff, 0xfe, 0xed, 0xa0, 0x80, 0x01, 0x02, 0xc3, 0x28, 0x7f)
}

// TestBinaryEvidenceIsByteAccurateAndNamesItsEncoding is the first of the
// issue's four required proofs: arbitrary bytes including invalid UTF-8
// survive the recorded representation exactly, and the encoding is on the
// event rather than implied.
func TestBinaryEvidenceIsByteAccurateAndNamesItsEncoding(t *testing.T) {
	fixture := binaryFixture()
	if utf8.Valid(fixture) {
		t.Fatal("the fixture is supposed to be invalid UTF-8")
	}

	e := loggedEvent(t, postRequest(bytes.NewReader(fixture), ""))

	if got := str(t, e, "body_encoding"); got != bodyEvidenceEncoding {
		t.Errorf("body_encoding = %q, want %q", got, bodyEvidenceEncoding)
	}
	encoded := str(t, e, "body_b64")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("body_b64 is not valid base64: %v", err)
	}
	if !bytes.Equal(decoded, fixture) {
		t.Errorf("body_b64 decoded to %x, want the received bytes %x", decoded, fixture)
	}

	// And the reason the byte-safe half is needed at all: the legacy JSON
	// string field cannot carry these bytes, and the event is honest about
	// that only because the other field exists. json.Marshal substitutes
	// U+FFFD for every byte outside UTF-8, so this assertion failing would
	// mean the string field had somehow become lossless -- which is fine,
	// and would only mean the two fields now agree.
	if body, ok := e["body"].(string); ok && body == string(fixture) {
		t.Log("body preserved every byte; body_b64 remains the authoritative copy")
	} else if !strings.ContainsRune(body0(e), utf8.RuneError) {
		t.Error("expected the JSON string field to have lost the non-UTF-8 bytes it cannot carry")
	}
}

// body0 returns the logged body string, or "" when the event omits it.
func body0(e map[string]any) string {
	body, _ := e["body"].(string)
	return body
}

// TestBodySHA256CoversTheCapturedPrefixAndSaysSo is the second required
// proof. A hash whose scope is ambiguous is worse than no hash, because it
// looks comparable across sensors and is not -- so the value and the label
// that describes it are asserted together, including that the clipped case's
// hash is NOT the complete body's hash.
func TestBodySHA256CoversTheCapturedPrefixAndSaysSo(t *testing.T) {
	payload := bytes.Repeat([]byte("C"), bodyCaptureMaxBytes+2048)
	captured := payload[:bodyCaptureMaxBytes]

	clipped := loggedEvent(t, postRequest(bytes.NewReader(payload), ""))

	if got := str(t, clipped, "body_sha256_scope"); got != bodySHA256Scope {
		t.Errorf("body_sha256_scope = %q, want %q", got, bodySHA256Scope)
	}
	if got := str(t, clipped, "body_sha256"); got != sha256Hex(captured) {
		t.Errorf("body_sha256 = %q, want the hash of the captured prefix %q", got, sha256Hex(captured))
	}
	if complete := sha256Hex(payload); str(t, clipped, "body_sha256") == complete {
		t.Error("body_sha256 is the complete body's hash, which would contradict body_capture_state")
	}

	// When nothing was clipped, the captured prefix IS the complete body and
	// the same label stays true -- which is what makes it a scope rather
	// than a caveat.
	whole := []byte("<?php echo md5('hi');")
	full := loggedEvent(t, postRequest(bytes.NewReader(whole), ""))
	if got := str(t, full, "body_sha256_scope"); got != bodySHA256Scope {
		t.Errorf("complete body: body_sha256_scope = %q, want %q", got, bodySHA256Scope)
	}
	if got := str(t, full, "body_sha256"); got != sha256Hex(whole) {
		t.Errorf("complete body: body_sha256 = %q, want the hash of the whole body", got)
	}
}

// TestBodySHA256ScopeNamesTheRedactionAxis is the third half of the same
// proof, and the part #3213 made necessary.
//
// The fixtures above carry no credential, so redaction is a no-op on them and
// they cannot tell you what the hash covers when there IS one. The label has
// to survive that case: a consumer comparing body_sha256 against a body held
// somewhere else must be able to tell from the event alone whether a mismatch
// means "different body" or "redacted body". So the scope value names both
// bounds -- a prefix, and post-redaction -- and this asserts the value is
// exactly that, and that a credential-bearing body really does hash the
// scrubbed form rather than the bytes that arrived.
func TestBodySHA256ScopeNamesTheRedactionAxis(t *testing.T) {
	form := "username=alice&password=" + canarySecret
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form))
	r.RemoteAddr = "198.51.100.7:54321"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e := loggedEvent(t, r)

	// The label has to say "redacted" outright. Asserting the constant would
	// pass just as happily if the constant were quietly reverted to a value
	// that claims nothing about the second bound, which is the exact
	// regression this test exists to catch.
	if got := str(t, e, "body_sha256_scope"); got != "captured-prefix-redacted" {
		t.Errorf("body_sha256_scope = %q, want the scope to name the redaction axis", got)
	}

	redacted := inspectCredentials(r, form).redactedBody
	if redacted == form {
		t.Fatal("the fixture was not redacted, so this test is proving nothing")
	}
	if got := str(t, e, "body_sha256"); got == sha256Hex([]byte(form)) {
		t.Error("body_sha256 is the hash of the UNREDACTED body -- it would be a fingerprint of a credential")
	}
	if got := str(t, e, "body_sha256"); got != sha256Hex([]byte(redacted)) {
		t.Errorf("body_sha256 = %q, want the hash of the redacted captured prefix %q", got, sha256Hex([]byte(redacted)))
	}

	// The two evidence fields describe one byte string, so a consumer can
	// check them against each other instead of taking either on trust.
	head, err := base64.StdEncoding.DecodeString(str(t, e, "body_b64"))
	if err != nil {
		t.Fatalf("body_b64 is not valid base64: %v", err)
	}
	if !bytes.Equal(head, []byte(redacted)) {
		t.Errorf("body_b64 decodes to %q, want the redacted body %q -- the two evidence fields disagree", head, redacted)
	}
	if got := str(t, e, "body_sha256"); got != sha256Hex(head) {
		t.Errorf("hashing the decoded body_b64 gives %q, not the recorded body_sha256 %q", sha256Hex(head), got)
	}
}

// TestEvidenceRetainsOnlyABoundedHead keeps the retained evidence bounded in
// its own right: the cap is 64 KiB, the head is a fraction of it, and the
// hash still covers everything that was captured. Raising bodyEvidenceMaxBytes
// to cover a whole payload is the change this fails.
func TestEvidenceRetainsOnlyABoundedHead(t *testing.T) {
	payload := bytes.Repeat([]byte("D"), bodyCaptureMaxBytes)
	e := loggedEvent(t, postRequest(bytes.NewReader(payload), ""))

	head, err := base64.StdEncoding.DecodeString(str(t, e, "body_b64"))
	if err != nil {
		t.Fatalf("body_b64 is not valid base64: %v", err)
	}
	if len(head) != bodyEvidenceMaxBytes {
		t.Fatalf("retained head is %d bytes, want exactly %d", len(head), bodyEvidenceMaxBytes)
	}
	if !bytes.Equal(head, payload[:bodyEvidenceMaxBytes]) {
		t.Error("the retained head is not the leading bytes of the capture")
	}
	if got := str(t, e, "body_sha256"); got != sha256Hex(payload) {
		t.Error("body_sha256 does not cover the whole captured prefix")
	}
}

// TestJavaMarkerIsSeparateFromPayloadClass is the extend-don't-replace half.
// The existing ordered serialized-object class is shared with PHP and keeps
// its meaning and its position in the switch; the Java evidence arrives in
// its own field, and an earlier-priority match on the same body does not
// erase it.
func TestJavaMarkerIsSeparateFromPayloadClass(t *testing.T) {
	javaOnly := append(append([]byte{}, javaStreamMagic...), []byte(" inert test bytes")...)
	// Two classes at once: the magic and an injection. The ordered switch
	// names "sqli"; the marker is still observed.
	javaAndSQLi := append(append([]byte{}, javaStreamMagic...), []byte(" UNION SELECT 1,2 --")...)
	php := []byte(`O:8:"stdClass":1:{s:1:"a";i:1;}`)

	cases := []struct {
		name       string
		body       []byte
		wantClass  string
		wantMarker string
	}{
		{"java magic only", javaOnly, "serialized-object", "stream-magic"},
		{"java magic plus an earlier-priority match", javaAndSQLi, "sqli", "stream-magic"},
		{"php serialize() keeps the shared class and no Java marker", php, "serialized-object", ""},
		{"base64 of the java magic", []byte(base64.StdEncoding.EncodeToString(javaStreamMagic)), "serialized-object", "stream-magic-base64"},
		{"base64 magic followed by inert bytes", []byte(base64.StdEncoding.EncodeToString(javaStreamMagic) + "aGVsbG8="), "serialized-object", "stream-magic-base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := javaMarker(tc.body); got != tc.wantMarker {
				t.Errorf("javaMarker() = %q, want %q", got, tc.wantMarker)
			}
			if got := classifyPayload("", string(tc.body)); got != tc.wantClass {
				t.Errorf("classifyPayload() = %q, want %q", got, tc.wantClass)
			}
		})
	}
}

// TestJavaMarkerDoesNotFireOnEverything pins the negatives the issue names:
// ordinary text, unrelated binary data, a PHP-like marker and a short
// coincidental base64 prefix all stay unobserved. A field that says "Java
// marker seen" is a claim, and a claim that fires on a five-character
// prefix is worse than no field.
func TestJavaMarkerDoesNotFireOnEverything(t *testing.T) {
	negatives := []struct {
		name string
		body []byte
	}{
		{"ordinary text", []byte("name=bob&submit=1")},
		{"ordinary JSON", []byte(`{"username":"alice","remember":true}`)},
		{"unrelated binary data", []byte("\x16\x03\x01\x00\xee\x01\x00\x00\xea\x03\x03\xc8\xf7")},
		{"php-like marker fixture", []byte(`O:8:"stdClass":1:{s:1:"a";i:1;}`)},
		{"the word in prose", []byte("I read the java serialization docs")},
		{"four-character coincidental base64 prefix", []byte("rO0A")},
		{"five-character coincidental base64 prefix", []byte("rO0AB")},
		{"six-character coincidental base64 prefix", []byte("rO0ABQ")},
		{"base64 magic not at the start of the body", []byte("payload=" + base64.StdEncoding.EncodeToString(javaStreamMagic))},
		{"near miss on the second byte", []byte{0xac, 0xed, 0x00, 0x06, 0x73, 0x72}},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			if got := javaMarker(tc.body); got != "" {
				t.Errorf("javaMarker(%q) = %q, want no marker observed", tc.body, got)
			}
		})
	}
}

// TestJavaMarkerAndPayloadClassSurviveTheSameEvent proves the separation
// end to end rather than through the two functions alone: one logged line
// carries both the ordered class and the independent Java observation.
func TestJavaMarkerAndPayloadClassSurviveTheSameEvent(t *testing.T) {
	body := append(append([]byte{}, javaStreamMagic...), []byte(" UNION SELECT 1,2,3 --")...)
	e := loggedEvent(t, postRequest(bytes.NewReader(body), ""))

	if got := str(t, e, "payload_class"); got != "sqli" {
		t.Errorf("payload_class = %q, want %q -- the existing class is unchanged", got, "sqli")
	}
	if got := str(t, e, "java_marker"); got != "stream-magic" {
		t.Errorf("java_marker = %q, want %q -- the earlier match erased the marker", got, "stream-magic")
	}
}

// TestBinaryEvidenceNeverDeserializesTheStream is the fourth required proof,
// behaviourally. A deserializer could not produce this event: the fixture is
// not a valid object graph, and its bytes include sequences that a parse
// would have had to reject or normalise away. What the event shows instead
// is the received bytes, unchanged, and a marker name.
func TestBinaryEvidenceNeverDeserializesTheStream(t *testing.T) {
	// Four bytes of Java stream header, then inert text -- no class name, no
	// serialVersionUID, no field list, no gadget reference. The longest run
	// here is deliberately not decodable as anything.
	fixture := append(append([]byte{}, javaStreamMagic...),
		0x00, 0xff, 0xfe, 0x80, 0x81, 'i', 'n', 'e', 'r', 't', 0xc3, 0x28, 0xed, 0xa0, 0x80, ' ', 'f', 'i', 'l', 'l', 'e', 'r')
	if utf8.Valid(fixture) {
		t.Fatal("the fixture is supposed to be invalid UTF-8")
	}

	e := loggedEvent(t, postRequest(bytes.NewReader(fixture), ""))

	if got := str(t, e, "java_marker"); got != "stream-magic" {
		t.Errorf("java_marker = %q, want %q", got, "stream-magic")
	}
	decoded, err := base64.StdEncoding.DecodeString(str(t, e, "body_b64"))
	if err != nil {
		t.Fatalf("body_b64 is not valid base64: %v", err)
	}
	if !bytes.Equal(decoded, fixture) {
		t.Error("the evidence is not the received bytes -- something parsed or normalised them")
	}
	// The strongest statement available offline: not one string value in the
	// whole document reproduces the fixture. Anything that had read the
	// stream as an object and surfaced any part of it would leave a
	// readable trace here, and a plain JSON round-trip could not, because
	// the invalid bytes are exactly what it cannot carry.
	assertNoStringCarriesFixture(t, e, fixture)
}

// assertNoStringCarriesFixture walks every string in the decoded document and
// fails if any of them contains the fixture's bytes.
func assertNoStringCarriesFixture(t *testing.T, node any, fixture []byte) {
	t.Helper()
	switch v := node.(type) {
	case string:
		if strings.Contains(v, string(fixture)) {
			t.Errorf("a string field reproduces the received bytes verbatim: %q", v)
		}
	case map[string]any:
		for _, child := range v {
			assertNoStringCarriesFixture(t, child, fixture)
		}
	case []any:
		for _, child := range v {
			assertNoStringCarriesFixture(t, child, fixture)
		}
	}
}

// TestPackageImportsNoDeserializer is the same guarantee made mechanical, so
// it cannot lapse quietly. A future change that reaches for a decoder -- Go's
// own gob, an XML or YAML unmarshaller, or any third-party library at all --
// fails here rather than becoming a new way to act on attacker bytes.
func TestPackageImportsNoDeserializer(t *testing.T) {
	// Each of these turns bytes into structure. That is precisely what this
	// sensor must not do with a request body: the honeypot's value is in
	// recording what arrived, and a decoder is where recording turns into
	// acting on it.
	forbidden := map[string]string{
		"encoding/gob":     "decodes typed values out of a byte stream",
		"encoding/xml":     "decodes elements into structure",
		"gopkg.in/yaml.v2": "decodes documents into structure",
		"gopkg.in/yaml.v3": "decodes documents into structure",
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		checked++
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			if why, bad := forbidden[path]; bad {
				t.Errorf("%s imports %q -- %s. A received object is never decoded.", name, path, why)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test sources were inspected; the guard above is vacuous")
	}

	// Stdlib only, so there is no transitive decoder nobody imported here.
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(gomod), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasPrefix(trimmed, "module ") || strings.HasPrefix(trimmed, "go ") {
			continue
		}
		t.Errorf("go.mod gained %q: this module is stdlib-only by design, so a third-party decoder cannot be added unnoticed", trimmed)
	}
}

// TestCaptureFieldsSurviveFilebeatNesting is the offline ingestion fixture.
// filebeat.yml's honeypot-json input parses each line with target "honeypot",
// so every top-level key lands under honeypot.*, and that object is
// `flattened` with ignore_above: 32000 (honeypot-init's
// elasticsearch-setup.sh). Two properties therefore have to hold for the new
// fields to be usable at all: they are top-level, and no value crosses that
// ceiling -- past it the value is stored but stops being indexed.
func TestCaptureFieldsSurviveFilebeatNesting(t *testing.T) {
	const flattenedIgnoreAbove = 32000

	payload := append(append([]byte{}, javaStreamMagic...), bytes.Repeat([]byte("E"), bodyCaptureMaxBytes)...)
	// body_read_error only exists on a read that failed, so it is checked on
	// the event that has one rather than asserted on an event that has none.
	events := map[string]map[string]any{
		"captured": loggedEvent(t, postRequest(bytes.NewReader(payload), "")),
		"failed": loggedEvent(t, postRequest(&failingReader{
			data: []byte("partial"),
			err:  errors.New("unexpected EOF"),
		}, "")),
	}
	required := []struct{ key, where string }{
		{"body_capture_state", "captured"},
		{"body_captured_bytes", "captured"},
		{"body_encoding", "captured"},
		{"body_b64", "captured"},
		{"body_sha256", "captured"},
		{"body_sha256_scope", "captured"},
		{"body_declared_bytes", "captured"},
		{"java_marker", "captured"},
		{"body_read_error", "failed"},
	}

	for _, want := range required {
		key, e := want.key, events[want.where]

		// filebeat nests the whole line, so what must be top-level in our
		// JSON is what must be reachable at honeypot.<key> afterwards.
		raw, err := json.Marshal(e[key])
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if string(raw) == "null" || string(raw) == `""` {
			t.Errorf("%s is empty on the %s event, so it carries nothing", key, want.where)
			continue
		}
		if len(raw) > flattenedIgnoreAbove {
			t.Errorf("%s is %d characters, past the flattened field's ignore_above of %d -- it would be stored but not indexed",
				key, len(raw), flattenedIgnoreAbove)
		}

		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var nested map[string]any
		if err := json.Unmarshal(line, &nested); err != nil {
			t.Fatal(err)
		}
		if _, ok := nested[key]; !ok {
			t.Errorf("%s does not survive the filebeat nesting as honeypot.%s", key, key)
		}
	}
}

// TestCaptureMetadataCarriesNoCredentialMaterial is the "presentation does
// not expose credentials" half, for the fields this change adds. The
// metadata says how much was captured and what it hashes; none of it repeats
// a submitted secret.
//
// REWRITTEN against #3213, and the original version of this test asserted the
// opposite. It argued that body_b64 "adds no new class of disclosed material"
// because `body` already carried the raw bytes -- a premise #3213 invalidated
// by redacting `body`, which would have left body_b64 as the only place a
// submitted credential survived the event. The assertion that
// decode(body_b64) == the raw form is therefore inverted, and the replacement
// is strictly stronger than the one it replaces: the old test checked only
// that the secret was absent from the base64 TEXT, which is nearly vacuous,
// because a base64 field cannot contain a raw secret as a substring in the
// first place. This one decodes the field and checks the bytes.
//
// The expected redacted form is produced by calling inspectCredentials, the
// same helper the sensor calls. Reimplementing redaction here would give the
// test a second, quietly divergent definition of what redacted means.
func TestCaptureMetadataCarriesNoCredentialMaterial(t *testing.T) {
	const submitted = "not-a-real-credential-value"
	form := "username=alice&password=" + submitted

	r := postRequest(bytes.NewReader([]byte(form)), "")
	r.SetBasicAuth("alice", submitted)
	r.Header.Set("Authorization", "Bearer "+submitted)
	e := loggedEvent(t, r)

	for _, key := range []string{
		"body_capture_state", "body_capture_state", "body_encoding",
		"body_sha256", "body_sha256_scope", "body_read_error",
		"body_declared_bytes", "java_marker",
	} {
		if v, ok := e[key].(string); ok && strings.Contains(v, submitted) {
			t.Errorf("%s repeats submitted credential material: %q", key, v)
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(str(t, e, "body_b64"))
	if err != nil {
		t.Fatalf("body_b64 is not valid base64: %v", err)
	}

	// The assertion that replaces the invalidated one. body_b64 is the
	// REDACTED capture, and the redacted capture is exactly what the shared
	// helper produced for this request.
	want := inspectCredentials(r, form)
	if got, want := string(decoded), want.redactedBody; got != want {
		t.Errorf("body_b64 decodes to %q, want the redacted body %q", got, want)
	}
	if bytes.Equal(decoded, []byte(form)) {
		t.Error("body_b64 carries the unredacted body -- that is the leak #3213 closed on `body`, reintroduced here")
	}
	// Checked on the DECODED bytes, which is the check that means something.
	// Checking the encoded text could never fail: base64 does not preserve
	// substrings, which is exactly why this field was a safe place to put a
	// secret and is now not one.
	if bytes.Contains(decoded, []byte(submitted)) {
		t.Errorf("the decoded evidence carries the submitted secret: %q", decoded)
	}

	// Body and BodyB64 are the same string, so the two fields cannot drift
	// apart. This is the invariant that makes body_b64 a faithful
	// representation of the event's own `body` rather than a second,
	// differently-filtered view of it.
	if got := body0(e); !strings.HasPrefix(got, string(decoded)) {
		t.Errorf("body_b64 (%q) is not a prefix of body (%q) -- the evidence and the body disagree", decoded, got)
	}
}

// TestBinaryEvidenceNeverCarriesCredentialMaterial is the guard that actually
// holds for body_b64, and it exists because the obvious one does not.
//
// credentials_test.go's TestPasswordNeverReachesTheEvent searches the log
// line for four encodings of the secret, one of which is the base64 of the
// secret. That catches a body_b64 leak only when the bytes preceding the
// secret in the body happen to be a multiple of three -- the base64 of a
// whole body only contains the base64 of an interior substring verbatim when
// that substring starts on a 3-byte boundary. Measured on this branch with
// the evidence deliberately built from the raw capture, it caught 2 of its
// own 14 channels: `username=admin&password=<secret>` (24 bytes before the
// secret) and `admin:<secret>` (6 bytes). The other 12 -- JSON, multipart,
// nested JSON, XML, query-string, header-only, and both read-cap cases --
// sailed through with the credential sitting in the event, because 3 did not
// divide the offset.
//
// So the check that matters is on the DECODED bytes, which does not care
// where the secret happens to fall. This runs the same canary through the
// shapes that carry a credential in a body, decodes body_b64, and requires
// the secret to be absent from what comes out. It is the property #3213
// established for `body`, extended to the one field that would otherwise have
// carried the raw bytes around it.
func TestBinaryEvidenceNeverCarriesCredentialMaterial(t *testing.T) {
	shapes := []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "form urlencoded",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=" + canaryUsername + "&password=" + canarySecret,
		},
		{
			name:        "json",
			contentType: "application/json",
			body:        `{"login":"` + canaryUsername + `","password":"` + canarySecret + `"}`,
		},
		{
			name:        "json, nested",
			contentType: "application/json",
			body:        `{"a":{"b":[{"user":"` + canaryUsername + `","secret":"` + canarySecret + `"}]}}`,
		},
		{
			name:        "html form",
			contentType: "text/html",
			body: `<form><input name="username" value="` + canaryUsername + `">` +
				`<input type="password" name="password" value="` + canarySecret + `"></form>`,
		},
		{
			name:        "multipart",
			contentType: "multipart/form-data; boundary=AaB03x",
			body: "--AaB03x\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n" +
				canaryUsername + "\r\n--AaB03x\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" +
				canarySecret + "\r\n--AaB03x--\r\n",
		},
		{
			name:        "bare basic, no field name at all",
			contentType: "text/plain",
			body:        canaryUsername + ":" + canarySecret,
		},
		{
			name:        "a credential-bearing body that hits the read cap",
			contentType: "application/x-www-form-urlencoded",
			body: "username=" + canaryUsername + "&filler=" + strings.Repeat("x", bodyReadCap) +
				"&password=" + canarySecret,
		},
		{
			// A body no field-name scan can speak for. #3213 documents this as
			// an honest limit rather than a bug -- a value with no key cannot
			// be told from ordinary data -- and the shapes it covers live in
			// credentials_test.go. It is here to pin that body_b64 inherits
			// that limit exactly rather than widening it: whatever `body`
			// cannot scrub, body_b64 is scrubbed by the same pass on the same
			// string, so the two can never disagree about it.
			name:        "an xml body no parser here reads",
			contentType: "text/xml",
			body: `<?xml version="1.0"?><login><user>` + canaryUsername + `</user>` +
				`<password>` + canarySecret + `</password></login>`,
		},
	}

	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/index.php", strings.NewReader(tc.body))
			r.RemoteAddr = "198.51.100.7:54321"
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			e := loggedEvent(t, r)

			decoded, err := base64.StdEncoding.DecodeString(str(t, e, "body_b64"))
			if err != nil {
				t.Fatalf("body_b64 is not valid base64: %v", err)
			}
			if bytes.Contains(decoded, []byte(canarySecret)) {
				t.Errorf("body_b64 decodes to bytes carrying the submitted secret: %q", decoded)
			}
			// Not vacuous: the evidence still has to carry the payload it
			// exists to preserve. The username half is deliberately allowed
			// through -- it is the analytic value and not a secret -- so a
			// guard that asserted its absence would be asserting the feature
			// away, and a guard that only checked for the secret would pass
			// just as happily on a field emptied of evidence entirely.
			if strings.Contains(tc.body, canaryUsername) && !bytes.Contains(decoded, []byte(canaryUsername)) {
				t.Errorf("body_b64 decodes to %q, which dropped the account name too -- the field is empty of evidence, not just of the secret", decoded)
			}
			// Whatever else it holds, the evidence is the event's own body.
			if got := body0(e); !strings.HasPrefix(got, string(decoded)) {
				t.Errorf("body_b64 is not a prefix of body -- the evidence and the body disagree")
			}
		})
	}
}
