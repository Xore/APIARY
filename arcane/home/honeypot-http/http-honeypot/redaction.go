// Redaction helpers for the opaque (non-form, non-JSON) path.
//
// This file is the shared body of redactOpaque/matchFieldName/opaqueValueEnd,
// applied identically by both sensors, because the http-honeypot suite
// found two bugs in the original single-file version that would have been
// inherited verbatim by any copy of it:
//
//  1. "password=x" matched the key "pass" with the cursor left on "word=",
//     so the field name was never fully written and the scrubbed body said
//     "pass[redacted]". The body stopped being re-parseable.
//  2. A quoted value was bounded by whichever separator introduced it, so
//     {"password":"secret"} scanned to the closing brace and left the
//     secret in the log. That is the JSON-with-a-lying-Content-Type path,
//     which redactSecretValues explicitly routes here on purpose.
//
// The second one is why a quoted value is bounded by its own closing quote
// regardless of the separator: in JSON the value after ':' is a quoted
// string, and the ':' rule (scan to , } ]) runs straight past the closing
// quote.
package main

import "strings"

// redactOpaque scrubs credential-shaped values out of a payload whose shape
// this sensor does not parse -- XML, multipart, plain text, a binary blob
// someone spoke at an HTTP port.
//
// It is a value scrubber, not a parser. It finds a known field name, looks
// at the separator that follows it, and replaces the value that belongs to
// that separator's own structural delimiter. Stopping at the first space
// would leave the tail of "correct horse battery staple" behind, and a
// password is exactly where someone puts a space.
//
// It deliberately over-redacts. A field called "monkey" loses its value; a
// prose body that mentions the word "password" may lose the rest of its
// line. A false redaction costs one scanner's junk; a missed redaction
// costs the trust boundary.
func redactOpaque(raw string) (string, bool) {
	var b strings.Builder
	b.Grow(len(raw))
	found := false
	lower := strings.ToLower(raw)

	for i := 0; i < len(raw); {
		name, nameLen := matchFieldName(raw, lower, i)
		if nameLen == 0 {
			b.WriteByte(raw[i])
			i++
			continue
		}
		b.WriteString(raw[i : i+nameLen])
		i += nameLen
		found = found || isCredentialField(name, true)

		// Step over the rest of the field name and WRITE it, then any
		// spaces before the separator.
		for i < len(raw) && isNameByte(raw[i]) {
			b.WriteByte(raw[i])
			i++
		}
		// A QUOTED field name closes before its separator. JSON puts one
		// there -- {"password":"secret"} has a quote at index 10 and the
		// colon at 11 -- and a quote is also one of the value separators,
		// so without this step the scrubber would treat the key's own
		// closing quote as "a quoted value starts here" and redact
		// through the colon, writing {"password"[redacted]secret"...
		if i < len(raw) && (raw[i] == '"' || raw[i] == '\'') {
			b.WriteByte(raw[i])
			i++
		}
		for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t') {
			b.WriteByte(raw[i])
			i++
		}
		if i >= len(raw) {
			break
		}
		if !isValueSeparator(raw[i]) {
			continue
		}
		// The separator is part of the field's shape, not part of its
		// value, so it is written back around the marker.
		b.WriteByte(raw[i])

		// A quoted value ends at its own closing quote, whichever
		// separator introduced it. This is the JSON case, and it is the
		// one that leaked: {"password":"secret"} arrives as ':' followed
		// by a quoted string, and the ':' rule would scan to the closing
		// brace and write the secret straight back into the log.
		if i+1 < len(raw) && (raw[i+1] == '"' || raw[i+1] == '\'') {
			quote := raw[i+1]
			b.WriteByte(quote)
			b.WriteString(redactMarker)
			b.WriteByte(quote)
			i = scanQuoted(raw, i+1)
			continue
		}
		b.WriteString(redactMarker)
		if end := opaqueValueEnd(raw, i+1); end > i+1 {
			i = end
		}
	}
	return b.String(), found
}

// isValueSeparator reports whether b can introduce a value after a field
// name. The shapes redactOpaque knows how to bound.
func isValueSeparator(b byte) bool {
	switch b {
	case '=', ':', '>', '"', '\'':
		return true
	}
	return false
}

// scanQuoted returns the index just past the closing quote of the quoted
// run starting at i, or len(raw) when the run is unterminated. raw[i] is
// the opening quote.
func scanQuoted(raw string, i int) int {
	quote := raw[i]
	for j := i + 1; j < len(raw); j++ {
		if raw[j] == quote {
			return j + 1
		}
	}
	return len(raw)
}

// opaqueValueEnd finds where an unquoted value ends, by the separator that
// introduced it. from is the index just past that separator: raw[from-1] is
// the '=' or ':' or '>' that started the value, and the rules differ per
// separator. It returns from when there is nothing to replace, so a bare
// mention of a field name costs nothing.
//
// The separator is passed in rather than found here because redactOpaque
// has already written it back around the redaction marker by the time this
// runs; finding it again would mean walking back over bytes already
// emitted.
func opaqueValueEnd(raw string, from int) int {
	if from <= 0 || from > len(raw) {
		return from
	}
	switch raw[from-1] {
	case '=':
		return scanTo(raw, from, "&\n")
	case ':':
		return scanTo(raw, from, ",}]\n")
	case '>':
		// XML text content: <password>…</password>
		return scanTo(raw, from, "<\n")
	case '"', '\'':
		return scanQuoted(raw, from-1)
	}
	return from
}

// isNameByte reports whether b can continue a field name. Deliberately
// narrower than the characters that may START one (matchFieldName's
// delimiter list) and narrower than [A-Za-z0-9_]: a value that ran on
// without a separator is not a name, and treating it as one would swallow
// the rest of the payload looking for an '=' that never comes.
func isNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_', b == '-', b == '.':
		return true
	}
	return false
}

// matchFieldName returns the longest credential field name starting at i in
// the original string, with its length, or ("", 0). The lowercased form is
// passed alongside because matching is case-insensitive -- "api_key",
// "apiKey" and "APIKEY" are one key here.
//
// A name only counts at the start of a token, or at a camelCase boundary.
// "compass=1" must not lose its value to the "pass" inside it, so a match
// mid-word needs an uppercase letter to start it -- which is exactly what a
// camelCase field name has and a lowercase word does not. That is the whole
// reason matchFieldName takes both strings: the lowercased form cannot tell
// loginPassword from loginpassword, and only the first is a field name
// anyone writes.
func matchFieldName(raw, lower string, i int) (string, int) {
	best := ""
	if i > 0 && !isNameStart(raw, lower, i) {
		return "", 0
	}
	for _, name := range redactFieldKeys {
		if len(name) > len(best) && strings.HasPrefix(lower[i:], name) {
			best = name
		}
	}
	return best, len(best)
}

// isNameStart reports whether position i begins a field name rather than
// sitting in the middle of one.
func isNameStart(raw, lower string, i int) bool {
	switch lower[i-1] {
	case ' ', '\t', '\n', '\r', '"', '\'', '=', ':', '<', '[', '{', ',', ';', '&', '?':
		return true
	}
	// A camelCase boundary: the character here is a letter and it is
	// capitalised. A lowercase match inside a word is still a word.
	return raw[i] >= 'A' && raw[i] <= 'Z'
}

// scanTo returns the first index at or after from holding one of the bytes
// in stops, or len(raw).
func scanTo(raw string, from int, stops string) int {
	for j := from; j < len(raw); j++ {
		if strings.IndexByte(stops, raw[j]) >= 0 {
			return j
		}
	}
	return len(raw)
}
