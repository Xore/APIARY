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
			// Markup puts ANOTHER attribute between the field name and the
			// value. `name="password" value="..."` is how every HTML form
			// in the fleet spells a login field, and giving up here wrote
			// the name, saw a 'v', and left the secret in the body. The
			// separator is the next `=` on the same tag, reached over one
			// attribute name.
			eq := markupValueSeparator(raw, i)
			if eq < 0 {
				continue
			}
			b.WriteString(raw[i:eq])
			i = eq
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

// markupValueSeparator returns the index of the `=` that introduces an
// attribute's value, when from sits on an attribute NAME rather than on a
// separator -- the `value="..."` in `<input name="password" value="...">`.
// It returns -1 when no such `=` exists before the tag ends.
//
// The scan is bounded to the current tag on purpose. An unbounded one would
// let a credential field name in one element reach into the value of a later
// one, and the job here is to replace a value that belongs to a name, not to
// rewrite the document around it.
func markupValueSeparator(raw string, from int) int {
	for j := from; j < len(raw); j++ {
		switch raw[j] {
		case '>', '\n', '\r', '<':
			return -1
		case '=':
			// The `=` has to introduce a value rather than close an
			// attribute name, so the byte before it must end a name.
			if j == from || !isNameByte(raw[j-1]) {
				return -1
			}
			return j
		}
		if !isNameByte(raw[j]) && raw[j] != '-' && raw[j] != '"' && raw[j] != '\'' {
			return -1
		}
	}
	return -1
}

// redactMultipart scrubs the value of every multipart part whose field name
// is credential-shaped, leaving the part headers, the name, the delimiters
// and the trailing newline exactly as they arrived -- the stored body still
// parses as the multipart that was sent, which is the whole reason to rewrite
// values in place rather than drop the parts.
//
// Multipart is not an exotic shape. A login form posted as multipart is what
// `curl --form` produces, what every HTML form declaring
// enctype="multipart/form-data" produces, and what a large share of the
// scanners that find this decoy produce. It leaked for a structural reason
// rather than a subtle one: in multipart the field name and its value are
// separated by a blank LINE, not by an `=`, so the key/value scrubber had no
// separator to act on and passed the body through with the password in it.
func redactMultipart(raw, boundary string) (string, bool) {
	if raw == "" || boundary == "" {
		return raw, false
	}
	delim := "--" + boundary
	segments := strings.Split(raw, delim)
	found := false
	for i, part := range segments {
		// Whatever precedes the first delimiter is preamble, and a closing
		// delimiter ("--boundary--") introduces no part at all. Both are
		// returned byte-identical.
		if i == 0 || strings.HasPrefix(part, "--") {
			continue
		}
		scrubbed, hit := redactMultipartPart(part)
		segments[i] = scrubbed
		found = found || hit
	}
	if !found {
		return raw, false
	}
	return strings.Join(segments, delim), found
}

// redactMultipartPart scrubs one part. The field name lives in the part's
// headers; the value is everything after the blank line that ends them.
func redactMultipartPart(part string) (string, bool) {
	split := multipartHeaderEnd(part)
	if split < 0 {
		return part, false
	}
	headers, rest := part[:split], part[split:]
	name, ok := multipartFieldName(headers)
	if !ok || !isCredentialField(name, false) {
		return part, false
	}
	// The value runs to the newline that precedes the next delimiter, which
	// is the trailing whitespace this part still carries. It is written back
	// so a redacted part has the same shape as the one that arrived.
	_, trailing := trimTrailingNewline(rest)
	return headers + redactMarker + trailing, true
}

// multipartHeaderEnd returns the index just past the blank line that ends a
// part's headers, or -1 when the part has no header block.
func multipartHeaderEnd(part string) int {
	if i := strings.Index(part, "\r\n\r\n"); i >= 0 {
		return i + 4
	}
	if i := strings.Index(part, "\n\n"); i >= 0 {
		return i + 2
	}
	return -1
}

// multipartFieldName returns the name= parameter of a part's
// Content-Disposition header, quoted or not.
//
// "filename=" contains "name=" as a substring and a part's filename is not a
// credential field name, so the match is only taken where a real parameter
// name would be -- after a space, a semicolon or a colon.
func multipartFieldName(headers string) (string, bool) {
	lower := strings.ToLower(headers)
	for i := 0; ; {
		j := strings.Index(lower[i:], "name=")
		if j < 0 {
			return "", false
		}
		at := i + j
		if at > 0 && (isNameByte(lower[at-1]) || lower[at-1] == '-') {
			i = at + 1
			continue
		}
		rest := headers[at+len("name="):]
		if rest == "" {
			return "", false
		}
		if q := rest[0]; q == '"' || q == '\'' {
			end := strings.IndexByte(rest[1:], q)
			if end < 0 {
				return "", false
			}
			return rest[1 : 1+end], true
		}
		end := 0
		for end < len(rest) && isNameByte(rest[end]) {
			end++
		}
		if end == 0 {
			return "", false
		}
		return rest[:end], true
	}
}

// multipartBoundary returns the boundary parameter of a multipart
// Content-Type, or "" when it declares none. Without one there is no
// delimiter to split on, and the caller falls back to the general scrubber
// rather than guessing where a part ends.
func multipartBoundary(contentType string) string {
	// The key is matched case-insensitively, but the VALUE is returned
	// exactly as it arrived: a multipart boundary is case-sensitive, and
	// lowercasing it here finds no delimiter in a body that used `--X`.
	for _, param := range strings.Split(contentType, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || !strings.EqualFold(key, "boundary") || value == "" {
			continue
		}
		return strings.Trim(value, `"`)
	}
	return ""
}

// trimTrailingNewline splits s into its content and the trailing CR/LF run
// that belongs to the framing rather than to the value.
func trimTrailingNewline(s string) (body, trailing string) {
	cut := len(s)
	for cut > 0 && (s[cut-1] == '\n' || s[cut-1] == '\r') {
		cut--
	}
	return s[:cut], s[cut:]
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
	case '"', '\'':
		// The candidate sits inside a quoted run, and in markup that run is
		// an attribute's value. The only HTML attribute whose value is a
		// field name is name= -- `<input name="password" value="...">` --
		// so everything else inside quotes is a value and not a name.
		//
		// This is not a harmless false positive to allow. `<input
		// type="password" name="password" value="...">` read as one field
		// named "password" takes the `=` of name= as its value separator,
		// rewrites the name into the marker, and walks the cursor past the
		// real value= the secret was in -- so the scrubber reported a hit
		// and the password went into the log.
		return quotedRunIsAFieldName(raw, lower, i-1, i)
	case ' ', '\t', '\n', '\r', '=', ':', '<', '[', '{', ',', ';', '&', '?':
		return true
	}
	// A camelCase boundary: the character here is a letter and it is
	// capitalised. A lowercase match inside a word is still a word.
	return raw[i] >= 'A' && raw[i] <= 'Z'
}

// quotedRunIsAFieldName reports whether the candidate at `at` -- which sits
// inside the quoted run opening at q -- is a field name rather than a word
// that happens to look like one.
//
// Two shapes inside quotes carry a field name and one does not:
//
//   - `name="password"`: the run IS the field name, because name= is the one
//     HTML attribute whose value is a field.
//   - `filename="password=..."`: the run is a value, and the field name and
//     its separator are both inside it. This is how a credential gets
//     reflected back through a header nobody reads, so it counts.
//   - `type="password"`: the run is a value with no separator in it. It
//     declares what kind of box the input is and holds no credential.
//
// The third shape is not a harmless false positive to allow. `<input
// type="password" name="password" value="...">` read as one field named
// "password" takes the `=` of name= as its value separator, rewrites the
// name into the marker, and walks the cursor past the real value= the secret
// was in -- so the scrubber reported a hit and the password went to the log.
func quotedRunIsAFieldName(raw, lower string, q, at int) bool {
	if q <= 0 || raw[q-1] != '=' {
		// Not `ident="..."` at all: a JSON key (`{"password":...}`), a form
		// value, a bare token. A key IS a field name, which is the case
		// this function was asked about. The rules below are only about
		// markup, because markup is the one shape where a key and a value
		// look identical on the wire.
		return true
	}
	attr := q - 1
	for attr > 0 && isNameByte(raw[attr-1]) {
		attr--
	}
	if strings.EqualFold(lower[attr:q-1], "name") {
		return true
	}
	// Otherwise the run is a value. A value carrying `name=` inside it is
	// carrying a credential field name: `filename="password=..."` is how a
	// credential gets reflected back through a header nobody reads.
	end := scanQuoted(raw, q) - 1
	if end > len(raw) {
		end = len(raw)
	}
	for j := at; j < end; j++ {
		if raw[j] == '=' {
			// A separator introducing a value, not `==` in a C snippet or
			// the `=>` of a JSON merge patch.
			return j+1 < len(raw) && raw[j+1] != '=' && raw[j+1] != '>'
		}
	}
	return false
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
