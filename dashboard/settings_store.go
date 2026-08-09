package main

// settings_store.go — shared helpers and sentinel errors for the dashboard's
// Elasticsearch-backed settings documents (roadmap §5). The actual store
// implementation lives in settings_store_es.go; this file only holds the
// pieces still shared by other, non-settings code (strictDecode is also
// used elsewhere for strict JSON decoding, and the sentinel errors are
// checked by HTTP handlers throughout the settings API).
//
// #787: this file used to describe a local-file store (atomicSettingsStore)
// with its own "if dashboard replicas are ever introduced, migrate to
// SQLite" TODO. Replicas were introduced (dashboard, dashboard-b) and that
// local-file store's in-memory cache never learned when the other replica
// wrote a change -- confirmed live, a settings toggle via one replica was
// invisible to the other until restart. The fix was Elasticsearch, not
// SQLite: it's the one backend both replicas already treat as shared source
// of truth. See settings_store_es.go's own header comment for the full
// design.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var (
	errStoreReadOnly = errors.New("settings store is read-only after a persistence failure")
	errStaleRevision = errors.New("settings were modified concurrently; reload and retry")
	errUnknownRecord = errors.New("no settings record for this subject")
)

// stripWeakPrefix removes a leading weak-validator marker ("W/") from an
// incoming If-Match value before comparing it against a freshly computed
// strong ETag. #177: every settings save through this store -- preferences
// and admin configuration alike -- failed as a false conflict, unconditionally,
// since the feature shipped, even for a single session on the very first
// attempt. Traced live (temporary server-side logging comparing the exact
// bytes): the client's If-Match arrived as `W/"r0-...` while this store's
// own freshly computed ETag was `"r0-...` -- byte-identical except for the
// weak marker. This dashboard never emits a weak ETag itself, so something
// in the proxy chain in front of it (Cloudflare and Traefik both sit in
// front, and both can transparently compress responses; either downgrading
// a strong validator to weak on a compressed response is standard proxy
// behavior, not a bug in that layer) added it on the way to the browser,
// which then dutifully echoed it back as If-Match. A naive byte-for-byte
// comparison against the freshly computed strong ETag never matches, even
// though the underlying value is identical. Stripping the marker before
// comparing is safe specifically because we control both ends: the "weak"
// value only ever differs from our own strong one by this exact prefix,
// added by an intermediary we trust, never by an actual different
// representation.
func stripWeakPrefix(etag string) string {
	if strings.HasPrefix(etag, "W/") {
		return etag[2:]
	}
	return etag
}

// maxSettingsBytes bounds a single settings document. Settings are small
// typed documents; anything larger is corruption or abuse.
const maxSettingsBytes = 1 << 20

// strictDecode unmarshals a single JSON document, rejecting unknown fields,
// trailing data, and malformed input.
func strictDecode(raw []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}
