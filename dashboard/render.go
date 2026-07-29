package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
)

// nonce and secHeaders establish the auth-backend rendering security
// primitives. They are intentionally not enabled route-wide until the
// remaining inline dashboard scripts have moved behind nonce-bearing
// templates or external assets.
func nonce() string {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(fmt.Sprintf("generate CSP nonce: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func secHeaders(w http.ResponseWriter, nonceValue string) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'nonce-"+nonceValue+"'; "+
			"style-src 'self' 'nonce-"+nonceValue+"'; "+
			"img-src 'self' data: https://tile.openstreetmap.org; "+
			"connect-src 'self' https://tile.openstreetmap.org; "+
			"font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}
