package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"net/http"
	"net/url"
)

func readRandom(b []byte) (int, error) {
	return rand.Read(b)
}

func subtleCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}

// validSameOrigin allows same-origin POSTs without breaking non-JS form
// posts that omit Origin: exact Origin match wins, otherwise fall back to
// Referer scheme+host equality. Parse errors deny.
func validSameOrigin(r *http.Request, origin string) bool {
	if origin == "" {
		return false
	}
	if r.Header.Get("Origin") == origin {
		return true
	}
	if r.Header.Get("Origin") != "" {
		return false
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		return false
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return false
	}
	ou, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if ru.Scheme == "" || ru.Host == "" {
		return false
	}
	return ru.Scheme == ou.Scheme && ru.Host == ou.Host
}
