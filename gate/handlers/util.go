package handlers

import (
	"crypto/rand"
	"crypto/subtle"
)

func readRandom(b []byte) (int, error) {
	return rand.Read(b)
}

func subtleCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}
