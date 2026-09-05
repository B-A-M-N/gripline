package secret

import (
	"crypto/hmac"
	"crypto/sha256"
)

// digestFor computes the plain SHA-256 of b; used in tests to cross-check the
// non-keyed Digest().
func digestFor(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// hmacSHA256 folds parts under key; used to cross-check DigestHMAC.
func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = m.Write(p)
	}
	return m.Sum(nil)
}
