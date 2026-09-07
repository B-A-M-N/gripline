package secret

import (
	"crypto/hmac"
	"crypto/sha256"
)

// hmacSHA256 folds parts under key; used to cross-check DigestHMAC.
func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = m.Write(p)
	}
	return m.Sum(nil)
}
