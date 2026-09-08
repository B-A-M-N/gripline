package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func FuzzVerifyAssertionEnvelope(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_700_000_000, 0)
	set, _ := NewKeySet(map[int]ed25519.PublicKey{1: pub}, 1)
	v, _ := New(set, "provider")
	f.Add(testToken(f, priv, testClaims(now)))
	f.Fuzz(func(t *testing.T, token string) {
		v.WithClock(func() time.Time { return now })
		r := httptest.NewRequest("POST", "http://backend/v1/messages", nil)
		r.Header.Set(AssertionHeader, token)
		_, _ = v.Verify(r)
	})
}

func FuzzLoadKeySet(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	set, _ := NewKeySet(map[int]ed25519.PublicKey{1: pub}, 1)
	seed, _ := json.Marshal(set)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadKeySet(bytes.NewReader(data))
	})
}
