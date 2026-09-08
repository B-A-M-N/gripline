package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func FuzzAuthenticatedPolicyEnvelope(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	f.Add([]byte(`{"version":1,"policy":{},"signature":"bad"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadAuthenticated(data, pub)
	})
}
