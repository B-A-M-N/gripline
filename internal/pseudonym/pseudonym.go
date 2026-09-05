// Package pseudonym provides keyed HMAC transforms for the long-term,
// privacy-preserving identifiers Gripline retains: source IDs and
// invalid-credential fingerprints. These use a keyed transform — never a raw
// hash of the input — so values are not trivially enumerable (§45, §73).
//
// The abuse-detection key used here MUST be distinct from the credential
// verifier pepper key (spec §45). Rotation is supported by carrying a key
// version and accepting past versions for verification.
package pseudonym

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Key is a keyed transform key with a version tag.
type Key struct {
	Version int
	// Secret is the HMAC key material. For production this lives in a secret
	// store, distinct from the verifier pepper key.
	Secret []byte
}

// Family distinguishes identifier domains so the same raw value in different
// contexts yields different pseudonyms.
type Family string

const (
	// FamilySource is used for source identifiers (normalized network identity).
	FamilySource Family = "source"
	// FamilyInvalidCred is used for short-lived invalid-credential fingerprints
	// (key-spray cardinality).
	FamilyInvalidCred Family = "invalid-cred"
)

// Ring holds the active pseudonym keys by version.
type Ring struct {
	active map[int][]byte
}

// NewRing builds a Ring from one or more keys (latest wins for new psys).
func NewRing(keys ...*Key) *Ring {
	r := &Ring{active: make(map[int][]byte, len(keys))}
	for _, k := range keys {
		if k != nil {
			r.active[k.Version] = k.Secret
		}
	}
	return r
}

// latest returns the highest configured key version.
func (r *Ring) latest() int {
	best := -1
	for v := range r.active {
		if v > best {
			best = v
		}
	}
	return best
}

// keyFor returns the key bytes for a version.
func (r *Ring) keyFor(v int) ([]byte, bool) {
	k, ok := r.active[v]
	return k, ok
}

// Derive produces the base64url pseudonym for the given family + raw input,
// under the latest configured key version. The result is prefixed so different
// families on the same raw value never collide.
func (r *Ring) Derive(family Family, raw []byte) string {
	v := r.latest()
	k, _ := r.keyFor(v)
	h := hmac.New(sha256.New, k)
	_, _ = h.Write([]byte(fmt.Sprintf("gripline:%s:v%d:", family, v)))
	_, _ = h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Verify recomputes the pseudonym under every active key version and reports
// whether any matches the presented value — supporting key rotation.
func (r *Ring) Verify(family Family, raw []byte, value string) bool {
	for v := range r.active {
		if r.deriveWith(family, raw, v) == value {
			return true
		}
	}
	return false
}

func (r *Ring) deriveWith(family Family, raw []byte, v int) string {
	k, ok := r.keyFor(v)
	if !ok {
		return ""
	}
	h := hmac.New(sha256.New, k)
	_, _ = h.Write([]byte(fmt.Sprintf("gripline:%s:v%d:", family, v)))
	_, _ = h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
