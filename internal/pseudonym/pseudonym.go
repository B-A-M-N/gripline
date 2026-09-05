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
// Keys with empty secret material or negative versions are refused: an HMAC
// under an empty key is publicly computable, which would silently turn the
// pseudonym into an enumerable value (§45, §73 — the exact failure this
// package exists to prevent). Key material is COPIED on ingestion so later
// mutation of the caller's slice cannot alter live keys. A Ring built from
// only invalid keys errors rather than failing open into an unkeyed transform.
func NewRing(keys ...*Key) (*Ring, error) {
	r := &Ring{active: make(map[int][]byte, len(keys))}
	for _, k := range keys {
		if k == nil {
			continue
		}
		if k.Version < 0 {
			return nil, fmt.Errorf("pseudonym: negative key version %d", k.Version)
		}
		if len(k.Secret) == 0 {
			return nil, fmt.Errorf("pseudonym: key version %d has empty secret", k.Version)
		}
		if _, dup := r.active[k.Version]; dup {
			return nil, fmt.Errorf("pseudonym: duplicate key version %d", k.Version)
		}
		r.active[k.Version] = append([]byte(nil), k.Secret...)
	}
	if len(r.active) == 0 {
		return nil, fmt.Errorf("pseudonym: ring requires at least one keyed version")
	}
	return r, nil
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
// families on the same raw value never collide. The raw input must be
// non-empty; deriving from an empty value would let every empty input share
// one pseudonym and would mask upstream extraction bugs.
func (r *Ring) Derive(family Family, raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("pseudonym: empty input")
	}
	v := r.latest()
	k, ok := r.keyFor(v)
	if !ok || len(k) == 0 {
		// Unreachable after NewRing validation; kept as a guard so a future
		// mutation can never reintroduce an unkeyed transform.
		return "", fmt.Errorf("pseudonym: no key for version %d", v)
	}
	return deriveWith(family, raw, v, k), nil
}

// Verify recomputes the pseudonym under every active key version and reports
// whether any matches the presented value — supporting key rotation.
func (r *Ring) Verify(family Family, raw []byte, value string) bool {
	if len(raw) == 0 {
		return false
	}
	for v, k := range r.active {
		if deriveWith(family, raw, v, k) == value {
			return true
		}
	}
	return false
}

// deriveWith is the single keyed-transform implementation; every derive path
// funnels through it so the keying is enforced in one place.
func deriveWith(family Family, raw []byte, v int, k []byte) string {
	h := hmac.New(sha256.New, k)
	_, _ = h.Write([]byte(fmt.Sprintf("gripline:%s:v%d:", family, v)))
	_, _ = h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
