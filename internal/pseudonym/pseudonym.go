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
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
)

// Key is a keyed transform key with a version tag.
type Key struct {
	Version int
	// Secret is the HMAC key material. For production this lives in a secret
	// store, distinct from the verifier pepper key.
	Secret []byte
}

// Format implements fmt.Formatter and always redacts (P0.38): formatting this
// key-bearing config struct must never reach the secret bytes. The ring copies
// the bytes at ingestion, so this construction-time handle is not retained.
func (k Key) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, "<redacted>")
}

// String implements fmt.Stringer (%s/%v).
func (k Key) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v).
func (k Key) GoString() string { return "<redacted>" }

var (
	_ fmt.Formatter  = Key{}
	_ fmt.Stringer   = Key{}
	_ fmt.GoStringer = Key{}
)

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
	active        map[int][]byte
	activeVersion int
}

// Format implements fmt.Formatter and always redacts (P0.16). VALUE receiver:
// the Ring holds live pseudonym key material (map[int][]byte); a struct copy
// must redact identically, not fall back to struct formatting.
func (r Ring) Format(f fmt.State, verb rune) { fmt.Fprint(f, "<redacted>") }

// String implements fmt.Stringer (value receiver, P0.16).
func (r Ring) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v; value receiver, P0.16).
func (r Ring) GoString() string { return "<redacted>" }

var (
	_ fmt.Formatter  = Ring{}
	_ fmt.Stringer   = Ring{}
	_ fmt.GoStringer = Ring{}
)

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
	if r.activeVersion > 0 {
		if _, ok := r.active[r.activeVersion]; ok {
			return r.activeVersion
		}
	}
	best := -1
	for v := range r.active {
		if v > best {
			best = v
		}
	}
	return best
}

// SetActiveVersion selects the cluster-authoritative generation for new
// pseudonyms. Older loaded generations remain available to Verify.
func (r *Ring) SetActiveVersion(version int) error {
	if r == nil {
		return fmt.Errorf("pseudonym: nil ring")
	}
	if _, ok := r.active[version]; !ok {
		return fmt.Errorf("pseudonym: key version %d is not loaded", version)
	}
	r.activeVersion = version
	return nil
}

// RetireVersion removes a non-active generation. Cluster callers must first
// prove that no persisted source aliases/scopes still depend on the
// generation; keeping this guard in the ring prevents an accidental local
// outage when the authority sequencing is bypassed.
func (r *Ring) RetireVersion(version int) error {
	if r == nil {
		return fmt.Errorf("pseudonym: nil ring")
	}
	if version == r.ActiveVersion() {
		return fmt.Errorf("pseudonym: cannot retire active key version %d", version)
	}
	if _, ok := r.active[version]; !ok {
		return fmt.Errorf("pseudonym: key version %d is not loaded", version)
	}
	delete(r.active, version)
	return nil
}

// ActiveVersion returns the generation used for new pseudonyms.
func (r *Ring) ActiveVersion() int { return r.latest() }

// Fingerprint returns a stable digest of all loaded pseudonym generations.
// The digest binds cluster configuration without exposing key material.
func (r *Ring) Fingerprint() string {
	if r == nil {
		return ""
	}
	versions := make([]int, 0, len(r.active))
	for version := range r.active {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	h := sha256.New()
	for _, version := range versions {
		_, _ = h.Write([]byte(strconv.Itoa(version)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(r.active[version])
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VersionFingerprint identifies one loaded pseudonym generation without
// exposing its secret. Cluster rotation uses this to distinguish staged
// capabilities from the currently active derivation generation.
func (r *Ring) VersionFingerprint(version int) (string, bool) {
	if r == nil {
		return "", false
	}
	key, ok := r.active[version]
	if !ok || len(key) == 0 {
		return "", false
	}
	h := sha256.New()
	_, _ = h.Write([]byte(strconv.Itoa(version)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(key)
	return hex.EncodeToString(h.Sum(nil)), true
}

// VersionFingerprints returns one safe fingerprint per loaded generation.
func (r *Ring) VersionFingerprints() map[int]string {
	if r == nil {
		return nil
	}
	out := make(map[int]string, len(r.active))
	for version := range r.active {
		if fingerprint, ok := r.VersionFingerprint(version); ok {
			out[version] = fingerprint
		}
	}
	return out
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

// DeriveAll returns one candidate per loaded generation in ascending version
// order. It is used by the clustered source resolver to find an existing
// pre-rotation source scope and preserve that source identity while the active
// key changes. The active Derive method remains the only default minting path.
func (r *Ring) DeriveAll(family Family, raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("pseudonym: empty input")
	}
	versions := make([]int, 0, len(r.active))
	for version := range r.active {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	out := make([]string, 0, len(versions))
	for _, version := range versions {
		key := r.active[version]
		if len(key) == 0 {
			continue
		}
		out = append(out, deriveWith(family, raw, version, key))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pseudonym: no loaded key for derivation")
	}
	return out, nil
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
//
// The output is version-prefixed (P0.37): "v<N>.<b64>" so a store keyed by
// pseudonym can route a lookup to the key version that minted it, giving
// storage continuity across rotation instead of a wholesale re-key. Verify
// recomputes under every active version and matches the prefixed form, so a
// rotated ring still accepts the older-version value.
func deriveWith(family Family, raw []byte, v int, k []byte) string {
	h := hmac.New(sha256.New, k)
	_, _ = h.Write([]byte(fmt.Sprintf("gripline:%s:v%d:", family, v)))
	_, _ = h.Write(raw)
	return fmt.Sprintf("v%d.%s", v, base64.RawURLEncoding.EncodeToString(h.Sum(nil)))
}
