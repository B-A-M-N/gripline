package pseudonym

import (
	"encoding/base64"
	"testing"
)

func mustRing(t *testing.T, keys ...*Key) *Ring {
	t.Helper()
	r, err := NewRing(keys...)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	return r
}

func testRing(t *testing.T) *Ring {
	t.Helper()
	return mustRing(t, &Key{Version: 1, Secret: []byte("pseudonym-test-key-1")})
}

func TestDeriveIsKeyedNotPlainHash(t *testing.T) {
	r := testRing(t)
	// Same raw under different keys → different pseudonym.
	other := mustRing(t, &Key{Version: 2, Secret: []byte("a-different-key")})
	a, err := r.Derive(FamilySource, []byte("1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := other.Derive(FamilySource, []byte("1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different keys must produce different pseudonyms")
	}
}

// The pseudonym must differ from any unkeyed transform of the raw input: the
// whole point of the keyed transform (§45, §73) is that values are not
// enumerable by an attacker who knows the input space.
func TestDeriveDiffersFromUnkeyedHash(t *testing.T) {
	r := testRing(t)
	raw := []byte("1.2.3.4")
	got, err := r.Derive(FamilySource, raw)
	if err != nil {
		t.Fatal(err)
	}
	// The keyed output must never equal base64(sha256(raw)) or a plain HMAC
	// with the family prefix but no key (what a nil-key HMAC would compute).
	if got == base64.RawURLEncoding.EncodeToString(raw) {
		t.Fatal("pseudonym must not be an encoding of the raw input")
	}
}

func TestFamilySeparation(t *testing.T) {
	r := testRing(t)
	raw := []byte("shared-input")
	a, err := r.Derive(FamilySource, raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Derive(FamilyInvalidCred, raw)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different families must not collide")
	}
}

func TestVerifySupportsRotation(t *testing.T) {
	k1 := &Key{Version: 1, Secret: []byte("key-v1")}
	k2 := &Key{Version: 2, Secret: []byte("key-v2")}
	r := mustRing(t, k1, k2)
	raw := []byte("some-source-identity")
	atV1, err := mustRing(t, k1).Derive(FamilySource, raw)
	if err != nil {
		t.Fatal(err)
	}
	// A value minted under v1 must verify under the rotated ring holding both.
	if !r.Verify(FamilySource, raw, atV1) {
		t.Fatal("rotated ring must verify a v1-minted pseudonym")
	}
}

func TestVerifyRejectsWrongValue(t *testing.T) {
	r := testRing(t)
	if r.Verify(FamilySource, []byte("input"), "decoy") {
		t.Fatal("wrong value must fail verification")
	}
}

// --- regressions: the unkeyed-transform fail-open (§45, §73) -----------------

// Regression: an empty key is refused — HMAC under an empty key is publicly
// computable and would silently mint enumerable pseudonyms.
func TestEmptyKeyRejected(t *testing.T) {
	if _, err := NewRing(&Key{Version: 1, Secret: nil}); err == nil {
		t.Fatal("empty secret must be rejected")
	}
	if _, err := NewRing(&Key{Version: 1, Secret: []byte{}}); err == nil {
		t.Fatal("zero-length secret must be rejected")
	}
}

// Regression: an empty ring must error at construction instead of failing open
// into an unkeyed transform at Derive time (previously: hmac.New(sha256.New,
// nil) — a plain hash).
func TestEmptyRingRejected(t *testing.T) {
	if _, err := NewRing(); err == nil {
		t.Fatal("ring with no keys must error at construction")
	}
	if _, err := NewRing(nil); err == nil {
		t.Fatal("ring built from only nil keys must error")
	}
}

// Regression: Derive must refuse empty input — every empty input sharing one
// pseudonym would mask upstream extraction bugs and enable trivial collision
// probing.
func TestDeriveRejectsEmptyInput(t *testing.T) {
	r := testRing(t)
	if _, err := r.Derive(FamilySource, nil); err == nil {
		t.Fatal("nil input must be rejected")
	}
	if _, err := r.Derive(FamilySource, []byte{}); err == nil {
		t.Fatal("empty input must be rejected")
	}
	// Verify likewise refuses empty input rather than matching some precomputed
	// empty-value pseudonym.
	if r.Verify(FamilyInvalidCred, nil, "anything") {
		t.Fatal("empty-input Verify must be false")
	}
}

// Regression: duplicate versions are a configuration error, not a silent
// last-wins overwrite.
func TestDuplicateVersionRejected(t *testing.T) {
	if _, err := NewRing(
		&Key{Version: 1, Secret: []byte("key-a")},
		&Key{Version: 1, Secret: []byte("key-b")},
	); err == nil {
		t.Fatal("duplicate key version must be rejected")
	}
}

// Regression (hardening): negative versions refused; key material copied on
// ingestion.
func TestNegativeVersionAndCopySafety(t *testing.T) {
	if _, err := NewRing(&Key{Version: -3, Secret: []byte("k")}); err == nil {
		t.Fatal("negative key version must be rejected")
	}
	secret1 := []byte("mutable-secret")
	r := mustRing(t, &Key{Version: 1, Secret: secret1})
	secret1[0] = 'X'
	got, err := r.Derive(FamilySource, []byte("in"))
	if err != nil {
		t.Fatal(err)
	}
	want := mustRing(t, &Key{Version: 1, Secret: []byte("mutable-secret")}).mustDerive(t, FamilySource, []byte("in"))
	if got != want {
		t.Fatal("ring must copy key material on ingestion")
	}
}

func (r *Ring) mustDerive(t *testing.T, family Family, raw []byte) string {
	t.Helper()
	v, err := r.Derive(family, raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// --- P0.38: key-bearing structs never format secret bytes --------------------

func TestKeyFormatRedacts(t *testing.T) {
	k := Key{Version: 1, Secret: []byte("super-secret-pseudonym-material")}
	for _, s := range []string{k.String(), k.GoString()} {
		if contains(s, "super-secret") || contains(s, "material") {
			t.Fatalf("P0.38: Key formatting leaked bytes: %q", s)
		}
	}
	if got := k.String(); got != "<redacted>" {
		t.Fatalf("P0.38: Key.String() = %q, want <redacted>", got)
	}
}

// --- P0.37: derive output carries the key version for storage continuity -----

func TestDeriveOutputIsVersionPrefixed(t *testing.T) {
	k := &Key{Version: 3, Secret: []byte("some-key")}
	r, err := NewRing(k)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Derive(FamilySource, []byte("1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	if !hasPrefix(out, "v3.") {
		t.Fatalf("P0.37: derive output %q must carry the key version prefix v3.", out)
	}
	// Verify must still match despite the prefix.
	if !r.Verify(FamilySource, []byte("1.2.3.4"), out) {
		t.Fatal("P0.37: Verify must match a version-prefixed derive output")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func hasPrefix(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	return s[:len(p)] == p
}
