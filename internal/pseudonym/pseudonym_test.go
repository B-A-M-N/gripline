package pseudonym

import (
	"testing"
)

func testRing() *Ring {
	return NewRing(&Key{Version: 1, Secret: []byte("pseudonym-test-key-1")})
}

func TestDeriveIsKeyedNotPlainHash(t *testing.T) {
	r := testRing()
	// Same raw under different keys → different pseudonym.
	other := NewRing(&Key{Version: 2, Secret: []byte("a-different-key")})
	if r.Derive(FamilySource, []byte("1.2.3.4")) == other.Derive(FamilySource, []byte("1.2.3.4")) {
		t.Fatal("different keys must produce different pseudonyms")
	}
}

func TestFamilySeparation(t *testing.T) {
	r := testRing()
	raw := []byte("shared-input")
	if r.Derive(FamilySource, raw) == r.Derive(FamilyInvalidCred, raw) {
		t.Fatal("different families must not collide")
	}
}

func TestVerifySupportsRotation(t *testing.T) {
	k1 := &Key{Version: 1, Secret: []byte("key-v1")}
	k2 := &Key{Version: 2, Secret: []byte("key-v2")}
	r := NewRing(k1, k2)
	raw := []byte("some-source-identity")
	atV1 := NewRing(k1).Derive(FamilySource, raw)
	// A value minted under v1 must verify under the rotated ring holding both.
	if !r.Verify(FamilySource, raw, atV1) {
		t.Fatal("rotated ring must verify a v1-minted pseudonym")
	}
}

func TestVerifyRejectsWrongValue(t *testing.T) {
	r := testRing()
	if r.Verify(FamilySource, []byte("input"), "decoy") {
		t.Fatal("wrong value must fail verification")
	}
}
