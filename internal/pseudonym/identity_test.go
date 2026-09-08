package pseudonym

import "testing"

func TestPseudonymClusterIdentityFingerprintAndActiveGeneration(t *testing.T) {
	one, err := NewRing(
		&Key{Version: 1, Secret: []byte("pseudonym-key-one")},
		&Key{Version: 2, Secret: []byte("pseudonym-key-two")},
	)
	if err != nil {
		t.Fatal(err)
	}
	two, err := NewRing(
		&Key{Version: 2, Secret: []byte("pseudonym-key-two")},
		&Key{Version: 1, Secret: []byte("pseudonym-key-one")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if one.Fingerprint() != two.Fingerprint() {
		t.Fatal("same loaded pseudonym generations must have the same fingerprint")
	}
	if one.ActiveVersion() != 2 {
		t.Fatalf("default active pseudonym version=%d, want 2", one.ActiveVersion())
	}
	if err := one.SetActiveVersion(1); err != nil {
		t.Fatal(err)
	}
	if one.ActiveVersion() != 1 {
		t.Fatalf("selected active pseudonym version=%d, want 1", one.ActiveVersion())
	}
	if err := one.SetActiveVersion(3); err == nil {
		t.Fatal("unloaded pseudonym generation must be rejected")
	}
}
