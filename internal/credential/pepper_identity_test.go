package credential

import "testing"

func TestPepperClusterIdentityFingerprintAndActiveGeneration(t *testing.T) {
	one, err := NewPepperRing(
		&PepperKey{Version: 1, Key: []byte("pepper-key-one")},
		&PepperKey{Version: 2, Key: []byte("pepper-key-two")},
	)
	if err != nil {
		t.Fatal(err)
	}
	two, err := NewPepperRing(
		&PepperKey{Version: 2, Key: []byte("pepper-key-two")},
		&PepperKey{Version: 1, Key: []byte("pepper-key-one")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if one.Fingerprint() != two.Fingerprint() {
		t.Fatal("same loaded pepper generations must have the same fingerprint")
	}
	if one.ActiveVersion() != 2 {
		t.Fatalf("default active pepper version=%d, want 2", one.ActiveVersion())
	}
	if err := one.SetActiveVersion(1); err != nil {
		t.Fatal(err)
	}
	if one.ActiveVersion() != 1 {
		t.Fatalf("selected active pepper version=%d, want 1", one.ActiveVersion())
	}
	if err := one.SetActiveVersion(3); err == nil {
		t.Fatal("unloaded pepper generation must be rejected")
	}
}
