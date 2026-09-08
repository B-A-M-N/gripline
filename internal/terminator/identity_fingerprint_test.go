package terminator

import "testing"

func TestPublicKeysetFingerprintChangesWithRotation(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	initial := keyring.PublicKeysetFingerprint()
	if len(initial) != 64 {
		t.Fatalf("fingerprint length=%d, want 64", len(initial))
	}
	if _, err := keyring.Rotate(); err != nil {
		t.Fatal(err)
	}
	if rotated := keyring.PublicKeysetFingerprint(); rotated == initial {
		t.Fatal("rotating signer must change the public-keyset fingerprint")
	}
}
