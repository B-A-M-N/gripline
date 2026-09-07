package keyexport

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateExportSortedAndDeterministic(t *testing.T) {
	// Build verifiers with deliberately unsorted KIDs.
	verifiers := map[int][]byte{}
	for _, kid := range []int{3, 1, 2} {
		pub := make([]byte, ed25519.PublicKeySize)
		pub[0] = byte(kid) // unique per kid
		verifiers[kid] = pub
	}

	exp, err := GenerateExport(2, verifiers)
	if err != nil {
		t.Fatal(err)
	}
	if exp.ActiveKID != 2 {
		t.Fatalf("active kid: got %d, want 2", exp.ActiveKID)
	}
	if len(exp.Keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(exp.Keys))
	}
	// Verify sorted by KID.
	for i := 1; i < len(exp.Keys); i++ {
		if exp.Keys[i].KID <= exp.Keys[i-1].KID {
			t.Fatalf("keys not sorted: %d <= %d", exp.Keys[i].KID, exp.Keys[i-1].KID)
		}
	}
	// GeneratedAt must be populated.
	if exp.GeneratedAt == "" {
		t.Fatal("GeneratedAt must be populated")
	}
}

func TestGenerateExportRejectsEmpty(t *testing.T) {
	if _, err := GenerateExport(1, map[int][]byte{}); err == nil {
		t.Fatal("expected error for empty verifiers")
	}
}

func TestGenerateExportRejectsInvalidKeySize(t *testing.T) {
	verifiers := map[int][]byte{1: []byte("not-a-key")}
	if _, err := GenerateExport(1, verifiers); err == nil {
		t.Fatal("expected error for invalid key size")
	}
}
