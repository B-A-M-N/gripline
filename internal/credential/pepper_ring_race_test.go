package credential

import (
	"sync"
	"testing"

	"github.com/B-A-M-N/gripline/internal/secret"
)

func TestPepperRingConcurrentReadersAndRetirement(t *testing.T) {
	pepperOne := &PepperKey{Version: 1, Key: []byte("race-pepper-one")}
	pepperTwo := &PepperKey{Version: 2, Key: []byte("race-pepper-two")}
	ring, err := NewPepperRing(pepperOne, pepperTwo)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := secret.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Zero()
	record := &CredentialRecord{
		CredentialID: "race-credential", AccountID: "race-account", Status: StatusNormal,
		Verifier: Verifier(raw, pepperOne), VerifierVersion: 1, PepperVersion: 1,
		PolicyID: "gripline-default-v1", PlanID: "race", Revision: 1,
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				_ = ring.DeriveVerifier(raw, 1)
				_ = ring.DeriveSprayPseudonym(raw, ring.ActiveVersion())
				_ = ring.DeriveAllActiveVerifiers(raw)
				_, _ = ring.Validate(raw, record)
				_ = ring.Latest()
				_ = ring.Versions()
				_ = ring.Fingerprint()
				_, _ = ring.VersionFingerprint(2)
				_ = ring.VersionFingerprints()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ring.SetActiveVersion(2); err != nil {
			t.Errorf("activate pepper: %v", err)
		}
		if err := ring.RetireVersion(1); err != nil {
			t.Errorf("retire pepper: %v", err)
		}
	}()
	wg.Wait()
	if got := ring.Versions(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("retired ring versions = %v, want [2]", got)
	}
}
