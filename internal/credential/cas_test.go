package credential

import (
	"sync"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/secret"
)

// TestCASStatusMutation tests UpdateStatusCAS behavior.
func TestCASStatusMutation(t *testing.T) {
	reg := NewMemoryRegistry()
	pep := &PepperKey{Version: 1, Key: []byte("pepper")}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte('a' + i%26)
	}
	sealed := secret.NewFromBytes(raw)

	if err := reg.Insert(&CredentialRecord{
		CredentialID: "cred_1", AccountID: "acct_1",
		Verifier: Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: StatusNormal, PolicyID: "pol_1", PlanID: "plan_1",
		CreatedAt: time.Now(), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// Normal → Watch via CAS.
	rec, err := reg.UpdateStatusCAS("cred_1", 1, StatusNormal, StatusWatch)
	if err != nil {
		t.Fatalf("CAS succeeded: %v", err)
	}
	if rec.Status != StatusWatch {
		t.Fatalf("expected WATCH, got %v", rec.Status)
	}
	if rec.Revision != 2 {
		t.Fatalf("expected revision 2, got %d", rec.Revision)
	}

	// Second CAS uses the new revision (revision bumped to 2 by first CAS).
	rec, err = reg.UpdateStatusCAS("cred_1", rec.Revision, StatusWatch, StatusConstrained)
	if err != nil {
		t.Fatalf("CAS with correct revision succeeded: %v", err)
	}
	if rec.Status != StatusConstrained {
		t.Fatalf("expected CONSTRAINED, got %v", rec.Status)
	}

	// Stale revision fails.
	_, err = reg.UpdateStatusCAS("cred_1", 1, StatusNormal, StatusRevoked)
	if err != ErrStaleCAS {
		t.Fatalf("expected ErrStaleCAS, got %v", err)
	}

	// Wrong from-status fails.
	_, err = reg.UpdateStatusCAS("cred_1", 2, StatusWatch, StatusRevoked)
	if err != ErrStaleCAS {
		t.Fatalf("expected ErrStaleCAS for wrong from-status, got %v", err)
	}

	// CONSTRAINED → QUARANTINED (escalation is fine).
	rec, err = reg.UpdateStatusCAS("cred_1", rec.Revision, StatusConstrained, StatusQuarantined)
	if err != nil {
		t.Fatalf("CONSTRAINED → QUARANTINED should succeed: %v", err)
	}
	// Now try to downgrade from QUARANTINED.
	_, err = reg.UpdateStatusCAS("cred_1", rec.Revision, StatusQuarantined, StatusNormal)
	if err == nil {
		t.Fatal("QUARANTINED downgrade must be rejected")
	}

	// REVOKED is terminal.
	reg.Revoke("cred_1")
	_, err = reg.UpdateStatusCAS("cred_1", 4, StatusRevoked, StatusNormal)
	if err == nil {
		t.Fatal("REVOKED must be terminal")
	}
}

// TestCASNoOpRejected tests that updating to the same status is rejected.
func TestCASNoOpRejected(t *testing.T) {
	reg := NewMemoryRegistry()
	pep := &PepperKey{Version: 1, Key: []byte("pepper")}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte('a' + i%26)
	}
	sealed := secret.NewFromBytes(raw)

	reg.Insert(&CredentialRecord{
		CredentialID: "cred_c", AccountID: "acct_1",
		Verifier: Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: StatusNormal, PolicyID: "pol_1", PlanID: "plan_1",
		CreatedAt: time.Now(), Revision: 1,
	})

	_, err := reg.UpdateStatusCAS("cred_c", 1, StatusNormal, StatusNormal)
	if err == nil {
		t.Fatal("no-op CAS must be rejected")
	}
}

// TestCASNotFound tests UpdateStatusCAS for absent credentials.
func TestCASNotFound(t *testing.T) {
	reg := NewMemoryRegistry()
	_, err := reg.UpdateStatusCAS("nonexistent", 0, StatusNormal, StatusWatch)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestCASConcurrent tests concurrent CAS for the same credential.
func TestCASConcurrent(t *testing.T) {
	reg := NewMemoryRegistry()
	pep := &PepperKey{Version: 1, Key: []byte("pepper")}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte('a' + i%26)
	}
	sealed := secret.NewFromBytes(raw)

	reg.Insert(&CredentialRecord{
		CredentialID: "cred_concurrent", AccountID: "acct_1",
		Verifier: Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: StatusNormal, PolicyID: "pol_1", PlanID: "plan_1",
		CreatedAt: time.Now(), Revision: 1,
	})

	var wg sync.WaitGroup
	successes := 0
	var mu sync.Mutex
	failures := 0

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// All goroutines try the same revision.
			rec, err := reg.UpdateStatusCAS("cred_concurrent", 1, StatusNormal, StatusWatch)
			if err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
				return
			}
			mu.Lock()
			successes++
			mu.Unlock()
			if rec.Status != StatusWatch {
				t.Error("expected WATCH on success")
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("exactly one CAS must succeed: got %d successes, %d failures", successes, failures)
	}
}
