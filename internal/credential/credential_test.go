package credential

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/freeinference/gripline/internal/secret"
)

// testKey is a pepper key used across tests.
func testKey() *PepperKey { return &PepperKey{Version: 1, Key: []byte("test-pepper-1")} }

// newNormalRecord creates a normal, active record with a derived verifier.
func newNormalRecord(id, account string, pep *PepperKey) (*CredentialRecord, *secret.SealedSecret) {
	raw, _ := secret.Random(32)
	rec := &CredentialRecord{
		CredentialID:    id,
		AccountID:       account,
		Verifier:        Verifier(raw, pep),
		VerifierVersion: 1,
		PepperVersion:   pep.Version,
		Status:          StatusNormal,
		PolicyID:        "fi-default-v1",
		PlanID:          "plan-a",
		CreatedAt:       time.Now().Add(-time.Hour),
		Revision:        1,
	}
	return rec, raw
}

func TestVerifierDoesNotContainRaw(t *testing.T) {
	raw, _ := secret.Random(16)
	pep := testKey()
	v := Verifier(raw, pep)
	if bytes.Contains(v, raw.Digest()) {
		t.Fatal("verifier must not be derivable back to the secret")
	}
}

func TestValidateSuccessAndDRotation(t *testing.T) {
	pep1 := testKey()
	rec, raw := newNormalRecord("cred_1", "acct_1", pep1)

	// Ring with both the original and a newer pepper (migration).
	pep2 := &PepperKey{Version: 2, Key: []byte("newer-pepper-2")}
	ring := NewPepperRing(pep1, pep2)

	got, err := ring.Validate(raw, rec)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.CredentialID != "cred_1" || got.AccountID != "acct_1" {
		t.Fatalf("wrong resolution: %+v", got)
	}
	raw.Zero()
}

func TestValidateFailsForWrongSecret(t *testing.T) {
	pep := testKey()
	rec, _ := newNormalRecord("cred_2", "acct_2", pep)
	wrong, _ := secret.Random(32)
	defer wrong.Zero()
	if _, err := NewPepperRing(pep).Validate(wrong, rec); err != UnknownError {
		t.Fatalf("expected UnknownError, got %v", err)
	}
}

// TestRevokedNeverAuthenticates is INV-13.
func TestRevokedNeverAuthenticates(t *testing.T) {
	pep := testKey()
	rec, raw := newNormalRecord("cred_3", "acct_3", pep)
	defer raw.Zero()
	rec.Status = StatusRevoked
	if _, err := NewPepperRing(pep).Validate(raw, rec); err != RevokedError {
		t.Fatalf("expected RevokedError, got %v", err)
	}
}

// TestRegistryNeverStoresRaw is INV-1: the registry persists only the verifier.
func TestRegistryNeverStoresRaw(t *testing.T) {
	pep := testKey()
	rec, raw := newNormalRecord("cred_4", "acct_4", pep)
	defer raw.Zero()

	reg := NewMemoryRegistry()
	reg.Insert(rec)

	// The raw secret must never appear in what the registry retains.
	// Invert: the verifier IS in storage; raw digest is not, and there is no
	// field carrying raw bytes. Assert via field presence.
	stored, _ := reg.Lookup("cred_4")
	if len(stored.Verifier) == 0 {
		t.Fatal("verifier must be stored")
	}
	if stored.AccountID == "" {
		t.Fatal("account missing")
	}
	// No raw-key field exists on the persisted record type.
	if strings.Contains(recordFieldNames(), "RawKey") || strings.Contains(recordFieldNames(), "Secret") {
		t.Fatal("CredentialRecord must not carry a raw-key field (INV-1)")
	}
}

func TestMemoryRegistryRevokeAndRevision(t *testing.T) {
	pep := testKey()
	rec, _ := newNormalRecord("cred_5", "acct_5", pep)
	reg := NewMemoryRegistry()
	reg.Insert(rec)

	if err := reg.Revoke("cred_5"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	st, _ := reg.Lookup("cred_5")
	if st.Status != StatusRevoked {
		t.Fatal("status must be revoked after Revoke")
	}
	if st.Revision != rec.Revision+1 {
		t.Fatalf("revision not bumped: got %d want %d", st.Revision, rec.Revision+1)
	}
	if err := reg.Revoke("nope"); err != ErrNotFound {
		t.Fatalf("revoke missing id should return ErrNotFound, got %v", err)
	}
}

// --- Hysteresis tests (spec §31) --------------------------------------------

func newSM(now *time.Time) *StateMachine {
	return NewStateMachine(DefaultHysteresis(), func() time.Time { return *now })
}

func TestHysteresisNormalToWatchNeedsTwoObservations(t *testing.T) {
	now := time.Now()
	sm := newSM(&now)
	if sm.Observe(10) != StatusNormal {
		t.Fatal("low risk stays NORMAL")
	}
	if sm.Observe(40) != StatusNormal {
		t.Fatal("single high obs must not trigger WATCH (needs 2)")
	}
	if sm.Observe(40) != StatusWatch {
		t.Fatal("two qualifying obs should enter WATCH")
	}
}

func TestHysteresisWatchToConstrainedToQuarantine(t *testing.T) {
	now := time.Now()
	sm := newSM(&now)
	// force into WATCH
	sm.Observe(40)
	sm.Observe(40)
	if sm.Status() != StatusWatch {
		t.Fatal("should be WATCH")
	}
	// score >= 55 → CONSTRAINED
	if sm.Observe(60) != StatusConstrained {
		t.Fatal("score >= 55 should move to CONSTRAINED")
	}
	// score >= 80 → QUARANTINED
	if sm.Observe(90) != StatusQuarantined {
		t.Fatal("score >= 80 should move to QUARANTINED")
	}
	// quarantine does not auto recover
	if sm.Observe(0) != StatusQuarantined {
		t.Fatal("quarantine requires explicit action")
	}
}

func TestHysteresisConstrainedToWatchAfterDwell(t *testing.T) {
	now := time.Now()
	sm := newSM(&now)
	sm.Observe(40)
	sm.Observe(40) // WATCH
	sm.Observe(60) // CONSTRAINED
	if sm.Status() != StatusConstrained {
		t.Fatal("should be CONSTRAINED")
	}
	// drop below 40 but dwell not elapsed → still CONSTRAINED
	sm.Observe(30)
	if sm.Status() != StatusConstrained {
		t.Fatal("short low-risk dip must not downgrade before dwell")
	}
	// advance past dwell
	now = now.Add(16 * time.Minute)
	sm.Observe(30)
	if sm.Status() != StatusWatch {
		t.Fatalf("after dwell at low risk should return to WATCH, got %v", sm.Status())
	}
}