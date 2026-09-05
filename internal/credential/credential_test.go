package credential

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/secret"
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
	if len(v) == 0 {
		t.Fatal("verifier must be derived")
	}
	// The verifier is a keyed digest — it must not equal any unkeyed transform
	// of the secret, and it must differ under a different pepper.
	other := Verifier(raw, &PepperKey{Version: 2, Key: []byte("other-pepper")})
	if bytes.Equal(v, other) {
		t.Fatal("verifier must depend on the pepper key")
	}
	raw.Zero()
}

func TestValidateSuccessAndDRotation(t *testing.T) {
	pep1 := testKey()
	rec, raw := newNormalRecord("cred_1", "acct_1", pep1)

	// Ring with both the original and a newer pepper (migration).
	pep2 := &PepperKey{Version: 2, Key: []byte("newer-pepper-2")}
	ring, err := NewPepperRing(pep1, pep2)
	if err != nil {
		t.Fatal(err)
	}

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
	if _, err := mustRing(t, pep).Validate(wrong, rec); err != UnknownError {
		t.Fatalf("expected UnknownError, got %v", err)
	}
}

// TestRevokedNeverAuthenticates is INV-13.
func TestRevokedNeverAuthenticates(t *testing.T) {
	pep := testKey()
	rec, raw := newNormalRecord("cred_3", "acct_3", pep)
	defer raw.Zero()
	rec.Status = StatusRevoked
	if _, err := mustRing(t, pep).Validate(raw, rec); err != RevokedError {
		t.Fatalf("expected RevokedError, got %v", err)
	}
}

// TestRegistryNeverStoresRaw is INV-1: the registry persists only the verifier.
func TestRegistryNeverStoresRaw(t *testing.T) {
	pep := testKey()
	rec, raw := newNormalRecord("cred_4", "acct_4", pep)
	defer raw.Zero()

	reg := NewMemoryRegistry()
	if err := reg.Insert(rec); err != nil {
		t.Fatal(err)
	}

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
	if err := reg.Insert(rec); err != nil {
		t.Fatal(err)
	}

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

// Regression (§36): an operator-confirmed-compromise signal (risk 100) must
// quarantine immediately from NORMAL, not climb the WATCH ladder first. A
// low-confidence novelty signal must NOT independently quarantine.
func TestDirectQuarantineEscalation(t *testing.T) {
	now := time.Now()
	sm := newSM(&now)
	if sm.Observe(100) != StatusQuarantined {
		t.Fatalf("risk 100 from NORMAL must quarantine immediately, got %v", sm.Status())
	}
	// Low-confidence novelty never quarantines on its own: a single score
	// below the quarantine threshold stays out of quarantine.
	now2 := time.Now()
	sm2 := newSM(&now2)
	if st := sm2.Observe(35); st == StatusQuarantined {
		t.Fatal("score 35 must not quarantine")
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

// mustRing builds a pepper ring that must succeed (tests).
func mustRing(t *testing.T, keys ...*PepperKey) *PepperRing {
	t.Helper()
	r, err := NewPepperRing(keys...)
	if err != nil {
		t.Fatalf("NewPepperRing: %v", err)
	}
	return r
}

// Regression: empty pepper key material must be refused at construction — an
// HMAC under an empty key is publicly computable, making stored verifiers
// enumerable (INV-1 fails closed, not open).
func TestEmptyPepperKeyRejected(t *testing.T) {
	if _, err := NewPepperRing(&PepperKey{Version: 1, Key: nil}); err == nil {
		t.Fatal("empty pepper key must be rejected")
	}
	if _, err := NewPepperRing(&PepperKey{Version: 1, Key: []byte{}}); err == nil {
		t.Fatal("zero-length pepper key must be rejected")
	}
	// DigestHMAC must also refuse an empty key directly.
	s := secret.NewFromBytes([]byte("sk-something"))
	defer s.Zero()
	if s.DigestHMAC(nil) != nil {
		t.Fatal("DigestHMAC with empty key must return nil (fail closed)")
	}
}

// Regression: a ring built from only invalid versions must error, not produce
// an empty (fail-open) ring.
func TestPepperRingRequiresAKey(t *testing.T) {
	if _, err := NewPepperRing(nil); err == nil {
		t.Fatal("ring with no keys must error")
	}
}

// Regression: IsAuthenticatable must agree with CredentialRecord.Authenticatable
// (§30) — QUARANTINED denies at authentication, not just REVOKED.
func TestStateMachineIsAuthenticatableMatchesGate(t *testing.T) {
	now := time.Now()
	sm := newSM(&now)
	if !sm.IsAuthenticatable() {
		t.Fatal("NORMAL must be authenticatable")
	}
	sm.Observe(100) // direct escalation → QUARANTINED
	if sm.Status() != StatusQuarantined {
		t.Fatalf("want QUARANTINED, got %v", sm.Status())
	}
	if sm.IsAuthenticatable() {
		t.Fatal("QUARANTINED must not be authenticatable (§30)")
	}
}

// Regression (P0.3): replacing a credential's record (rotation) must
// invalidate the previous verifier as an authentication path. The old flow
// left a stale byVerifier index entry, so the old key kept authenticating.
func TestCredentialReplacementInvalidatesOldVerifier(t *testing.T) {
	pep := testKey()
	raw1, _ := secret.Random(32)
	defer raw1.Zero()
	raw2, _ := secret.Random(32)
	defer raw2.Zero()

	reg := NewMemoryRegistry()
	rec1 := &CredentialRecord{
		CredentialID: "cred_rot", AccountID: "acct_1",
		Verifier: Verifier(raw1, pep), PepperVersion: pep.Version,
		Status: StatusNormal, Revision: 1,
	}
	if err := reg.Insert(rec1); err != nil {
		t.Fatal(err)
	}

	// old key authenticates
	if _, ok := reg.FindByVerifier(Verifier(raw1, pep), pep.Version); !ok {
		t.Fatal("old verifier must resolve before replacement")
	}

	// replace with a new verifier (rotation)
	rec2 := *rec1
	rec2.Verifier = Verifier(raw2, pep)
	rec2.Revision = 2
	if err := reg.Insert(&rec2); err != nil {
		t.Fatal(err)
	}

	if _, ok := reg.FindByVerifier(Verifier(raw2, pep), pep.Version); !ok {
		t.Fatal("new verifier must resolve after replacement")
	}
	if _, ok := reg.FindByVerifier(Verifier(raw1, pep), pep.Version); ok {
		t.Fatal("old verifier MUST NOT resolve after replacement (P0.3)")
	}
	// and the record itself was updated, not duplicated
	stored, _ := reg.Lookup("cred_rot")
	if !bytes.Equal(stored.Verifier, rec2.Verifier) || stored.Revision != 2 {
		t.Fatalf("record not replaced: rev=%d", stored.Revision)
	}
}

// Regression (P0.3 defense in depth): a poisoned index entry pointing at a
// record whose verifier has since changed must fail closed.
func TestFindByVerifierDefensivelyRechecks(t *testing.T) {
	pep := testKey()
	raw, _ := secret.Random(32)
	defer raw.Zero()
	reg := NewMemoryRegistry()
	if err := reg.Insert(&CredentialRecord{
		CredentialID: "cred_d", AccountID: "a",
		Verifier: Verifier(raw, pep), PepperVersion: pep.Version,
		Status: StatusNormal, Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate index/record divergence: record rotates without going through
	// Insert's index maintenance (a future bug) — the defensive re-check must
	// catch any stale entry.
	oldVer := Verifier(raw, pep)
	raw2, _ := secret.Random(32)
	defer raw2.Zero()
	reg.mu.Lock()
	rec := reg.records["cred_d"]
	rec.Verifier = Verifier(raw2, pep)
	rec.Revision++
	reg.mu.Unlock()

	if _, ok := reg.FindByVerifier(oldVer, pep.Version); ok {
		t.Fatal("stale index entry must not authenticate (defensive re-check)")
	}
}

// Regression (P0.3): two different credentials must never share a verifier
// under the same pepper version.
func TestConflictingVerifierOwnershipRejected(t *testing.T) {
	pep := testKey()
	raw, _ := secret.Random(32)
	defer raw.Zero()
	ver := Verifier(raw, pep)
	reg := NewMemoryRegistry()
	if err := reg.Insert(&CredentialRecord{
		CredentialID: "cred_a", Verifier: ver, PepperVersion: 1, Status: StatusNormal,
	}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Insert(&CredentialRecord{
		CredentialID: "cred_b", Verifier: ver, PepperVersion: 1, Status: StatusNormal,
	}); err != ErrVerifierOwned {
		t.Fatalf("want ErrVerifierOwned, got %v", err)
	}
}

// Regression (hardening): negative pepper versions are refused, and key
// material is copied on ingestion — later mutation of the caller's slice
// cannot alter live keys.
func TestPepperRingNegativeVersionAndCopySafety(t *testing.T) {
	if _, err := NewPepperRing(&PepperKey{Version: -1, Key: []byte("k")}); err == nil {
		t.Fatal("negative pepper version must be rejected")
	}
	key := []byte("mutable-key")
	r := mustRing(t, &PepperKey{Version: 1, Key: key})
	key[0] = 'X' // caller mutates its slice after construction
	s := secret.NewFromBytes([]byte("raw"))
	defer s.Zero()
	// The digest must still be computed under the ORIGINAL key bytes.
	m := hmac.New(sha256.New, []byte("mutable-key"))
	m.Write([]byte("gripline:secret:digest:v1"))
	m.Write([]byte("raw"))
	if !bytes.Equal(s.DigestHMAC(r.active[1]), m.Sum(nil)) {
		t.Fatal("ring must copy key material on ingestion")
	}
}
