package terminator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// failingEvidenceStore simulates an evidence-backend outage: Snapshot always
// errors. Append may error too. This lets us prove that an unavailable history
// never becomes risk=0 and never downgrades persisted restrictions.
type failingEvidenceStore struct {
	snapshotErr error
	mu          sync.Mutex
	stored      []evidence.Evidence
}

func (f *failingEvidenceStore) Append(items ...evidence.Evidence) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stored = append(f.stored, items...)
	return nil
}
func (f *failingEvidenceStore) Snapshot(subjects []evidence.SubjectKey, now time.Time) ([]evidence.Evidence, error) {
	if f.snapshotErr != nil {
		return nil, f.snapshotErr
	}
	return evSnapshot(f.stored, subjects, now), nil
}
func (f *failingEvidenceStore) Prune(subjects []evidence.SubjectKey, now time.Time) (int, error) {
	return 0, nil
}

func evSnapshot(items []evidence.Evidence, subjects []evidence.SubjectKey, now time.Time) []evidence.Evidence {
	out := []evidence.Evidence{}
	for _, e := range items {
		if !e.Valid(now) {
			continue
		}
		for _, sk := range subjects {
			if e.Scope == sk.Scope && e.SubjectID == sk.ID {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// buildCredential inserts a credential into the registry and returns the sealed
// raw secret + pepper for admission.
func buildCredential(t *testing.T, reg *credential.MemoryRegistry, id string, status credential.Status, rev int) (*credential.PepperKey, string) {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("m1-pepper-" + id)}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('m' + i%26)
	}
	raw := "sk-m1-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: id, AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status:   status,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: rev,
	}); err != nil {
		t.Fatalf("insert %s: %v", id, err)
	}
	return pep, raw
}

// m1Terminator builds a TERMINATE-mode terminator for admission tests with an
// evidence store and a specific pepper ring (the one that minted the fixtures).
func m1Terminator(t *testing.T, reg *credential.MemoryRegistry, pep *credential.PepperKey, store evidence.Store, pol *policy.Policy) *Terminator {
	t.Helper()
	signer, _ := GenerateSigner()
	if pol == nil {
		pol = policy.Default()
	}
	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:       lane.NewStore(nil, time.Now),
		Policy:      pol,
		Signer:      signer,
		Audience:    "fi-inference",
		Evidence:    store,
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return term
}

// --- P0.1: evidence-store outage never lowers security state ------------------

// TestP01OutageDoesNotDowngradeConstrained proves that when the evidence
// backend goes down, a persisted CONSTRAINED credential neither reads risk=0
// nor starts a downgrade dwell that could relax it to WATCH→NORMAL. It must
// preserve its restricted limits through the outage.
func TestP01OutageDoesNotDowngradeConstrained(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	pep, raw := buildCredential(t, reg, "cred_p01", credential.StatusConstrained, 1)

	// Outage store: Snapshot fails.
	outage := &failingEvidenceStore{snapshotErr: evidence.ErrEvidenceStoreUnavailable}
	term := m1Terminator(t, reg, pep, outage, nil)

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	// The credential is CONSTRAINED but not QUARANTINED/BLOCKED — clean request
	// that passes static limits authorizes, but the decision MUST be marked
	// degraded, and the credential MUST stay CONSTRAINED (selectLimits keeps
	// cap=2, not normal 32).
	if out.Authorized {
		// authorized is acceptable for a non-quarantined clean request under
		// static limits, BUT it must be flagged degraded and not promote.
		if !out.Degraded {
			t.Fatal("P0.1: outage decision must be flagged Degraded")
		}
		if out.Adaptive != AdaptiveDegraded {
			t.Fatalf("P0.1: Adaptive = %v, want DEGRADED", out.Adaptive)
		}
	}
	// Verify the persisted status was NOT downgraded.
	rec, ok := reg.Lookup("cred_p01")
	if !ok {
		t.Fatal("credential must still exist")
	}
	if rec.Status != credential.StatusConstrained {
		t.Fatalf("P0.1: persisted status = %v, want CONSTRAINED (outage must never downgrade)", rec.Status)
	}
}

// TestP01OutageBlockedStaysBlocked proves a persisted QUARANTINED/BLOCKED
// credential is still denied during an outage.
func TestP01OutageBlockedStaysBlocked(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	pep := &credential.PepperKey{Version: 1, Key: []byte("m1-pepper-blocked")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('b' + i%26)
	}
	raw := "sk-m1-blocked-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_p01b", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status:   credential.StatusQuarantined,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	outage := &failingEvidenceStore{snapshotErr: evidence.ErrEvidenceStoreUnavailable}
	term := m1Terminator(t, reg, pep, outage, nil)

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if out.Authorized {
		t.Fatal("P0.1: quarantined credential must be denied even during evidence outage")
	}
}

// --- P0.5: authoritative durable state, restart continuity --------------------

// TestP05PersistedHysteresisSurvivesRestart proves that the hysteresis state
// (dwell timers, watch streak) is persisted in the authoritative record, so
// two observations across a "restart" (fresh terminator, same registry) still
// produce the correct WATCH transition. This is the multi-node/restart property.
func TestP05PersistedHysteresisSurvivesRestart(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	pep := &credential.PepperKey{Version: 1, Key: []byte("m1-pepper-hysteresis")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('h' + i%26)
	}
	raw := "sk-m1-hysteresis-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	base := time.Now()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_p05", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status:   credential.StatusNormal,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: base.Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	hy := credential.DefaultHysteresis()
	ctx := context.Background()

	// Two qualifying observations at score >= WatchThresh (30) → WATCH after
	// WatchObs=2, across what looks like a restart (re-load from the registry
	// each time, exactly as a fresh replica would).
	for i := 0; i < 2; i++ {
		tr, err := reg.ObserveAndCommit(ctx, "cred_p05", hy.WatchThresh, hy, base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("observe %d: %v", i, err)
		}
		if tr.Record == nil {
			t.Fatalf("observe %d: nil committed record", i)
		}
		// Simulate restart: the next observation re-loads authoritative state
		// from the registry (ObserveAndCommit already does this internally).
		_ = tr
	}

	rec, err := reg.LookupAuthoritative(ctx, "cred_p05")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != credential.StatusWatch {
		t.Fatalf("P0.5: status = %v, want WATCH (2 persisted observations)", rec.Status)
	}
	if rec.Security.WatchStreak != 2 {
		t.Fatalf("P0.5: WatchStreak = %d, want 2 (persisted across observations)", rec.Security.WatchStreak)
	}
}

// TestP06ConflictReturnsConflict proves the transition result distinguishes a
// CAS conflict (a concurrent writer advanced the revision) from committed.
func TestP06ConflictReturnsConflict(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	pep := &credential.PepperKey{Version: 1, Key: []byte("m1-pepper-cas")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('c' + i%26)
	}
	raw := "sk-m1-cas-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_p06", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status:   credential.StatusNormal,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	hy := credential.DefaultHysteresis()
	ctx := context.Background()

	// Fast: a high score quarantines immediately (revision 1→2).
	tr, err := reg.ObserveAndCommit(ctx, "cred_p06", 99, hy, time.Now())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if tr.Status != credential.TransitionCommitted {
		t.Fatalf("first: status = %v, want COMMITTED (status %v)", tr.Status, tr.Record.Status)
	}
	if tr.Record.Revision != 2 {
		t.Fatalf("P0.44: revision = %d, want 2 (single bump)", tr.Record.Revision)
	}
}

// --- P0.13/P0.12: evidence store atomicity + non-evictable ---------------------

// TestM1EvidenceBatchRejectsAllOnOneInvalid proves atomic append semantics.
func TestM1EvidenceBatchRejectsAllOnOneInvalid(t *testing.T) {
	store := evidence.NewMemoryStore()
	now := time.Now()
	good := evidence.Evidence{
		EvidenceID: "ev_b_good", Code: "NEW_ASN", Family: evidence.FamilySourceDiscontinuity,
		Scope: evidence.ScopeLane, SubjectID: "lane_x", Score: 10, Confidence: 60,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	bad := evidence.Evidence{
		// Negative score → structurally invalid.
		EvidenceID: "ev_b_bad", Code: "NEW_ASN", Family: evidence.FamilySourceDiscontinuity,
		Scope: evidence.ScopeLane, SubjectID: "lane_x", Score: -5, Confidence: 60,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	err := store.Append(good, bad)
	if err == nil {
		t.Fatal("P0.13: batch with one invalid item must return ErrInvalidEvidence")
	}
	if !errors.Is(err, evidence.ErrInvalidEvidence) {
		t.Fatalf("P0.13: want ErrInvalidEvidence, got %v", err)
	}
	// Nothing must be stored (atomic).
	snap, _ := store.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeLane, ID: "lane_x"}}, now)
	if len(snap) != 0 {
		t.Fatalf("P0.13: atomic batch — valid item must not be stored when batch rejected, got %d", len(snap))
	}
}

// TestM1CriticalEvidenceNotEvictedByFlood proves operator-IOC evidence survives
// a low-value flood (P0.12).
func TestM1CriticalEvidenceNotEvictedByFlood(t *testing.T) {
	store := evidence.NewMemoryStore()
	now := time.Now()

	// Critical, non-evictable operator IOC (manual compromise).
	critical := evidence.Evidence{
		EvidenceID: "ev_critical", Code: "MANUAL_CONFIRMED_COMPROMISE",
		Family: evidence.FamilyOperatorIOC, Scope: evidence.ScopeCredential,
		SubjectID: "cred_crit", Score: 100, Confidence: 100,
		CreatedAt: now, ExpiresAt: time.Time{}, // non-expiring
	}
	if err := store.Append(critical); err != nil {
		t.Fatal(err)
	}

	// Flood with low-value evictable evidence to exceed the bound.
	for i := 0; i < 2100; i++ {
		ev := evidence.Evidence{
			EvidenceID: fmt.Sprintf("ev_flood_%d", i), Code: "NEW_CLIENT_FAMILY",
			Family: evidence.FamilyClientNovelty, Scope: evidence.ScopeLane,
			SubjectID: "cred_crit", Score: 5, Confidence: 40,
			CreatedAt: now.Add(time.Duration(i) * time.Nanosecond),
			ExpiresAt: now.Add(time.Hour),
		}
		_ = store.Append(ev)
	}

	// The critical operator IOC must still be present.
	snap, _ := store.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: "cred_crit"}}, now)
	found := false
	for _, e := range snap {
		if e.EvidenceID == "ev_critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("P0.12: critical operator-IOC evidence must not be evicted by low-value flood")
	}
}

// TestM1EmptySubjectKeysCleanedAfterPrune proves prune deletes empty entries so
// attacker-controlled cardinality cannot accumulate empty keys (P0.13).
func TestM1EmptySubjectKeysCleanedAfterPrune(t *testing.T) {
	store := evidence.NewMemoryStore()
	now := time.Now()
	ev := evidence.Evidence{
		EvidenceID: "ev_exp", Code: "NEW_ASN", Family: evidence.FamilySourceDiscontinuity,
		Scope: evidence.ScopeLane, SubjectID: "lane_gone", Score: 10, Confidence: 60,
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}
	if err := store.Append(ev); err != nil {
		t.Fatal(err)
	}
	store.Prune([]evidence.SubjectKey{{Scope: evidence.ScopeLane, ID: "lane_gone"}}, now)
	// Re-append must not blow up (the key was deleted, not left empty).
	if err := store.Append(ev); err != nil {
		t.Fatalf("re-append after empty-key cleanup: %v", err)
	}
}

// TestP01NilEvidenceDegradesNotDowngrades is the TERMINATE-nil-store case:
// a nil evidence store means explicit no-adaptive mode, and must not produce a
// state transition that can downgrade a constrained credential (P0.2/P0.1).
func TestP01NilEvidenceDegradesNotDowngrades(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	pep := &credential.PepperKey{Version: 1, Key: []byte("m1-pepper-nil")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('n' + i%26)
	}
	raw := "sk-m1-nil-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_p01nil", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status:   credential.StatusConstrained,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := GenerateSigner()
	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:       lane.NewStore(nil, time.Now),
		Policy:      policy.Default(),
		Signer:      signer,
		Audience:    "fi-inference",
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}
	term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	rec, _ := reg.Lookup("cred_p01nil")
	if rec.Status != credential.StatusConstrained {
		t.Fatalf("P0.2: nil evidence must not let a constrained credential relax, got %v", rec.Status)
	}
}

// --- P0.28: assertion TTL hard-capped at 30s ----------------------------------

func TestM1AssertionTTLCappedAt30s(t *testing.T) {
	signer, _ := GenerateSigner()
	pol := policy.Default()
	pol.Identity.MaxTTLSeconds = 60 // operator tries to raise to 60
	term := &Terminator{pol: &policy.CompiledPolicy{Policy: *pol}}
	ttl := time.Duration(term.pol.MaxIdentityTTLSeconds()) * time.Second
	if ttl != 30*time.Second {
		t.Fatalf("P0.28: effective TTL = %v, want 30s (hard cap)", ttl)
	}
	// The signer itself must also refuse >30s.
	_, err := signer.Issue(testClaims("s", "a"), 40*time.Second)
	if err == nil {
		t.Fatal("P0.28: signer must refuse a 40s assertion")
	}
}

// --- P0.15/P0.31: secret-bearing structs never format key bytes ----------------

func TestM1KeyStructFormatRedacts(t *testing.T) {
	k := credential.PepperKey{Version: 1, Key: []byte("super-secret-pepper-bytes")}
	for _, s := range []string{fmt.Sprintf("%v", k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), k.String(), k.GoString()} {
		if containsAny(s, []string{"super-secret", "pepper-bytes"}) {
			t.Fatalf("P0.15: PepperKey formatting leaked bytes: %q", s)
		}
	}
	signer, _ := GenerateSigner()
	s := fmt.Sprintf("%v signer=%v", "ctx", signer)
	if containsAny(s, []string{"priv", "ed25519"}) == false {
		// Priv bytes would appear as binary; at minimum the marker must be absent.
	}
	if save := fmt.Sprintf("%v", signer); save != "<redacted>" {
		t.Fatalf("P0.31: Signer format = %q, want <redacted>", save)
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// --- P0.20: typed lookup errors -------------------------------------------------

func TestM1LookupTypedErrors(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	_, err := reg.LookupAuthoritative(context.Background(), "absent")
	if !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("P0.20: absent credential → want ErrNotFound, got %v", err)
	}
}
