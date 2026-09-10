package terminator

import (
	"errors"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// failingStore is an evidence.Store whose Snapshot always fails (outage).
type failingStore struct{ evidence.Store }

func (failingStore) Snapshot([]evidence.SubjectKey, time.Time) ([]evidence.Evidence, error) {
	return nil, evidence.ErrEvidenceStoreUnavailable
}

type failingLaneRepository struct{ lane.Repository }

func (failingLaneRepository) RecordCleanAuthorizedAndPromote(string, string, int, lane.PromotionCriteria, time.Time) (*lane.LaneRecord, bool, error) {
	return nil, false, errors.New("lane authority unavailable")
}

func baselineTestTerminator(t *testing.T, ev evidence.Store) (*Terminator, string, *lane.Store) {
	t.Helper()
	now := time.Now()
	pol := policy.Default()
	pol.Learning.AllowNewLanes = true
	pol.Learning.MinCleanAge = time.Hour
	pol.Learning.MinCleanRequests = 1
	pol.Learning.MinCleanActiveDays = 1
	pol.Learning.MaxEstablishmentRisk = 20

	signer, _ := GenerateSigner()
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-baseline-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_base", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: now.Add(-time.Hour), Revision: 1,
	})
	store := lane.NewStore(nil, func() time.Time { return now })
	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: store, Policy: pol, Signer: signer, Audience: "fi-inference",
		Evidence:    ev,
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}
	return term, raw, store
}

// P0.27: an authorized admission alone must NOT advance the baseline; only the
// proxy lifecycle event (FinalizeBaseline) does.
func TestBaselineDeferredUntilFinalize(t *testing.T) {
	term, raw, store := baselineTestTerminator(t, evidence.NewMemoryStore())

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	ids := store.ListLaneIDs("cred_base")
	if len(ids) != 1 {
		t.Fatalf("want 1 lane, got %d", len(ids))
	}
	rec, _ := store.Get("cred_base", ids[0])
	if rec.AuthorizedCleanRequests != 0 {
		t.Fatalf("admission must not count as clean activity before finalize (P0.27), got %d", rec.AuthorizedCleanRequests)
	}

	if !out.FinalizeBaseline() {
		t.Fatal("finalize must apply after upstream success")
	}
	rec, _ = store.Get("cred_base", ids[0])
	if rec.AuthorizedCleanRequests != 1 {
		t.Fatalf("want 1 clean request after finalize, got %d", rec.AuthorizedCleanRequests)
	}

	// Idempotency: double-finalize must not double count.
	if out.FinalizeBaseline() {
		t.Fatal("finalize must be idempotent")
	}
	rec, _ = store.Get("cred_base", ids[0])
	if rec.AuthorizedCleanRequests != 1 {
		t.Fatalf("double finalize counted twice: %d", rec.AuthorizedCleanRequests)
	}
}

// Deferred completion accounting must receive its own authority budget. A
// request that streams longer than the admission budget still gets one bounded
// attempt to record its final clean observation.
func TestBaselineFinalizeAfterAdmissionBudget(t *testing.T) {
	term, raw, store := baselineTestTerminator(t, evidence.NewMemoryStore())

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	time.Sleep(deferredAuthorityTimeout + 100*time.Millisecond)
	if !out.FinalizeBaseline() {
		t.Fatal("baseline token must remain spendable after a long stream")
	}
	ids := store.ListLaneIDs("cred_base")
	rec, _ := store.Get("cred_base", ids[0])
	if rec.AuthorizedCleanRequests != 1 {
		t.Fatalf("long-stream baseline was not recorded: got %d", rec.AuthorizedCleanRequests)
	}
}

func TestBaselineFinalizeFailureIsCountedWithoutChangingAdmission(t *testing.T) {
	term, raw, store := baselineTestTerminator(t, evidence.NewMemoryStore())
	term.dep.Lanes = failingLaneRepository{Repository: store}

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("lane persistence failure must not change admission authorization: %s", out.Reason)
	}
	if !out.FinalizeBaseline() {
		t.Fatal("baseline token should be spent even when deferred persistence fails")
	}
	if got := term.BaselineFinalizeFailures(); got != 1 {
		t.Fatalf("baseline finalize failures=%d, want 1", got)
	}
	if _, ok := store.Get("cred_base", store.ListLaneIDs("cred_base")[0]); !ok {
		t.Fatal("admission should still create a lane")
	}
	if out.FinalizeBaseline() {
		t.Fatal("baseline token must remain idempotent after a persistence failure")
	}
}

// P0.27/P0.1: a degraded admission (evidence store outage at admit time) may
// authorize but its baseline token is ineligible — unreliable history must not
// build trust.
func TestDegradedBaselineTokenNeverFinalizes(t *testing.T) {
	term, raw, store := baselineTestTerminator(t, failingStore{evidence.NewMemoryStore()})

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("degraded admission should still authorize: %s", out.Reason)
	}
	if !out.Degraded {
		t.Fatal("evidence outage must mark the outcome degraded")
	}
	if out.Baseline == nil || out.Baseline.Eligible {
		t.Fatal("degraded admission must issue an ineligible baseline token")
	}
	if out.FinalizeBaseline() {
		t.Fatal("degraded baseline token must never finalize (P0.1/P0.27)")
	}
	ids := store.ListLaneIDs("cred_base")
	rec, _ := store.Get("cred_base", ids[0])
	if rec.AuthorizedCleanRequests != 0 {
		t.Fatalf("degraded finalize must not count clean activity, got %d", rec.AuthorizedCleanRequests)
	}
}

// P0.26: active disqualifying evidence at finalize time vetoes promotion even
// when every counter criterion is satisfied.
func TestDisqualifyingEvidenceVetoesPromotionAtFinalize(t *testing.T) {
	evStore := evidence.NewMemoryStore()
	term, raw, store := baselineTestTerminator(t, evStore)

	// Active disqualifying evidence against the LANE subject.
	now := term.dep.RiskNow()
	bad, err := evidence.Mint(term.pol.EvidenceRules, "CONCURRENCY_OVER_10X_BASELINE", mustLaneID(t, store, "cred_base", term, raw), now, term.pol.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := evStore.Append(bad); err != nil {
		t.Fatal(err)
	}

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	// Finalize succeeds (credit applied) but promotion must be vetoed.
	if !out.FinalizeBaseline() {
		t.Fatal("finalize should apply")
	}
	ids := store.ListLaneIDs("cred_base")
	rec, _ := store.Get("cred_base", ids[0])
	if rec.State != lane.StateNew {
		t.Fatalf("AllowNewLanes seeding may move NEW→PROBATION, but got %v (must never reach ESTABLISHED)", rec.State)
	}
	if rec.State == lane.StateEstablished {
		t.Fatal("active disqualifying evidence must veto establishment (P0.26)")
	}
}

func mustLaneID(t *testing.T, store *lane.Store, credID string, term *Terminator, raw string) string {
	t.Helper()
	ids := store.ListLaneIDs(credID)
	if len(ids) == 0 {
		// Admit once to create the lane, then finalize to keep counters sane.
		out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
		if !out.Authorized {
			t.Fatalf("admit failed: %s", out.Reason)
		}
		ids = store.ListLaneIDs(credID)
	}
	return ids[0]
}

// P0.26 fail-closed: when the evidence store is UNAVAILABLE at finalize time,
// the veto conservatively applies (unknown history must not build trust).
func TestEvidenceOutageAtFinalizeVetoesPromotion(t *testing.T) {
	// First admission goes against a working store; the finalize runs against
	// an outage. Simulate by making the store fail only after admit.
	working := evidence.NewMemoryStore()
	fs := &flipStore{Store: working}
	term, raw, store := baselineTestTerminator(t, fs)

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	fs.fail = true // outage begins before the upstream completes
	if !out.FinalizeBaseline() {
		t.Fatal("baseline credit still applies under outage (counters are store-local)")
	}
	ids := store.ListLaneIDs("cred_base")
	rec, _ := store.Get("cred_base", ids[0])
	if rec.State == lane.StateEstablished {
		t.Fatal("promotion must not occur while history is unreadable (fail-closed veto)")
	}
}

// flipStore fails Snapshot on demand (after an outage begins).
type flipStore struct {
	evidence.Store
	fail bool
}

func (f *flipStore) Snapshot(subs []evidence.SubjectKey, now time.Time) ([]evidence.Evidence, error) {
	if f.fail {
		return nil, errors.New("evidence: outage")
	}
	return f.Store.Snapshot(subs, now)
}
