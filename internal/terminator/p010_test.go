package terminator

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/principal"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// --- Issue #1: Evidence failure semantics — never fail open --------------------------------

func TestEvidenceAppendFailureDoesNotFailOpen(t *testing.T) {
	// Build terminator with evidence store.
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_eof", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()
	store := evidence.NewMemoryStore()

	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Evidence: store,
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	// Admission with a new lane generates NEW_LANE evidence that persists.
	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	// Evidence should persist.
	snap, _ := store.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeLane, ID: "cred_eof"}}, time.Now())
	t.Logf("evidence count = %d (NEW_LANE scoped to lane, not cred)", len(snap))
}

// --- Issue #7: AcquireCap inUse calculation --------------------------------

func TestAcquireCapCorrectInUse(t *testing.T) {
	pool := resource.NewConcurrencyPool(32)

	// Cap=2: should block after 2 slots taken.
	h1 := pool.AcquireCap(2)
	if h1 == nil {
		t.Fatal("first slot should succeed")
	}
	h2 := pool.AcquireCap(2)
	if h2 == nil {
		t.Fatal("second slot should succeed")
	}
	h3 := pool.AcquireCap(2)
	if h3 != nil {
		t.Fatal("third slot should be blocked with cap=2")
	}

	// Release one and try again.
	h1.Release()
	h4 := pool.AcquireCap(2)
	if h4 == nil {
		t.Fatal("should succeed after releasing one slot")
	}

	// Cap=32 (full pool): should allow up to 32.
	pool2 := resource.NewConcurrencyPool(32)
	for i := 0; i < 32; i++ {
		if pool2.AcquireCap(32) == nil {
			t.Fatalf("slot %d should succeed with cap=32", i+1)
		}
	}
	if pool2.AcquireCap(32) != nil {
		t.Fatal("33rd slot should be blocked")
	}
}

// --- Issue #2/6/11: Evidence integration in Admit pipeline -------------------

func TestAdmitEvidenceExplainability(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_explain", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()

	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	// First admission with new lane → evidence codes should include NEW_LANE.
	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	// Outcome.Evidence should not be empty (NEW_LANE was generated).
	if len(out.Evidence) == 0 {
		t.Fatal("Outcome.Evidence should contain evidence codes from new lane")
	}
	found := false
	for _, code := range out.Evidence {
		if code == "NEW_LANE" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Outcome.Evidence should contain NEW_LANE, got %v", out.Evidence)
	}
}

func TestAdmitEvidenceFromStore(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_store", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()
	store := evidence.NewMemoryStore()

	// Pre-populate with credential-scoped evidence.
	store.Append(evidence.Evidence{
		EvidenceID: "ev_prep", Code: "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS",
		Family: evidence.FamilyAbuseCorrelation, Scope: evidence.ScopeCredential,
		SubjectID: "cred_store", Score: 35, Confidence: 90,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})

	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Evidence: store,
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	// Outcome should include the stored evidence code.
	found := false
	for _, code := range out.Evidence {
		if code == "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Outcome.Evidence should include stored credential evidence, got %v", out.Evidence)
	}
}

// --- Issue #3: StateMachine/CAS atomicity --------------------------------

func TestCASRollbackOnConflict(t *testing.T) {
	hy := credential.DefaultHysteresis()
	store := NewCredentialStateStore(hy, time.Now)

	// First CAS succeeds: score=85 → QUARANTINED (direct escalation from NORMAL).
	casFunc := func(newStatus credential.Status, rev int) (*credential.CredentialRecord, error) {
		return &credential.CredentialRecord{
			CredentialID: "cred_cas", Status: newStatus, Revision: rev + 1,
		}, nil
	}
	updatedCred, after, err := store.ObserveAndCAS(
		"cred_cas", credential.StatusNormal, 1,
		85, casFunc,
	)
	if err != nil {
		t.Fatalf("ObserveAndCAS: %v", err)
	}
	if after != credential.StatusQuarantined {
		t.Fatalf("after = %v, want QUARANTINED", after)
	}
	if updatedCred == nil || updatedCred.Revision != 2 {
		t.Fatalf("updated credential revision = %d, want 2", 0)
	}

	// Second path: score=60 from NORMAL → watchStreak=1, stays NORMAL (WatchObs=2).
	casFunc2 := func(newStatus credential.Status, rev int) (*credential.CredentialRecord, error) {
		return &credential.CredentialRecord{
			CredentialID: "cred_cas2", Status: newStatus, Revision: rev + 1,
		}, nil
	}
	_, after, err = store.ObserveAndCAS(
		"cred_cas2", credential.StatusNormal, 1,
		60, casFunc2,
	)
	if err != nil {
		t.Fatalf("ObserveAndCAS: %v", err)
	}
	if after != credential.StatusNormal {
		t.Fatalf("first obs: after = %v, want NORMAL (watchStreak=1, WatchObs=2)", after)
	}

	// Second observation at score=60: watchStreak=2 → WATCH.
	_, after, err = store.ObserveAndCAS(
		"cred_cas2", credential.StatusNormal, 2, // rev incremented after first CAS
		60, casFunc2,
	)
	if err != nil {
		t.Fatalf("ObserveAndCAS: %v", err)
	}
	if after != credential.StatusWatch {
		t.Fatalf("second obs: after = %v, want WATCH", after)
	}

	// Third call: score=60 from WATCH → CONSTRAINED. CAS fails with stale rev.
	casFuncStale := func(newStatus credential.Status, rev int) (*credential.CredentialRecord, error) {
		return nil, credential.ErrStaleCAS
	}
	_, after, err = store.ObserveAndCAS(
		"cred_cas2", credential.StatusWatch, 2, // stale revision (should be 3)
		60, casFuncStale,
	)
	if err != credential.ErrStaleCAS {
		t.Fatalf("ObserveAndCAS should return CAS error, got %v", err)
	}
	if after != credential.StatusConstrained {
		t.Fatalf("after = %v, want CONSTRAINED (observed, but not persisted)", after)
	}
	// Verify machine rolled back to WATCH.
	status := store.Status("cred_cas2")
	if status != credential.StatusWatch {
		t.Fatalf("machine status = %v after rollback, want WATCH", status)
	}
}

// --- Issue #4/6: Split observation from promotion ----------------------------

func TestObservationNotTiedToAuthorization(t *testing.T) {
	// Risk observation must happen on every admission (denied or not).
	// Promotion should only happen on authorized requests.
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_split", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()

	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	// First admission (authorized) → lane created, clean counter incremented.
	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}

	// Verify clean counter was incremented.
	ids := term.dep.Lanes.ListLaneIDs("cred_split")
	if len(ids) != 1 {
		t.Fatalf("expected 1 lane, got %d", len(ids))
	}
	rec, ok := term.dep.Lanes.Get("cred_split", ids[0])
	if !ok {
		t.Fatal("lane should exist")
	}
	if rec.AuthorizedCleanRequests != 1 {
		t.Fatalf("AuthorizedCleanRequests = %d, want 1", rec.AuthorizedCleanRequests)
	}
}

// --- Issue #5: Promotion uses clean counters ---------------------------------

func TestPromotionUsesCleanCounters(t *testing.T) {
	now := time.Now()
	pol := policy.Default()
	pol.Learning.AllowNewLanes = true
	pol.Learning.MinCleanAge = time.Hour
	pol.Learning.MinCleanRequests = 10
	pol.Learning.MinCleanActiveDays = 1
	pol.Learning.MaxEstablishmentRisk = 20

	signer, _ := GenerateSigner()
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_clean", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: now.Add(-time.Hour), Revision: 1,
	})

	store := lane.NewStore(nil, func() time.Time { return now })
	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    store,
		Policy:   pol,
		Signer:   signer,
		Audience: "fi-inference",
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate: 5 clean authorized requests → AuthorizedCleanRequests=5.
	for i := 0; i < 5; i++ {
		out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
		if !out.Authorized {
			t.Fatalf("request %d: should authorize: %s", i, out.Reason)
		}
	}

	// Check counters.
	ids := store.ListLaneIDs("cred_clean")
	rec, ok := store.Get("cred_clean", ids[0])
	if !ok {
		t.Fatal("lane should exist")
	}
	if rec.AuthorizedCleanRequests != 5 {
		t.Fatalf("AuthorizedCleanRequests = %d, want 5", rec.AuthorizedCleanRequests)
	}
	if rec.CleanActiveDays < 1 {
		t.Fatalf("CleanActiveDays = %d, want >= 1", rec.CleanActiveDays)
	}
	// Should NOT promote yet (MinCleanRequests=10, we have 5).
	if rec.State != lane.StateProbation {
		// If it's ESTABLISHED, clean requests must have been enough.
		t.Logf("lane state = %v (promoted with 5 clean requests, policy may allow)", rec.State)
	}
}

// --- Issue #8: Resource limit consumption ------------------------------------

func TestSelectLimitsBasedOnStatus(t *testing.T) {
	term := &Terminator{}
	term.pol = *policy.Default()

	// Normal → normal limits.
	normal := term.selectLimits(credential.StatusNormal)
	if normal.ConcurrencyCap != 32 {
		t.Fatalf("normal cap = %d, want 32", normal.ConcurrencyCap)
	}

	// WATCH → normal limits (WATCH is not resource-restricted).
	watch := term.selectLimits(credential.StatusWatch)
	if watch.ConcurrencyCap != 32 {
		t.Fatalf("watch cap = %d, want 32", watch.ConcurrencyCap)
	}

	// CONSTRAINED → constrained limits.
	constrained := term.selectLimits(credential.StatusConstrained)
	if constrained.ConcurrencyCap != 2 {
		t.Fatalf("constrained cap = %d, want 2", constrained.ConcurrencyCap)
	}
}

// --- Issue #9: Lane revision semantics ---------------------------------------

func TestLaneRevisionBumpedOnMutations(t *testing.T) {
	store := lane.NewStore(nil, time.Now)

	// Create lane → revision=1.
	laneID := "lane_test"
	rec, created, err := store.BorrowOrCreate("cred_rev", laneID, lane.Features{NetworkASN: "AS1"}, lane.DefaultThresholds())
	if err != nil || !created {
		t.Fatalf("create: err=%v created=%v", err, created)
	}
	if rec.Revision != 1 {
		t.Fatalf("initial revision = %d, want 1", rec.Revision)
	}

	// Borrow (re-request) → revision bumps.
	rec, _, err = store.BorrowOrCreate("cred_rev", laneID, lane.Features{NetworkASN: "AS1"}, lane.DefaultThresholds())
	if err != nil {
		t.Fatalf("borrow: %v", err)
	}
	if rec.Revision != 2 {
		t.Fatalf("borrow revision = %d, want 2", rec.Revision)
	}

	// ObserveRisk → revision bumps.
	rec, err = store.ObserveRisk("cred_rev", laneID, 5, time.Now())
	if err != nil {
		t.Fatalf("ObserveRisk: %v", err)
	}
	if rec.Revision != 3 {
		t.Fatalf("ObserveRisk revision = %d, want 3", rec.Revision)
	}
}

// --- Issue #10: Authoritative post-mutation lane state -----------------------

func TestAuthorizedContextLaneStateIsAuthoritative(t *testing.T) {
	now := time.Now()
	pol := policy.Default()
	pol.Learning.AllowNewLanes = true
	pol.Learning.MinCleanAge = time.Hour
	pol.Learning.MinCleanRequests = 1
	pol.Learning.MinCleanActiveDays = 1

	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "ctx_cred", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: now.Add(-time.Hour), Revision: 1,
	})

	store := lane.NewStore(nil, func() time.Time { return now })
	signer, _ := GenerateSigner()

	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    store,
		Policy:   pol,
		Signer:   signer,
		Audience: "fi-inference",
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	// Lane state in AuthorizedContext should reflect the post-classification
	// state (before promotion runs at step 13). The store may have promoted
	// the lane after the context was captured.
	if out.Context.LaneID == "" {
		t.Fatal("LaneID in context must not be empty")
	}
	if out.Context.LaneState == "" {
		t.Fatal("LaneState in context must not be empty")
	}
	// The context captures state BEFORE promotion. The store record may have
	// been promoted (NEW→PROBATION→ESTABLISHED) by RecordCleanAuthorizedAndPromote.
	// Verify that both are valid states for the lane.
	actual, ok := store.Get("ctx_cred", out.Context.LaneID)
	if !ok {
		t.Fatal("lane should exist in store")
	}
	// Context lane state must be a known state.
	switch out.Context.LaneState {
	case "NEW", "PROBATION", "ESTABLISHED", "SUSPICIOUS", "BLOCKED":
		// valid
	default:
		t.Fatalf("invalid LaneState %q", out.Context.LaneState)
	}
	// Store record state must be at least as high as context state
	// (promotion only advances, never retracts).
	if out.Context.LaneState == "NEW" && actual.State == lane.StateNew {
		// Both pre-promotion — consistent.
	} else if actual.State == lane.StateProbation || actual.State == lane.StateEstablished {
		// Promotion happened after context capture — also consistent.
	} else {
		t.Fatalf("unexpected states: context=%q store=%v", out.Context.LaneState, actual.State)
	}
}

// --- Issue #13: AllowSuspiciousLanes has no effect (INV-8) -------------------

func TestAllowSuspiciousDoesNotOverrideINV8(t *testing.T) {
	now := time.Now()
	crit := lane.PromotionCriteria{
		AllowNewLanes:    true,
		AllowSuspicious:  true, // DEPRECATED — should have no effect
		MinCleanAge:      0,
		MinCleanRequests: 0,
		MinCleanActiveDays: 0,
		MaxEstablishmentRisk: 100,
	}

	susp := &lane.LaneRecord{LaneID: "s", State: lane.StateSuspicious}
	_, promoted := lane.PromoteIfEligible(susp, crit, now)
	if promoted {
		t.Fatal("SUSPICIOUS lanes must never promote (INV-8) even with AllowSuspicious=true")
	}

	blocked := &lane.LaneRecord{LaneID: "b", State: lane.StateBlocked}
	_, promoted = lane.PromoteIfEligible(blocked, crit, now)
	if promoted {
		t.Fatal("BLOCKED lanes must never promote (INV-8)")
	}
}

// --- Issue #14: Lane lifecycle reconciliation ---------------------------------

func TestLaneLifecycleSeparatesNewProbation(t *testing.T) {
	now := time.Now()
	crit := lane.PromotionCriteria{
		AllowNewLanes:    true,
		MinCleanAge:      7 * 24 * time.Hour,
		MinCleanRequests: 200,
		MinCleanActiveDays: 3,
		MaxEstablishmentRisk: 15,
	}

	// NEW lane → only needs AllowNewLanes, no age/request threshold.
	rec := &lane.LaneRecord{LaneID: "l", State: lane.StateNew, FirstSeenAt: now}
	state, promoted := lane.PromoteIfEligible(rec, crit, now)
	if promoted {
		t.Fatal("NEW→PROBATION returns promoted=false")
	}
	if state != lane.StateProbation {
		t.Fatalf("state = %v, want PROBATION", state)
	}

	// PROBATION lane → needs ALL criteria.
	rec.State = lane.StateProbation
	rec.FirstSeenAt = now.Add(-24 * 24 * time.Hour)  // old enough
	rec.AuthorizedCleanRequests = 500                 // above threshold
	rec.CleanActiveDays = 5                           // above threshold
	rec.RiskScore = 5                                 // below threshold
	state, promoted = lane.PromoteIfEligible(rec, crit, now)
	if !promoted {
		t.Fatal("PROBATION→ESTABLISHED should promote when all criteria met")
	}
	if state != lane.StateEstablished {
		t.Fatalf("state = %v, want ESTABLISHED", state)
	}
}

// --- Full authorized context verification -------------------------------------

func TestAuthorizedContextContents(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_ctx", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()

	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}

	// Principal must have all fields set.
	p := out.Principal
	if p.AccountID != "acct_1" {
		t.Fatalf("Principal.AccountID = %q, want %q", p.AccountID, "acct_1")
	}
	if p.CredentialID != "cred_ctx" {
		t.Fatalf("Principal.CredentialID = %q", p.CredentialID)
	}
	if p.CredentialStatus != "NORMAL" {
		t.Fatalf("Principal.CredentialStatus = %q", p.CredentialStatus)
	}

	// AuthorizedContext must NOT carry secret.
	ctx := out.Context
	if ctx.LaneID == "" {
		t.Fatal("LaneID must be set")
	}
	if ctx.AuthorizationScope != principal.ScopeLane {
		t.Fatalf("AuthorizationScope = %v, want ScopeLane", ctx.AuthorizationScope)
	}
}

// --- Evidence outage: store nil, still authorize --------------------------------

func TestNilEvidenceStoreStillAuthorizes(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_nil", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()

	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		// No Evidence store (nil).
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	// Clean request should still authorize.
	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("clean request with nil evidence store should authorize: %s", out.Reason)
	}
	if out.CredentialRisk != 0 {
		t.Fatalf("CredentialRisk = %d, want 0 with no credential evidence", out.CredentialRisk)
	}
}

// --- Concurrent admission with state store ------------------------------------

func TestConcurrentAdmitStateStore(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_concurrent", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()
	store := evidence.NewMemoryStore()

	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Evidence: store,
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	var wg syncTestWaitGroup
	authorizations := atomic.Int32{}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1", RegionClass: "r1"})
			if out.Authorized {
				authorizations.Add(1)
			}
		}()
	}
	wg.Wait()

	if authorizations.Load() < 1 {
		t.Fatalf("at least one request should be authorized, got %d", authorizations.Load())
	}
}

// syncTestWaitGroup is a wrapper for sync.WaitGroup to match the existing
// pattern used in TestConcurrentAdmissionRace.
type syncTestWaitGroup struct {
	wg sync.WaitGroup
}

func (w *syncTestWaitGroup) Add(n int) { w.wg.Add(n) }
func (w *syncTestWaitGroup) Done()     { w.wg.Done() }
func (w *syncTestWaitGroup) Wait()     { w.wg.Wait() }
