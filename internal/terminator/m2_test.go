package terminator

import (
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// TestM2LaneScopedContainment is the Gate-I style proof: a BLOCKED lane is
// denied while a separate NORMAL lane on the SAME credential continues to
// authorize. This is the product's central differentiation (P0.7): lane risk
// produces real lane enforcement, not just a stored score.
func TestM2LaneScopedContainment(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	pep := &credential.PepperKey{Version: 1, Key: []byte("m2-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('m' + i%26)
	}
	raw := "sk-m2-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_m2", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status:   credential.StatusNormal,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	signer, _ := GenerateSigner()
	store := evidence.NewMemoryStore()
	ls := lane.NewStore(nil, time.Now)
	// P0.13: this test exercises the BLOCKED pathway, which is policy-gated —
	// opt into the operator-validated automatic-block posture.
	pol := policy.Default()
	pol.LaneSecurity.EnableAutomaticBlock = true
	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:       ls,
		Policy:      pol,
		Signer:      signer,
		Audience:    "fi-inference",
		Evidence:    store,
		Mode:        ModeEnforce, // lane enforcement is a REQUIRED seam (P0.2)
		Concurrency: &fakePool{resource.NewConcurrencyPool(100)},
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	// Lane A — residential / claude-code style.
	laneA := lane.Features{NetworkASN: "AS-RESIDENTIAL", NetworkType: "residential", RegionClass: "us", ClientFamily: "claude-code"}
	// Lane B — distinct hosting style.
	laneB := lane.Features{NetworkASN: "AS-HOSTING", NetworkType: "hosting", RegionClass: "eu", ClientFamily: "sdk"}

	// Establish both lanes as separate.
	outA := term.Admit(bearerHeaders(raw), laneA)
	if !outA.Authorized {
		t.Fatalf("lane A should authorize: %s", outA.Reason)
	}
	outB := term.Admit(bearerHeaders(raw), laneB)
	if !outB.Authorized {
		t.Fatalf("lane B should authorize: %s", outB.Reason)
	}
	laneAID, laneBID := outA.Context.LaneID, outB.Context.LaneID
	if laneAID == laneBID {
		t.Fatal("distinct feature vectors must classify to distinct lanes")
	}

	// Drive lane B's risk high enough to BLOCK it (BlockThresh 70). Seed
	// lane-B-scoped evidence summing ≥ BlockThresh so a single observation on the
	// next admission drives the lane to LANE_BLOCKED (single-high-block).
	hi := []evidence.Evidence{
		{
			EvidenceID: "ev_block_1", Code: "CONCURRENCY_OVER_10X_BASELINE",
			Family: evidence.FamilyResourceVelocity, Scope: evidence.ScopeLane,
			SubjectID: laneBID, Score: 30, Confidence: 85,
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		},
		{
			EvidenceID: "ev_block_2", Code: "NEW_HOSTING_ASN",
			Family: evidence.FamilySourceDiscontinuity, Scope: evidence.ScopeLane,
			SubjectID: laneBID, Score: 15, Confidence: 70,
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		},
		{
			EvidenceID: "ev_block_3", Code: "RAPID_ENDPOINT_OR_MODEL_ENUMERATION",
			Family: evidence.FamilyClientNovelty, Scope: evidence.ScopeLane,
			SubjectID: laneBID, Score: 15, Confidence: 60,
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		},
		{
			EvidenceID: "ev_block_4", Code: "CONCURRENCY_OVER_10X_BASELINE",
			Family: evidence.FamilyResourceVelocity, Scope: evidence.ScopeLane,
			SubjectID: laneBID, Score: 30, Confidence: 85,
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		},
	}
	if err := store.Append(hi...); err != nil {
		t.Fatal(err)
	}

	// Lane B requests now get high lane-risk → BLOCKED → denied.
	outB2 := term.Admit(bearerHeaders(raw), laneB)
	if outB2.Authorized {
		t.Fatal("P0.7: lane B must be BLOCKED after high lane-scoped risk")
	}
	if outB2.Reason != "lane_restricted" {
		t.Fatalf("denial reason = %q, want lane_restricted", outB2.Reason)
	}
	if laneSec := secStatus(t, ls, credM2ID, laneBID); laneSec != lane.LaneBlocked {
		t.Fatalf("lane B security = %v, want BLOCKED", laneSec)
	}

	// Lane A must remain unaffected (Gate I: A continues, B denied).
	outA2 := term.Admit(bearerHeaders(raw), laneA)
	if !outA2.Authorized {
		t.Fatalf("P0.7: lane A must continue authorizing while lane B is blocked: %s", outA2.Reason)
	}
}

const credM2ID = "cred_m2"

func secStatus(t *testing.T, ls *lane.Store, credID, laneID string) lane.SecurityStatus {
	t.Helper()
	if rec, ok := ls.Get(credID, laneID); ok {
		return rec.Security.Status
	}
	t.Fatalf("lane %q not found under %q", laneID, credID)
	return lane.LaneNormal
}
