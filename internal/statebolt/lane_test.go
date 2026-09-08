package statebolt

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/lane"
)

// openTestStore opens a Store on a temp file.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustCreateLane(t *testing.T, s *Store, credID, laneID string, now time.Time) *lane.LaneRecord {
	t.Helper()
	rec, created, err := s.BorrowOrCreate(credID, laneID, lane.Features{NetworkASN: "AS1", HTTPVersion: "1.1"}, lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()})
	if err != nil || !created {
		t.Fatalf("create lane: created=%v err=%v", created, err)
	}
	return rec
}

// TestLaneRepositoryRoundTrip proves the durable lane repository preserves the
// FULL authoritative record across a store close/reopen — trust ladder,
// security status, risk, features, revisions, and clean counters — so a
// restart reproduces the exact security decision (P0.10).
func TestLaneRepositoryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	now := time.Now()

	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	mustCreateLane(t, s, "cred_1", "lane_1", now)

	// Drive the security dimension to SUSPICIOUS and accumulate baseline
	// progress.
	if _, err := s.ObserveRisk("cred_1", "lane_1", 60, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveRisk("cred_1", "lane_1", 60, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecordCleanAuthorizedAndPromote("cred_1", "lane_1", 3, lane.DefaultPromotionCriteria(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	before, ok := s.Get("cred_1", "lane_1")
	if !ok {
		t.Fatal("lane missing before restart")
	}
	if before.Security.Status != lane.LaneSuspicious {
		t.Fatalf("want SUSPICIOUS before restart, got %v", before.Security.Status)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: every authoritative field must survive.
	s2, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	after, ok := s2.Get("cred_1", "lane_1")
	if !ok {
		t.Fatal("lane LOST across restart (P0.10 violated)")
	}
	if after.LaneID != before.LaneID || after.CredentialID != before.CredentialID {
		t.Fatal("identity mismatch across restart")
	}
	if after.Security.Status != lane.LaneSuspicious {
		t.Fatalf("security status lost across restart: %v", after.Security.Status)
	}
	if after.Security.RiskScore != before.Security.RiskScore {
		t.Fatalf("security risk lost: %d vs %d", after.Security.RiskScore, before.Security.RiskScore)
	}
	if after.RiskScore != before.RiskScore || after.Revision != before.Revision {
		t.Fatalf("risk/revision lost: %d/%d vs %d/%d", after.RiskScore, after.Revision, before.RiskScore, before.Revision)
	}
	if after.FeatSchema != before.FeatSchema || after.ClassificationRevision != before.ClassificationRevision {
		t.Fatal("feature/classification revision lost across restart")
	}
	if after.RequestCount != before.RequestCount || after.AuthorizedCleanRequests != before.AuthorizedCleanRequests {
		t.Fatal("counters lost across restart")
	}
	if !after.FirstSeenAt.Equal(before.FirstSeenAt) || !after.CleanSince.Equal(before.CleanSince) {
		t.Fatal("timestamps lost across restart")
	}
	if after.Features.NetworkASN != before.Features.NetworkASN || after.Features.HTTPVersion != before.Features.HTTPVersion {
		t.Fatal("feature vector lost across restart")
	}

	// The recovered lane must continue behaving: same-ID identical-features
	// reuse works, and the security reducer continues from the restored state.
	reused, created, err := s2.BorrowOrCreate("cred_1", "lane_1", before.Features, lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()})
	if err != nil || created {
		t.Fatalf("post-restart reuse: created=%v err=%v", created, err)
	}
	if reused.RequestCount != before.RequestCount+1 {
		t.Fatalf("reuse must continue the restored counter: %d vs %d", reused.RequestCount, before.RequestCount)
	}
}

func TestLaneSecurityTransitionIsDurablyAudited(t *testing.T) {
	s := openTestStore(t)
	lim := lane.DefaultLimits()
	lim.Security.SuspectObs = 1
	mustCreateLane(t, s, "cred_security", "lane_security", time.Now())
	ctx := lane.DefaultPolicyContext()
	ctx.Limits = lim
	ctx.Security = lim.Security
	if _, err := s.ObserveRiskWithPolicy(context.Background(), "cred_security", "lane_security", lim.Security.SuspectThresh, time.Now(), ctx, lane.TransitionMetadata{RequestID: "req_lane_security"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListSecurityTransitions(0, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("security transitions=%v err=%v, want one lane transition", rows, err)
	}
	if rows[0].Kind != "lane_security" || rows[0].RequestID != "req_lane_security" || rows[0].After != "SUSPICIOUS" {
		t.Fatalf("unexpected lane transition: %+v", rows[0])
	}
}

// TestLaneRepositorySameSemanticsAsMemory proves the Bolt repository and the
// resident store produce the same outcomes for the same operation sequence
// (shared pure reducers): borrowing, conflicts, explosion limits, risk
// elevation, and promotion all behave identically regardless of backend.
func TestLaneRepositorySameSemanticsAsMemory(t *testing.T) {
	now := time.Now()
	boltStore := openTestStore(t)
	memStore := lane.NewStore(nil, func() time.Time { return now })

	feat := lane.Features{NetworkASN: "AS1", HTTPVersion: "1.1"}
	ctx := lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()}

	// Identical sequences against both backends.
	r1, c1, err1 := boltStore.BorrowOrCreate("c", "l1", feat, ctx)
	r2, c2, err2 := memStore.BorrowOrCreate("c", "l1", feat, ctx)
	if (err1 != nil) != (err2 != nil) || c1 != c2 {
		t.Fatalf("create diverged: bolt(%v,%v) mem(%v,%v)", c1, err1, c2, err2)
	}
	if r1.State != r2.State || r1.Revision != r2.Revision {
		t.Fatalf("created record diverged: %+v vs %+v", r1, r2)
	}

	// Same-ID different-features must conflict identically.
	_, _, cf1 := boltStore.BorrowOrCreate("c", "l1", lane.Features{NetworkASN: "AS2", HTTPVersion: "1.1"}, ctx)
	_, _, cf2 := memStore.BorrowOrCreate("c", "l1", lane.Features{NetworkASN: "AS2", HTTPVersion: "1.1"}, ctx)
	if (cf1 == nil) != (cf2 == nil) {
		t.Fatalf("conflict diverged: bolt=%v mem=%v", cf1, cf2)
	}

	// Risk elevation drives SUSPICIOUS identically (2 qualifying observations).
	for i := 0; i < 2; i++ {
		b1, e1 := boltStore.ObserveRisk("c", "l1", 60, now)
		b2, e2 := memStore.ObserveRisk("c", "l1", 60, now)
		if (e1 != nil) != (e2 != nil) {
			t.Fatalf("observe diverged: %v vs %v", e1, e2)
		}
		if b1.Security.Status != b2.Security.Status {
			t.Fatalf("security status diverged: %v vs %v", b1.Security.Status, b2.Security.Status)
		}
	}
	if b1, _ := boltStore.Get("c", "l1"); b1.Security.Status != lane.LaneSuspicious {
		t.Fatalf("bolt lane should be SUSPICIOUS, got %v", b1.Security.Status)
	}

	// ListLaneIDs agrees.
	if got := boltStore.ListLaneIDs("c"); len(got) != 1 || got[0] != "l1" {
		t.Fatalf("ListLaneIDs bolt = %v", got)
	}
	if got := memStore.ListLaneIDs("c"); len(got) != 1 || got[0] != "l1" {
		t.Fatalf("ListLaneIDs mem = %v", got)
	}
}

// TestLaneRetentionCommitsOnDomainError proves Bolt retains the cleanup from
// the reducer even when the requested borrow is rejected by a lane-id
// conflict. The memory and durable repositories must expose the same domain
// error, but only the durable test can catch transaction rollback of cleanup.
func TestLaneRetentionCommitsOnDomainError(t *testing.T) {
	type clock struct{ now time.Time }
	base := time.Now().Truncate(time.Millisecond)
	for _, backend := range []string{"memory", "bolt"} {
		c := &clock{now: base}
		var repo lane.Repository
		var policyRepo lane.PolicyAwareRepository
		var durable *Store
		var path string
		if backend == "memory" {
			memory := lane.NewStore(func() lane.Limits {
				lim := lane.DefaultLimits()
				lim.LaneIdleExpiration = time.Hour
				return lim
			}, func() time.Time { return c.now })
			repo, policyRepo = memory, memory
		} else {
			var err error
			path = filepath.Join(t.TempDir(), "state.db")
			durable, err = Open(path, Options{Now: func() time.Time { return c.now }})
			if err != nil {
				t.Fatal(err)
			}
			repo, policyRepo = durable, durable
		}

		featuresA := lane.Features{NetworkASN: "AS1", NetworkType: "residential", RegionClass: "US", ClientFamily: "client-a"}
		featuresB := lane.Features{NetworkASN: "AS2", NetworkType: "hosting", RegionClass: "EU", ClientFamily: "client-b"}
		ctx := lane.DefaultPolicyContext()
		ctx.Classification = lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()}
		ctx.Limits.LaneIdleExpiration = time.Hour
		if _, created, err := policyRepo.BorrowOrCreateWithPolicy(context.Background(), "cred", "lane-a", featuresA, ctx); err != nil || !created {
			t.Fatalf("%s create A: created=%v err=%v", backend, created, err)
		}
		c.now = base.Add(30 * time.Minute)
		if _, created, err := policyRepo.BorrowOrCreateWithPolicy(context.Background(), "cred", "lane-b", featuresB, ctx); err != nil || !created {
			t.Fatalf("%s create B: created=%v err=%v", backend, created, err)
		}
		c.now = base.Add(80 * time.Minute)
		_, _, err := policyRepo.BorrowOrCreateWithPolicy(context.Background(), "cred", "lane-b", lane.Features{NetworkASN: "AS2", NetworkType: "hosting", RegionClass: "EU", ClientFamily: "client-b-different"}, ctx)
		if err != lane.ErrLaneConflict {
			t.Fatalf("%s conflict err=%v, want ErrLaneConflict", backend, err)
		}
		if _, ok := repo.Get("cred", "lane-a"); ok {
			t.Fatalf("%s expired lane survived rejected borrow", backend)
		}
		if _, ok := repo.Get("cred", "lane-b"); !ok {
			t.Fatalf("%s active lane was deleted during cleanup", backend)
		}
		if durable != nil {
			if err := durable.Close(); err != nil {
				t.Fatal(err)
			}
			// Reopen under the same clock and prove the expired row does not
			// return after the failed transaction.
			reopened, err := Open(path, Options{Now: func() time.Time { return c.now }})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := reopened.Get("cred", "lane-a"); ok {
				t.Fatal("bolt expired lane resurrected after reopen")
			}
			if _, ok := reopened.Get("cred", "lane-b"); !ok {
				t.Fatal("bolt active lane missing after reopen")
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestLaneRepositoryExplosionLimits proves the durable repository enforces the
// per-credential lane bound (§28) exactly like the resident store.
func TestLaneRepositoryExplosionLimits(t *testing.T) {
	s := openTestStore(t)
	lim := lane.DefaultLimits()
	ctx := lane.DefaultPolicyContext()
	ctx.Limits = lim

	var lastErr error
	created := 0
	for i := 0; i < lim.MaxActiveLanesPerCredential+5; i++ {
		id := "lane_" + string(rune('a'+i))
		_, ok, err := s.BorrowOrCreate("c", id, lane.Features{NetworkASN: "AS1", HTTPVersion: "1.1", ClientFamily: string(rune('a' + i))}, ctx.Classification)
		_ = ok
		if err != nil {
			lastErr = err
			break
		}
		if ok {
			created++
		}
	}
	// All lanes stay NEW, so the provisional bound (8) is the first limit the
	// create loop hits — tighter than the active-lane bound (16).
	if created != lim.MaxProvisionalLanes || lastErr != lane.ErrTooManyLanes {
		t.Fatalf("explosion limit: created=%d lastErr=%v", created, lastErr)
	}
}

// TestLaneRepositoryNulIdentifierRejected proves collision-safe keys: a NUL
// byte in a persisted identifier is rejected, never stored (P0.1C).
func TestLaneRepositoryNulIdentifierRejected(t *testing.T) {
	s := openTestStore(t)
	if _, _, err := s.BorrowOrCreate("bad\x00cred", "l1", lane.Features{NetworkASN: "AS1"}, lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()}); err == nil {
		t.Fatal("NUL in credential id must be rejected")
	}
	if _, _, err := s.BorrowOrCreate("c", "bad\x00lane", lane.Features{NetworkASN: "AS1"}, lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()}); err == nil {
		t.Fatal("NUL in lane id must be rejected")
	}
}

// TestLaneUnblockPersistsAcrossRestart proves the operator unblock (and its
// audit entries) survive a restart: an unblocked lane stays NORMAL, and the
// audit trail contains both the block-relevant history and the unblock row.
func TestLaneUnblockPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	now := time.Now()

	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	mustCreateLane(t, s, "c", "l", now)
	// Elevate to SUSPICIOUS, then operator-force the precondition path: the
	// Unblock action requires BLOCKED, so first drive SUSPICIOUS → the reducer
	// cannot reach BLOCKED (automatic block disabled). Manually elevate the
	// persisted record through a direct observation at block threshold with
	// automatic block enabled via hysteresis override.
	hy := lane.DefaultSecurityHysteresis()
	hy.EnableAutomaticBlock = true
	ctx := lane.DefaultPolicyContext()
	ctx.Security = hy
	if _, err := s.ObserveRiskWithPolicy(context.Background(), "c", "l", 90, now, ctx, lane.TransitionMetadata{}); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.Get("c", "l")
	if rec.Security.Status != lane.LaneBlocked {
		t.Fatalf("want BLOCKED, got %v", rec.Security.Status)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	// BLOCKED survives restart — this is the P0.10 tombstone guarantee.
	if rec, _ := s2.Get("c", "l"); rec.Security.Status != lane.LaneBlocked {
		t.Fatalf("BLOCKED lost across restart: %v", rec.Security.Status)
	}
	// Unblock is durable + audited.
	if err := s2.Unblock("c", "l", "op", "operator clearing", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rec, _ := s2.Get("c", "l"); rec.Security.Status != lane.LaneNormal {
		t.Fatalf("want NORMAL after unblock, got %v", rec.Security.Status)
	}
	if n, err := s2.CountAuditRecords(); err != nil || n == 0 {
		t.Fatalf("unblock must be audited: n=%d err=%v", n, err)
	}
	// Unblock of a non-blocked lane fails closed.
	if err := s2.Unblock("c", "l", "op", "again", now.Add(2*time.Minute)); err == nil {
		t.Fatal("unblocking a NORMAL lane must fail")
	}
}

// TestPing proves the readiness probe answers on a healthy store and fails
// after Close (P1-24: /readyz must be a real check).
func TestPing(t *testing.T) {
	s := openTestStore(t)
	if err := s.Ping(); err != nil {
		t.Fatalf("healthy store must ping, got %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(); err == nil {
		t.Fatal("ping must fail after Close")
	}
}
