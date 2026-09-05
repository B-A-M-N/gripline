package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/freeinference/gripline/internal/evidence"
)

func ev(code string, scope evidence.Scope, subject string, score int, grp string, createdAgo, ttl time.Duration) evidence.Evidence {
	base := time.Now()
	return evidence.Evidence{
		EvidenceID:       code + ":" + subject,
		Code:             code,
		Family:           table()[code].Family,
		Scope:            scope,
		SubjectID:        subject,
		Score:            score,
		Confidence:       80,
		CreatedAt:        base.Add(-createdAgo),
		ExpiresAt:        base.Add(ttl),
		CorrelationGroup: grp,
	}
}

func table() evidence.Table { return evidence.DefaultTable() }

func now() time.Time { return time.Now() }

// untilRevokedIOC builds a MANUAL_CONFIRMED_COMPROMISE evidence with no TTL
// (ExpiresAt zero = until revoked, per §37).
func untilRevokedIOC(subject string) evidence.Evidence {
	return evidence.Evidence{
		EvidenceID: subject, Code: "MANUAL_CONFIRMED_COMPROMISE",
		Family: evidence.FamilyOperatorIOC, Scope: evidence.ScopeCredential,
		SubjectID: subject, Score: 100, Confidence: 100, CreatedAt: time.Now(),
	}
}

func TestRiskIsClampedToBounds(t *testing.T) {
	// MANUAL_CONFIRMED_COMPROMISE is an until-revoked indicator (no TTL).
	one := []evidence.Evidence{untilRevokedIOC("c1")}
	if s := Evaluate(one, now()); s != 100 {
		t.Fatalf("operator IOC should yield 100, got %d", s)
	}

	// Many high RESOURCE_VELOCITY signals cap at the family cap (35), not sum.
	var many []evidence.Evidence
	for i := 0; i < 20; i++ {
		many = append(many, ev("CONCURRENCY_OVER_10X_BASELINE", evidence.ScopeLane, "c", 30, "", 0, time.Hour))
	}
	s := Evaluate(many, now())
	if s != 35 {
		t.Fatalf("ResourceVelocity family should cap at 35, got %d", s)
	}

	// Global 100 clamp: spread signals across families so the sum would exceed 100.
	spread := []evidence.Evidence{
		untilRevokedIOC("c2"),
		ev("NEW_HOSTING_ASN", evidence.ScopeLane, "c2", 15, "", 0, 24*time.Hour),
		ev("SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS", evidence.ScopeSource, "c2", 35, "", 0, time.Minute),
	}
	s = Evaluate(spread, now())
	if s > 100 || s < 0 {
		t.Fatal("risk must remain within 0..100")
	}
	if s != 100 {
		t.Fatalf("cross-family sum should clamp at 100, got %d", s)
	}
}

func TestFamilyCapsLimitDoubleCounting(t *testing.T) {
	// 10 unrelated-lane signals each +20 → family cap 40 must cap the
	// RESOURCE/ABUSE contribution.
	var items []evidence.Evidence
	for i := 0; i < 10; i++ {
		items = append(items, ev("SIMULTANEOUS_ESTABLISHED_LANE_FROM_UNRELATED_ASN", evidence.ScopeCredential, "c", 20, "", 0, time.Minute))
	}
	s := Evaluate(items, now())
	if s > 40 {
		t.Fatalf("ABUSE_CORRELATION family cap 40 exceeded: got %d", s)
	}
}

func TestCorrelationGroupBoundedReducer(t *testing.T) {
	// All three signals trace to ONE location transition → correlate to max, not sum.
	base := now()
	items := []evidence.Evidence{
		{EvidenceID: "1", Code: "NEW_ASN", Family: evidence.FamilySourceDiscontinuity, Scope: evidence.ScopeLane, SubjectID: "c", Score: 10, Confidence: 90, CreatedAt: base.Add(-5 * time.Minute), ExpiresAt: base.Add(24 * time.Hour), CorrelationGroup: "location"},
		{EvidenceID: "2", Code: "NEW_HOSTING_ASN", Family: evidence.FamilySourceDiscontinuity, Scope: evidence.ScopeLane, SubjectID: "c", Score: 15, Confidence: 90, CreatedAt: base.Add(-5 * time.Minute), ExpiresAt: base.Add(24 * time.Hour), CorrelationGroup: "location"},
		{EvidenceID: "3", Code: "NEW_COUNTRY", Family: evidence.FamilySourceDiscontinuity, Scope: evidence.ScopeLane, SubjectID: "c", Score: 15, Confidence: 90, CreatedAt: base.Add(-5 * time.Minute), ExpiresAt: base.Add(24 * time.Hour), CorrelationGroup: "location"},
	}
	// With correlation: group best = 15 (not 10+15+15=40).
	if s := Evaluate(items, base); s != 15 {
		t.Fatalf("correlated group should use max (15), got %d", s)
	}
}

func TestExpiredEvidenceStopsInfluencing(t *testing.T) {
	base := time.Now()
	active := []evidence.Evidence{
		{EvidenceID: "a", Code: "NEW_ASN", Family: evidence.FamilySourceDiscontinuity, Scope: evidence.ScopeLane, SubjectID: "c", Score: 10, Confidence: 90, CreatedAt: base.Add(-time.Hour), ExpiresAt: base.Add(time.Hour), CorrelationGroup: "loc"},
	}
	expired := []evidence.Evidence{
		{EvidenceID: "e", Code: "NEW_ASN", Family: evidence.FamilySourceDiscontinuity, Scope: evidence.ScopeLane, SubjectID: "c", Score: 10, Confidence: 90, CreatedAt: base.Add(-48 * time.Hour), ExpiresAt: base.Add(-24 * time.Hour), CorrelationGroup: "loc"},
	}
	if Evaluate(active, base) != 10 {
		t.Fatal("active evidence should count")
	}
	if Evaluate(expired, base) != 0 {
		t.Fatal("expired evidence must not influence risk (§37, INV-risk)")
	}
}

func TestStateWrapsAndClamps(t *testing.T) {
	st := NewState(250)
	if st.Score() != 100 {
		t.Fatalf("initial clamp expected 100, got %d", st.Score())
	}
	st = NewState(-5)
	if st.Score() != 0 {
		t.Fatalf("initial clamp expected 0, got %d", st.Score())
	}
}

// FuzzRiskBounds asserts the invariant risk ∈ [0,100] for arbitrary evidence
// mixes. Run with `go test -fuzz=FuzzRiskBounds`.
func FuzzRiskBounds(f *testing.F) {
	f.Add(0, 0, 0) // (score, confidence, nItems)
	f.Fuzz(func(t *testing.T, score, conf, n int) {
		if n < 0 || n > 100 {
			return // drive n through a bounded cardinality
		}
		items := make([]evidence.Evidence, 0, n)
		base := time.Now()
		codes := []string{"NEW_ASN", "NEW_HOSTING_ASN", "CONCURRENCY_OVER_10X_BASELINE", "MANUAL_CONFIRMED_COMPROMISE"}
		for i := 0; i < n && i < 100; i++ {
			code := codes[i%len(codes)]
			items = append(items, evidence.Evidence{
				Code: code, Family: familyFor(code), Score: sanitize(score), Confidence: sanitize(conf),
				CreatedAt: base.Add(-time.Minute), ExpiresAt: base.Add(time.Hour),
			})
		}
		s := Evaluate(items, base)
		if s < 0 || s > 100 {
			t.Fatalf("risk out of bounds: %d", s)
		}
	})
}

func sanitize(v int) int {
	if v > 1000 {
		return v % 1000
	}
	if v < 0 {
		return 0
	}
	return v
}

func familyFor(code string) evidence.Family {
	if strings.Contains(code, "ASN") {
		return evidence.FamilySourceDiscontinuity
	}
	return evidence.FamilyResourceVelocity
}
