package evidence

import (
	"testing"
	"time"
)

func TestEvidenceValidWithActiveTTL(t *testing.T) {
	now := time.Now()
	e := Evidence{Code: "NEW_ASN", Score: 10, Confidence: 90, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	if !e.Valid(now) {
		t.Fatal("active evidence should be valid")
	}
}

func TestEvidenceExpiredIsInvalid(t *testing.T) {
	now := time.Now()
	e := Evidence{Score: 10, Confidence: 90, CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-24 * time.Hour)}
	if e.Valid(now) {
		t.Fatal("expired evidence must be invalid (§37)")
	}
}

func TestEvidenceRejectsBadScores(t *testing.T) {
	now := time.Now()
	if e := (Evidence{Score: -5, Confidence: 50, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); e.Valid(now) {
		t.Fatal("negative score evidence must be invalid")
	}
	if e := (Evidence{Score: 10, Confidence: 101, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); e.Valid(now) {
		t.Fatal("confidence >100 must be invalid")
	}
}

func TestFamilyCaps(t *testing.T) {
	if FamilySourceDiscontinuity.FamilyCap() != 35 {
		t.Fatalf("source cap = %d, want 35", FamilySourceDiscontinuity.FamilyCap())
	}
	if FamilyOperatorIOC.FamilyCap() != 100 {
		t.Fatalf("operator cap = %d, want 100", FamilyOperatorIOC.FamilyCap())
	}
}

func TestDefaultTableHasKeys(t *testing.T) {
	tbl := DefaultTable()
	for _, code := range []string{"NEW_ASN", "NEW_HOSTING_ASN", "NEW_COUNTRY", "CONCURRENCY_OVER_4X_BASELINE",
		"TOKEN_VELOCITY_OVER_10X_BASELINE", "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS", "MANUAL_CONFIRMED_COMPROMISE"} {
		if _, ok := tbl[code]; !ok {
			t.Fatalf("missing default evidence rule: %s", code)
		}
	}
}

func TestEvidenceScopeString(t *testing.T) {
	if ScopeLane.String() != "LANE" || ScopeCredential.String() != "CREDENTIAL" || ScopeSource.String() != "SOURCE" {
		t.Fatal("scope string mapping broken")
	}
}

// Regression (§36): a zero-TTL rule means "does not self-expire" — the minted
// evidence must carry a zero ExpiresAt (unbounded under Valid), not
// ExpiresAt == CreatedAt (which expires the instant after creation and would
// silently evaporate an operator IOC like MANUAL_CONFIRMED_COMPROMISE).
func TestZeroTTLRuleMeansNeverExpires(t *testing.T) {
	now := time.Now()
	rule := Rule{TTL: 0} // e.g. MANUAL_CONFIRMED_COMPROMISE: until revoked
	ev := Evidence{
		Code:      "MANUAL_CONFIRMED_COMPROMISE",
		Family:    FamilyOperatorIOC,
		Score:     rule.Score,
		CreatedAt: now,
	}
	if rule.TTL > 0 {
		ev.ExpiresAt = now.Add(rule.TTL)
	}
	if !ev.Valid(now) {
		t.Fatal("zero-TTL evidence must be valid at mint time")
	}
	if !ev.ExpiresAt.IsZero() {
		t.Fatal("zero-TTL rule must mint a zero (unbounded) ExpiresAt")
	}
	if !ev.Valid(now.Add(365 * 24 * time.Hour)) {
		t.Fatal("zero-TTL evidence must remain valid a year later")
	}
	// And a positive-TTL rule still expires on schedule.
	positive := Evidence{CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour)}
	if !positive.Valid(now.Add(7*24*time.Hour - time.Second)) {
		t.Fatal("positive-TTL evidence must be valid just before expiry")
	}
	if positive.Valid(now.Add(7*24*time.Hour + time.Second)) {
		t.Fatal("positive-TTL evidence must expire on schedule")
	}
}
