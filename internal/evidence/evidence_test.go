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
