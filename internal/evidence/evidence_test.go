package evidence

import (
	"testing"
	"time"
)

func TestEvidenceValidWithActiveTTL(t *testing.T) {
	now := time.Now()
	e := Evidence{Code: "NEW_ASN", SubjectID: "cred_1", Family: FamilySourceDiscontinuity,
		Scope: ScopeLane, Score: 10, Confidence: 90, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	if !e.Valid(now) {
		t.Fatal("active evidence should be valid")
	}
}

func TestEvidenceExpiredIsInvalid(t *testing.T) {
	now := time.Now()
	e := Evidence{Code: "NEW_ASN", SubjectID: "cred_1", Score: 10, Confidence: 90,
		CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-24 * time.Hour)}
	if e.Valid(now) {
		t.Fatal("expired evidence must be invalid (§37)")
	}
}

func TestEvidenceRejectsBadScores(t *testing.T) {
	now := time.Now()
	mk := func(mutate func(*Evidence)) Evidence {
		e := Evidence{Code: "NEW_ASN", SubjectID: "cred_1", Score: 10, Confidence: 50,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		mutate(&e)
		return e
	}
	if mk(func(e *Evidence) { e.Score = -5 }).Valid(now) {
		t.Fatal("negative score evidence must be invalid")
	}
	if mk(func(e *Evidence) { e.Confidence = 101 }).Valid(now) {
		t.Fatal("confidence >100 must be invalid")
	}
	if mk(func(e *Evidence) { e.SubjectID = "" }).Valid(now) {
		t.Fatal("empty subject must be invalid (P0.11)")
	}
	if mk(func(e *Evidence) { e.Code = "" }).Valid(now) {
		t.Fatal("empty code must be invalid")
	}
	if mk(func(e *Evidence) { e.Family = Family(99) }).Valid(now) {
		t.Fatal("unknown family must be invalid")
	}
	if mk(func(e *Evidence) { e.Scope = Scope(99) }).Valid(now) {
		t.Fatal("unknown scope must be invalid")
	}
	if mk(func(e *Evidence) { e.CreatedAt = now.Add(time.Minute) }).Valid(now) {
		t.Fatal("future-created evidence must be invalid (P0.11)")
	}
	if mk(func(e *Evidence) { e.ExpiresAt = e.CreatedAt.Add(-time.Second) }).Valid(now) {
		t.Fatal("expiry before creation must be invalid")
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

// --- P0.11: trusted minting --------------------------------------------------

// Regression (P0.11): Mint is the only sanctioned evidence producer — every
// security-relevant field comes from the rule table, and unknown codes are
// rejected rather than invented.
func TestMintPopulatesFromTable(t *testing.T) {
	now := time.Now()
	tbl := DefaultTable()
	want := tbl["NEW_HOSTING_ASN"]

	ev, err := Mint(tbl, "NEW_HOSTING_ASN", "cred_9", now, 7)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if ev.Family != want.Family || ev.Scope != want.Scope || ev.Score != want.Score ||
		ev.Severity != want.Severity || ev.Confidence != want.Confidence ||
		ev.CorrelationGroup != want.CorrelationGroup {
		t.Fatalf("minted evidence does not match the rule: %+v", ev)
	}
	if ev.SubjectID != "cred_9" || ev.PolicyRevision != 7 {
		t.Fatalf("subject/revision not bound: %+v", ev)
	}
	if !ev.ExpiresAt.Equal(now.Add(want.TTL)) {
		t.Fatalf("TTL not applied from the rule: %v", ev.ExpiresAt)
	}
	if !ev.Valid(now) {
		t.Fatal("minted evidence must be valid")
	}
}

func TestMintRejectsUnknownCodeAndEmptySubject(t *testing.T) {
	tbl := DefaultTable()
	if _, err := Mint(tbl, "TOTALLY_MADE_UP_CODE", "cred_1", time.Now(), 1); err == nil {
		t.Fatal("unknown code must be rejected (P0.11)")
	}
	if _, err := Mint(tbl, "NEW_ASN", "", time.Now(), 1); err == nil {
		t.Fatal("empty subject must be rejected")
	}
	if _, err := Mint(nil, "NEW_ASN", "cred_1", time.Now(), 1); err == nil {
		t.Fatal("nil table must be rejected")
	}
}

// Regression (P0.11): a zero-TTL rule mints UNBOUNDED evidence (zero
// ExpiresAt), not evidence that expires the instant after creation —
// MANUAL_CONFIRMED_COMPROMISE must remain active until explicit revocation.
func TestMintZeroTTLMeansUnbounded(t *testing.T) {
	now := time.Now()
	ev, err := Mint(DefaultTable(), "MANUAL_CONFIRMED_COMPROMISE", "cred_1", now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.ExpiresAt.IsZero() {
		t.Fatalf("zero-TTL rule must mint zero ExpiresAt, got %v", ev.ExpiresAt)
	}
	if !ev.Valid(now.Add(365 * 24 * time.Hour)) {
		t.Fatal("operator IOC must remain valid a year later (until revoked)")
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
		SubjectID: "cred_1",
		Family:    FamilyOperatorIOC,
		Scope:     ScopeCredential,
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
	positive := Evidence{Code: "NEW_ASN", SubjectID: "cred_1", CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour)}
	if !positive.Valid(now.Add(7*24*time.Hour - time.Second)) {
		t.Fatal("positive-TTL evidence must be valid just before expiry")
	}
	if positive.Valid(now.Add(7*24*time.Hour + time.Second)) {
		t.Fatal("positive-TTL evidence must expire on schedule")
	}
}
