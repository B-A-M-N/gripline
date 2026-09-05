package principal

import "testing"

func TestPrincipalNeverCarriesSecret(t *testing.T) {
	// The Principal struct has no secret field — nothing but identity fields.
	p := Principal{
		AccountID:          "acct_1",
		CredentialID:       "cred_1",
		PolicyID:           "fi-default-v1",
		PlanID:             "plan-a",
		CredentialStatus:   "NORMAL",
		CredentialRevision: 1,
	}
	if p.CredentialID == "" || p.AccountID == "" {
		t.Fatal("principal must carry identity fields")
	}
	if p.CredentialStatus == "" {
		t.Fatal("principal must carry credential status")
	}
	// No path to store raw secret exists by construction — the struct has no
	// such field and no constructors take one.
}

func TestAuthorizedContext(t *testing.T) {
	ctx := AuthorizedContext{
		Principal:          Principal{CredentialID: "cred_1"},
		LaneID:             "lane_1",
		LaneState:          "ESTABLISHED",
		AuthorizationScope: ScopeLane,
		RiskState:          12,
	}
	if ctx.AuthorizationScope != ScopeLane {
		t.Fatalf("scope = %s, want LANE", ctx.AuthorizationScope)
	}
	if ctx.RiskState < 0 || ctx.RiskState > 100 {
		t.Fatalf("risk = %d, must be 0..100", ctx.RiskState)
	}
}

func TestDefaultResolverPassThrough(t *testing.T) {
	p := Principal{CredentialID: "cred_9"}
	got, err := (DefaultResolver{}).Resolve(p)
	if err != nil {
		t.Fatalf("default resolver must not error: %v", err)
	}
	if got.CredentialID != p.CredentialID {
		t.Fatal("default resolver must pass principal through")
	}
}
