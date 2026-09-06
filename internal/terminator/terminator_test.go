package terminator

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

// --- assertion verification: INV-10, INV-11 ---------------------------------

func TestAssertionSignAndVerify(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	a, err := signer.Issue(Claims{
		Subject: "acct_1", CredID: "cred_1", LaneID: "lane_1",
		Audience: "fi-inference", JTI: "req_1", PolicyRev: 1, CredRev: 1, Scope: []string{"inference"},
	}, 30*time.Second)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	enc := a.Encode()
	if enc == "" {
		t.Fatal("assertion must encode")
	}
	claims, err := ParseAndVerify(enc, signer.Public(), "fi-inference", time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "acct_1" || claims.Audience != "fi-inference" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	if claims.CredID != "cred_1" || claims.LaneID != "lane_1" {
		t.Fatalf("credential/context claims missing: %+v", claims)
	}
}

func TestExpiredAssertionFailsINV10(t *testing.T) {
	signer, _ := GenerateSigner()
	a, _ := signer.Issue(Claims{Subject: "s", Audience: "aud", JTI: "j"}, 30*time.Second)
	if _, err := ParseAndVerify(a.Encode(), signer.Public(), "aud", time.Now().Add(31*time.Second)); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestWrongAudienceFailsINV11(t *testing.T) {
	signer, _ := GenerateSigner()
	a, _ := signer.Issue(Claims{Subject: "s", Audience: "fi-inference", JTI: "j"}, 30*time.Second)
	if _, err := ParseAndVerify(a.Encode(), signer.Public(), "some-other-aud", time.Now()); err != ErrWrongAudience {
		t.Fatalf("want ErrWrongAudience, got %v", err)
	}
}

func TestTamperedAssertionFails(t *testing.T) {
	signer, _ := GenerateSigner()
	a, _ := signer.Issue(Claims{Subject: "s", Audience: "aud", JTI: "j"}, 30*time.Second)
	if _, err := ParseAndVerify(a.Encode()+"x", signer.Public(), "aud", time.Now()); err == nil {
		t.Fatal("tampered assertion must fail verification")
	}
}

// Regression: the verifier must reject assertions minted by a different issuer
// even when correctly signed with a trusted key (internal-identity spoofing).
func TestWrongIssuerRejected(t *testing.T) {
	signer, _ := GenerateSigner()
	a, err := signer.Issue(Claims{Subject: "s", Audience: "aud", JTI: "j"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// The issuer is forced to "gripline" on Issue; craft a foreign-issuer
	// payload by re-signing claims with a different issuer value.
	forged := Claims{Issuer: "other-service", Subject: "s", Audience: "aud", JTI: "j",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(30 * time.Second).Unix()}
	payload, _ := json.Marshal(forged)
	sig := ed25519.Sign(signer.priv, payload)
	enc := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := ParseAndVerify(enc, signer.Public(), "aud", time.Now()); err != ErrWrongIssuer {
		t.Fatalf("want ErrWrongIssuer, got %v", err)
	}
	_ = a
}

// Regression: a signed assertion claiming a lifetime beyond the supported TTL
// bound must be rejected — defends against signer-key misuse minting
// long-lived identities (INV-10 defense in depth).
func TestOverTTLAssertionRejected(t *testing.T) {
	signer, _ := GenerateSigner()
	now := time.Now()
	claims := Claims{
		Issuer: "gripline", Subject: "s", CredID: "cred_1", Audience: "aud", JTI: "j",
		// Valid "now" window but a 2-hour lifetime — over the TTL bound.
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(2 * time.Hour).Unix(),
	}
	payload, _ := json.Marshal(claims)
	sig := ed25519.Sign(signer.priv, payload)
	enc := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := ParseAndVerify(enc, signer.Public(), "aud", now); err != ErrTTLTooLong {
		t.Fatalf("want ErrTTLTooLong, got %v", err)
	}
}

// Regression: exp is inclusive-invalid — an assertion is expired AT its expiry
// second (now == exp), not only after it.
func TestAssertionExpiredAtExactExpiry(t *testing.T) {
	signer, _ := GenerateSigner()
	a, _ := signer.Issue(Claims{Subject: "s", CredID: "cred_x", Audience: "aud", JTI: "j"}, 30*time.Second)
	enc := a.Encode()
	atExp := time.Unix(a.Claims().ExpiresAt, 0)
	if _, err := ParseAndVerify(enc, signer.Public(), "aud", atExp); err != ErrExpired {
		t.Fatalf("want ErrExpired at now==exp, got %v", err)
	}
	// One second before expiry it is still valid.
	if _, err := ParseAndVerify(enc, signer.Public(), "aud", atExp.Add(-time.Second)); err != nil {
		t.Fatalf("valid one second before expiry: %v", err)
	}
}

// --- admission flow ---------------------------------------------------------

type fakePool struct{ p *resource.ConcurrencyPool }

func (f *fakePool) Acquire(scope string, maxConcurrency int) *resource.LeaseHandle {
	return f.p.AcquireCap(maxConcurrency)
}

// buildTerminator wires a terminator around a single credential and returns the
// raw token string the test uses to act as the client.
func buildTerminator(t *testing.T, status credential.Status, concurrency *resource.ConcurrencyPool) (*Terminator, string) {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	tc := makeCredentialWithStatus("cred_a", "acct_1", status, pep)

	signer, _ := GenerateSigner()
	dep := Dependencies{
		Registry: tc.reg,
		Peppers:  credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
	}
	if concurrency != nil {
		dep.Concurrency = &fakePool{concurrency}
	}
	term, err := New(dep)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return term, tc.raw
}

// makeCredentialWithStatus builds a registry entry and returns the raw token.
func makeCredentialWithStatus(id, account string, status credential.Status, pep *credential.PepperKey) struct {
	reg *credential.MemoryRegistry
	raw string
} {
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: id, AccountID: account,
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: pep.Version,
		Status: status, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		panic(err) // test fixture construction must succeed
	}
	return struct {
		reg *credential.MemoryRegistry
		raw string
	}{reg: reg, raw: raw}
}

func bearerHeaders(tok string) map[string][]string {
	return map[string][]string{"Authorization": {"Bearer " + tok}}
}

func TestAdmitValidCredential(t *testing.T) {
	term, raw := buildTerminator(t, credential.StatusNormal, nil)
	out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out.Authorized {
		t.Fatalf("valid credential denied: %s err=%v", out.Reason, out.DenialErr)
	}
	if out.Assertion == nil {
		t.Fatal("authorized request must carry an internal assertion")
	}
	if out.Principal.AccountID != "acct_1" || out.Principal.CredentialID != "cred_a" {
		t.Fatalf("wrong principal: %+v", out.Principal)
	}
	// The internal assertion must never carry the raw credential (INV-3).
	if assertContains(out.Assertion.Encode(), raw) {
		t.Fatal("internal assertion must not contain the raw credential")
	}
}

func TestAdmitInvalidCredential(t *testing.T) {
	term, _ := buildTerminator(t, credential.StatusNormal, nil)
	out := term.Admit(bearerHeaders("sk-definitely-not-the-key"), lane.Features{})
	if out.Authorized {
		t.Fatal("unknown credential must be denied")
	}
	if out.Reason != "invalid_credential" {
		t.Fatalf("reason = %s, want invalid_credential", out.Reason)
	}
}

func TestAdmitRevokedCredential(t *testing.T) {
	term, raw := buildTerminator(t, credential.StatusRevoked, nil)
	out := term.Admit(bearerHeaders(raw), lane.Features{})
	if out.Authorized {
		t.Fatal("revoked credential must never authenticate (INV-13)")
	}
}

// Regression: quarantine must deny at authentication (§30), not ride through
// to policy with a permissive lane.
func TestAdmitQuarantinedCredentialDenied(t *testing.T) {
	term, raw := buildTerminator(t, credential.StatusQuarantined, nil)
	out := term.Admit(bearerHeaders(raw), lane.Features{})
	if out.Authorized {
		t.Fatal("quarantined credential must be denied at authentication (§30)")
	}
	if out.Reason != "credential_restricted" {
		t.Fatalf("reason = %s, want credential_restricted", out.Reason)
	}
}

// Regression: an expired credential record must fail authentication (§75).
func TestAdmitExpiredCredentialDenied(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_e", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), PepperVersion: 1,
		Status:    credential.StatusNormal,
		ExpiresAt: time.Now().Add(-time.Minute), // already expired
		Revision:  1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := GenerateSigner()
	term, err := New(Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Policy: policy.Default(), Signer: signer, Audience: "fi-inference",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := term.Admit(bearerHeaders(raw), lane.Features{})
	if out.Authorized {
		t.Fatal("expired credential must never authenticate (§75)")
	}
	if out.Reason != "credential_expired" {
		t.Fatalf("reason = %s, want credential_expired", out.Reason)
	}
}

// Regression: lane explosion is an attack signal and must fail closed (§28).
func TestAdmitLaneExplosionDenied(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	tc := makeCredentialWithStatus("cred_x", "acct_1", credential.StatusNormal, pep)
	signer, _ := GenerateSigner()
	store := lane.NewStore(func() lane.Limits {
		return lane.Limits{MaxActiveLanesPerCredential: 2, LaneIdleExpiration: time.Hour}
	}, time.Now)
	term, err := New(Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Lanes: store, Policy: policy.Default(), Signer: signer, Audience: "fi-inference",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fill the two lane slots with distinct networks.
	feats := []lane.Features{
		{NetworkASN: "AS1", RegionClass: "r1"},
		{NetworkASN: "AS2", RegionClass: "r2"},
	}
	for _, f := range feats {
		out := term.Admit(bearerHeaders(tc.raw), f)
		if !out.Authorized {
			t.Fatalf("expected first lanes to authorize: %s", out.Reason)
		}
	}
	// Third distinct network → explosion limit → deny (not silently allow).
	out := term.Admit(bearerHeaders(tc.raw), lane.Features{NetworkASN: "AS3", RegionClass: "r3"})
	if out.Authorized {
		t.Fatal("lane explosion must fail closed (§28)")
	}
	if out.Reason != "lane_limit_exceeded" {
		t.Fatalf("reason = %s, want lane_limit_exceeded", out.Reason)
	}
}

func TestAdmitAmbiguousAuthFails(t *testing.T) {
	term, raw := buildTerminator(t, credential.StatusNormal, nil)
	h := map[string][]string{
		"Authorization": {"Bearer " + raw},
		"x-api-key":     {"some-other-key"},
	}
	out := term.Admit(h, lane.Features{})
	if out.Authorized {
		t.Fatal("conflicting carriers must fail closed")
	}
	if out.Reason != "invalid_authentication" {
		t.Fatalf("reason = %s", out.Reason)
	}
	// Secret headers must be stripped even on failure (INV-12 hygiene).
	if _, ok := h["Authorization"]; ok {
		t.Fatal("Authorization must be stripped after extraction")
	}
	if _, ok := h["x-api-key"]; ok {
		t.Fatal("x-api-key must be stripped after extraction")
	}
}

func TestAdmitConcurrencyLimitDenies(t *testing.T) {
	pool := resource.NewConcurrencyPool(1)
	term, raw := buildTerminator(t, credential.StatusNormal, pool)
	// Hold the only slot so a new admit must be denied.
	held := pool.Acquire()
	defer held.Release()
	out := term.Admit(bearerHeaders(raw), lane.Features{})
	if out.Authorized {
		t.Fatal("over concurrency must deny before issuing internal identity (INV-6)")
	}
	if out.Reason != "concurrency_limit" {
		t.Fatalf("reason = %s, want concurrency_limit", out.Reason)
	}
}

func TestAdmitReleasesLeaseOnCompletion(t *testing.T) {
	pool := resource.NewConcurrencyPool(1)
	term, raw := buildTerminator(t, credential.StatusNormal, pool)
	out := term.Admit(bearerHeaders(raw), lane.Features{})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	if out.Lease == nil {
		t.Fatal("authorized request must hold a concurrency lease")
	}
	out.Lease.Release()
	if pool.Balance() != 1 {
		t.Fatalf("after release balance = %d, want 1 (INV-15)", pool.Balance())
	}
}

// Regression (INV-15 / §48): when assertion issuance fails after the lease is
// acquired, the lease must be released — a failed admit must never leak a
// concurrency slot permanently.
func TestAdmitReleasesLeaseWhenIdentityFails(t *testing.T) {
	pool := resource.NewConcurrencyPool(1)
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	tc := makeCredentialWithStatus("cred_l", "acct_1", credential.StatusNormal, pep)
	term, err := New(Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Policy:      policy.Default(),
		Signer:      failingSigner{}, // identity issuance fails after lease acquisition
		Audience:    "fi-inference",
		Concurrency: &fakePool{pool},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := term.Admit(bearerHeaders(tc.raw), lane.Features{})
	if out.Authorized {
		t.Fatal("admit must fail when identity cannot be issued")
	}
	if pool.Balance() != 1 {
		t.Fatalf("lease leaked on identity failure: balance = %d, want 1 (INV-15)", pool.Balance())
	}
}

// failingSigner always fails to mint an assertion (§60: signer outage fails
// closed).
type failingSigner struct{}

func (failingSigner) Issue(_ Claims, _ time.Duration) (*Assertion, error) {
	return nil, errors.New("signer unavailable")
}

func TestAdmitStripsSecretAndZeroes(t *testing.T) {
	term, raw := buildTerminator(t, credential.StatusNormal, nil)
	h := bearerHeaders(raw)
	out := term.Admit(h, lane.Features{})
	if !out.Authorized {
		t.Fatal("should authorize")
	}
	if _, ok := h["Authorization"]; ok {
		t.Fatal("Authorization must be stripped after extraction (§18)")
	}
}

// assertContains reports whether haystack contains needle as a substring.
func assertContains(haystack, needle string) bool {
	return len(needle) > 0 && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// Regression (§24): a lane-id collision surfaces as a distinct, fail-closed
// denial — never as a state reset of the colliding lane and never as a
// generic "authorized" outcome.
func TestAdmitLaneCollisionFailsClosed(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	tc := makeCredentialWithStatus("cred_c", "acct_1", credential.StatusNormal, pep)
	signer, _ := GenerateSigner()
	store := lane.NewStore(func() lane.Limits {
		return lane.Limits{MaxActiveLanesPerCredential: 8, MaxProvisionalLanes: 8, LaneIdleExpiration: time.Hour}
	}, time.Now)
	term, err := New(Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Lanes: store, Policy: policy.Default(), Signer: signer, Audience: "fi-inference",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Force a collision: pre-create a lane whose id equals the derivation the
	// terminator will produce for these features, with dissimilar stored
	// features so similarity cannot Match. BorrowOrCreate takes the caller's
	// id verbatim, so the seeded row lands exactly on the future collide id.
	collideFeat := lane.Features{NetworkASN: "AS-ATTACK", RegionClass: "r1"}
	collideID := "lane_cred_c_" + shortTag(collideFeat)
	if _, created, err := store.BorrowOrCreate("cred_c", collideID,
		lane.Features{NetworkASN: "AS-DIFFERENT", RegionClass: "r2"}, lane.DefaultThresholds()); err != nil || !created {
		t.Fatalf("seed lane: created=%v err=%v", created, err)
	}

	out := term.Admit(bearerHeaders(tc.raw), collideFeat)
	if out.Authorized {
		t.Fatal("collision must fail closed")
	}
	if out.Reason != "lane_conflict" {
		t.Fatalf("reason = %s, want lane_conflict", out.Reason)
	}
	// The seeded lane's stored features must be untouched.
	got, _ := store.Get("cred_c", collideID)
	if got == nil || got.Features.NetworkASN != "AS-DIFFERENT" {
		t.Fatalf("seeded lane was mutated: %+v", got)
	}
}

// --- P0.5/P0.6/P0.12 regressions --------------------------------------------

// Regression (P0.5): mutating the caller's *policy.Policy after New must not
// alter live enforcement — the terminator enforces a snapshot taken at
// construction.
func TestPolicyMutationAfterNewCannotAlterEnforcement(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	tc := makeCredentialWithStatus("cred_pm", "acct_1", credential.StatusNormal, pep)
	pol := policy.Default()
	signer, _ := GenerateSigner()
	term, err := New(Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Policy: pol, Signer: signer, Audience: "fi-inference",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mutate every security-relevant field of the live policy object.
	pol.Risk.Quarantine = 1 // would deny everything at any risk
	pol.Identity.MaxTTLSeconds = 60
	pol.Revision = 999

	// P0.10: mutate the REFERENCE-BEARING field too. The old shallow struct
	// copy shared EvidenceRules with the compiled snapshot — this write would
	// rewrite live enforcement (e.g. inflate NEW_LANE score) after New().
	pol.EvidenceRules["NEW_LANE"] = evidence.Rule{
		Family: evidence.FamilyAbuseCorrelation, Score: 100, Severity: 5,
		Confidence: 100, TTL: 24 * time.Hour,
	}
	pol.EvidenceRules["NONEXISTENT_INJECTED_RULE"] = evidence.Rule{
		Family: evidence.FamilyAbuseCorrelation, Score: 100, Severity: 5,
		Confidence: 100, TTL: 24 * time.Hour,
	}
	pol.Classification.Match = 0.01 // would collapse every candidate into any lane

	out := term.Admit(bearerHeaders(tc.raw), lane.Features{})
	if !out.Authorized {
		t.Fatalf("snapshot policy must still authorize a clean request: %s %v", out.Reason, out.DenialErr)
	}
	if out.Context.Principal.CredentialID != "cred_pm" {
		t.Fatalf("wrong principal: %+v", out.Context.Principal)
	}
	if out.Assertion.Claims().PolicyRev != 1 {
		t.Fatalf("assertion must carry the snapshot revision 1, got %d", out.Assertion.Claims().PolicyRev)
	}
	if out.Assertion.Claims().CredID == "" {
		t.Fatal("assertion must carry the credential id")
	}

	// P0.10 continued: the compiled evidence table must be the ORIGINAL
	// DefaultTable parameters, not the mutated ones — the injected rule must
	// not mint, and NEW_LANE must keep its default parameters. Construct an
	// ENFORCE terminator with a valid policy, inject into the caller's table
	// AFTER construction, and verify the injection never reaches enforcement.
	enfPol := policy.Default()
	enfTerm, err := New(Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   enfPol, Signer: signer, Audience: "fi-inference",
		Evidence:    evidence.NewMemoryStore(),
		Concurrency: &fakePool{resource.NewConcurrencyPool(16)},
	})
	if err != nil {
		t.Fatal(err)
	}
	enfPol.EvidenceRules["NONEXISTENT_INJECTED_RULE"] = evidence.Rule{
		Family: evidence.FamilyAbuseCorrelation, Scope: evidence.ScopeCredential,
		Score: 100, Severity: 5, Confidence: 100, TTL: 24 * time.Hour,
	}
	enfPol.EvidenceRules["NEW_LANE"] = evidence.Rule{
		Family: evidence.FamilyAbuseCorrelation, Scope: evidence.ScopeLane,
		Score: 100, Severity: 5, Confidence: 100, TTL: 24 * time.Hour,
	}
	out2 := enfTerm.Admit(bearerHeaders(tc.raw), laneFeatures("AS1"))
	if !out2.Authorized {
		t.Fatalf("clean request must authorize: %s", out2.Reason)
	}
	for _, code := range out2.Evidence {
		if code == "NONEXISTENT_INJECTED_RULE" {
			t.Fatal("post-New injected evidence rule must not mint (P0.10)")
		}
	}
	// The authorized outcome itself proves NEW_LANE kept its compiled score:
	// the injected 100-score NEW_LANE rule would have pushed risk to QUARANTINE
	// and denied this clean request.
}

// Regression (P0.5): a credential whose PolicyID differs from the loaded
// policy must fail closed — never be evaluated under the wrong policy.
func TestCredentialUnderWrongPolicyDenied(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('k' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_wp", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), PepperVersion: pep.Version,
		Status: credential.StatusNormal, PolicyID: "some-OTHER-policy", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := GenerateSigner()
	term, err := New(Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Policy: policy.Default(), Signer: signer, Audience: "fi-inference",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := term.Admit(bearerHeaders(raw), lane.Features{})
	if out.Authorized {
		t.Fatal("credential bound to another policy must be denied")
	}
	if out.Reason != "policy_unavailable" {
		t.Fatalf("reason = %s, want policy_unavailable", out.Reason)
	}
	// P0.12: a denied outcome must not carry a populated context.
	if out.Context.Principal.CredentialID != "" || out.Context.LaneID != "" {
		t.Fatalf("denied outcome must not expose an AuthorizedContext: %+v", out.Context)
	}
}

// Regression (P0.6): ENFORCE mode must refuse construction without its
// security-critical dependencies instead of silently degrading enforcement.
func TestEnforceModeRequiresLanesAndConcurrency(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	tc := makeCredentialWithStatus("cred_m", "acct_1", credential.StatusNormal, pep)
	signer, _ := GenerateSigner()
	base := Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Policy: policy.Default(), Signer: signer, Audience: "fi-inference",
	}

	noLanes := base
	noLanes.Mode = ModeEnforce
	if _, err := New(noLanes); err == nil {
		t.Fatal("ENFORCE without a lane store must fail construction")
	}
	// With lanes but no concurrency controller → still refused.
	withLanes := base
	withLanes.Mode = ModeEnforce
	withLanes.Lanes = lane.NewStore(nil, time.Now)
	if _, err := New(withLanes); err == nil {
		t.Fatal("ENFORCE without a concurrency controller must fail construction")
	}
	// Complete ENFORCE wiring succeeds: lanes + concurrency controller AND an
	// evidence/adaptive-state backend (P0.2 — ENFORCE-without-adaptive-state is
	// not a supported posture).
	full := withLanes
	full.Concurrency = &fakePool{resource.NewConcurrencyPool(4)}
	full.Evidence = evidence.NewMemoryStore()
	if _, err := New(full); err != nil {
		t.Fatalf("complete ENFORCE wiring must construct: %v", err)
	}
	// Unknown modes are rejected.
	unknown := base
	unknown.Mode = Mode("OBSERVE")
	if _, err := New(unknown); err == nil {
		t.Fatal("unknown mode must fail construction")
	}
	// Empty mode defaults to TERMINATE and constructs.
	termMode := base
	termMode.Mode = ""
	if _, err := New(termMode); err != nil {
		t.Fatalf("empty mode must default to TERMINATE: %v", err)
	}
}

// Regression (P0.12): a denied Outcome (concurrency) must not expose a
// populated Principal/Context — an AuthorizedContext exists only for an
// authorized request.
func TestDeniedOutcomeExposesNoContext(t *testing.T) {
	pool := resource.NewConcurrencyPool(1)
	term, raw := buildTerminator(t, credential.StatusNormal, pool)
	held := pool.Acquire()
	defer held.Release()
	out := term.Admit(bearerHeaders(raw), lane.Features{})
	if out.Authorized {
		t.Fatal("must deny over concurrency")
	}
	if out.Context.Principal.CredentialID != "" || out.Context.LaneID != "" || out.Principal.CredentialID != "" {
		t.Fatalf("denied outcome carries identity: principal=%+v ctx=%+v", out.Principal, out.Context)
	}
	if out.Lease != nil || out.Assertion != nil {
		t.Fatal("denied outcome must not carry a lease or assertion")
	}
}

// --- P0.11 hardening regressions: signer + request ids -----------------------

// Regression (hardening): NewSigner validates key material — a truncated or
// mis-typed key fails at construction, not at signing time.
func TestNewSignerValidatesKeySize(t *testing.T) {
	if _, err := NewSigner(ed25519.PrivateKey(make([]byte, 10))); err == nil {
		t.Fatal("short private key must be rejected")
	}
	if _, err := NewSigner(nil); err == nil {
		t.Fatal("nil private key must be rejected")
	}
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner(signer.priv); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

// Regression (hardening): request ids are 128-bit CSPRNG values — globally
// unique across nodes/restarts, not process-local counters (an
// attacker-guessable jti is replay ammunition).
func TestRequestIDEntropy(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := newRequestID()
		if len(id) != len("req_")+22 { // 128 bits base64url raw = 22 chars
			t.Fatalf("id %q has unexpected length %d", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate request id %q", id)
		}
		seen[id] = true
	}
}
