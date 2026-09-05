package terminator

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/freeinference/gripline/internal/credential"
	"github.com/freeinference/gripline/internal/lane"
	"github.com/freeinference/gripline/internal/policy"
	"github.com/freeinference/gripline/internal/resource"
	"github.com/freeinference/gripline/internal/secret"
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
		IssuedAt: now.Add(-2 * time.Hour).Unix(), ExpiresAt: now.Unix(),
	}
	payload, _ := json.Marshal(claims)
	sig := ed25519.Sign(signer.priv, payload)
	enc := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := ParseAndVerify(enc, signer.Public(), "aud", now); err != ErrTTLTooLong {
		t.Fatalf("want ErrTTLTooLong, got %v", err)
	}
}

// --- admission flow ---------------------------------------------------------

type fakePool struct{ p *resource.ConcurrencyPool }

func (f *fakePool) Acquire(scope string) *resource.LeaseHandle { return f.p.Acquire() }

// buildTerminator wires a terminator around a single credential and returns the
// raw token string the test uses to act as the client.
func buildTerminator(t *testing.T, status credential.Status, concurrency *resource.ConcurrencyPool) (*Terminator, string) {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	tc := makeCredentialWithStatus("cred_a", "acct_1", status, pep)

	signer, _ := GenerateSigner()
	dep := Dependencies{
		Registry: tc.reg,
		Peppers:  credential.NewPepperRing(pep),
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
	reg.Insert(&credential.CredentialRecord{
		CredentialID: id, AccountID: account,
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: pep.Version,
		Status: status, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
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
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_e", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), PepperVersion: 1,
		Status:    credential.StatusNormal,
		ExpiresAt: time.Now().Add(-time.Minute), // already expired
		Revision:  1,
	})
	signer, _ := GenerateSigner()
	term, err := New(Dependencies{
		Registry: reg, Peppers: credential.NewPepperRing(pep),
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
		Registry: tc.reg, Peppers: credential.NewPepperRing(pep),
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
		Registry: tc.reg, Peppers: credential.NewPepperRing(pep),
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
