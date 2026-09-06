package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// staticRevs is a RevisionSource over a fixed table (P0.19 test double).
type staticRevs map[string]int

func (s staticRevs) CredentialRevision(credID string) (int, bool) {
	v, ok := s[credID]
	return v, ok
}

// trustAll / trustNone are TransportIdentity test doubles (P0.53).
type trustAll struct{}

func (trustAll) Trusted(*http.Request) bool { return true }

type trustNone struct{}

func (trustNone) Trusted(*http.Request) bool { return false }

// P0.19: a cryptographically valid assertion whose cred_rev is behind the
// authoritative current revision is rejected when revision checks are on;
// the same assertion passes when they are off (stateless TTL-only class).
func TestBackendRevisionFreshness(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	claims := terminator.Claims{
		Subject: "acct_r", CredID: "cred_r", Audience: "aud_r", JTI: "req_r",
		PolicyRev: 2, CredRev: 3, Scope: []string{"inference"},
	}
	a, err := signer.Issue(claims, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	mkReq := func() *http.Request {
		r := httptest.NewRequest("POST", "http://backend.local/v1/messages", nil)
		r.Header.Set(assertionHeader, a.Encode())
		return r
	}

	// Stateless TTL-only verifier: accepts.
	stateless := NewBackendVerifier(signer.Public(), "aud_r")
	if _, err := stateless.Verify(mkReq()); err != nil {
		t.Fatalf("stateless verifier must accept: %v", err)
	}

	// Sensitive verifier, current rev = 3: accepts.
	current := NewBackendVerifier(signer.Public(), "aud_r").WithRevisionChecks(staticRevs{"cred_r": 3}, 1)
	if _, err := current.Verify(mkReq()); err != nil {
		t.Fatalf("current-rev assertion must pass: %v", err)
	}

	// Credential bumped to rev 4 after issuance → assertion stale → denied.
	bumped := NewBackendVerifier(signer.Public(), "aud_r").WithRevisionChecks(staticRevs{"cred_r": 4}, 1)
	if _, err := bumped.Verify(mkReq()); err == nil {
		t.Fatal("P0.19: stale cred_rev must be rejected by a revision-checking backend")
	}

	// Unknown credential at the revision source → fail closed (unknown is stale).
	unknown := NewBackendVerifier(signer.Public(), "aud_r").WithRevisionChecks(staticRevs{}, 1)
	if _, err := unknown.Verify(mkReq()); err == nil {
		t.Fatal("P0.19: unknown credential revision must fail closed")
	}

	// Policy floor above the assertion's policy_rev → denied.
	floor := NewBackendVerifier(signer.Public(), "aud_r").WithRevisionChecks(staticRevs{"cred_r": 3}, 3)
	if _, err := floor.Verify(mkReq()); err == nil {
		t.Fatal("P0.19: policy_rev below the minimum must be rejected")
	}
}

// P0.52: StripAssertion removes the bearer after verification so it never
// propagates to further services or logs.
func TestBackendStripAssertionAfterVerify(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	a, err := signer.Issue(terminator.Claims{
		Subject: "acct_s", CredID: "cred_s", Audience: "aud_s", JTI: "req_s",
		PolicyRev: 1, CredRev: 1, Scope: []string{"inference"},
	}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://backend.local/v1/messages", nil)
	r.Header.Set(assertionHeader, a.Encode())
	r.Header.Set("Authorization", "Bearer should-have-been-stripped-upstream")

	ver := NewBackendVerifier(signer.Public(), "aud_s")
	if _, err := ver.Verify(r); err != nil {
		t.Fatal(err)
	}
	ver.StripAssertion(r)
	if len(r.Header.Values(assertionHeader)) != 0 {
		t.Fatal("P0.52: the assertion must not survive past verification")
	}
}

// P0.53: with transport identity required, an untrusted connection is denied
// BEFORE the assertion is examined — even a valid one.
func TestBackendTransportIdentityGate(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	a, err := signer.Issue(terminator.Claims{
		Subject: "acct_t", CredID: "cred_t", Audience: "aud_t", JTI: "req_t",
		PolicyRev: 1, CredRev: 1, Scope: []string{"inference"},
	}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ver := NewBackendVerifier(signer.Public(), "aud_t").RequireTransportIdentity(trustNone{})
	r := httptest.NewRequest("POST", "http://backend.local/v1/messages", nil)
	r.Header.Set(assertionHeader, a.Encode())
	if _, err := ver.Verify(r); err == nil {
		t.Fatal("P0.53: valid assertion over untrusted transport must be denied")
	}

	verOK := NewBackendVerifier(signer.Public(), "aud_t").RequireTransportIdentity(trustAll{})
	r2 := httptest.NewRequest("POST", "http://backend.local/v1/messages", nil)
	r2.Header.Set(assertionHeader, a.Encode())
	if _, err := verOK.Verify(r2); err != nil {
		t.Fatalf("trusted transport + valid assertion must pass: %v", err)
	}
	_ = credential.ErrNotFound
}
