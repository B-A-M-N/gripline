package terminator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

type sourceAliasBindRecorder struct {
	calls atomic.Int64
}

func (r *sourceAliasBindRecorder) BindAuthenticatedSource(context.Context, []SourceAliasCandidate, SourceAliasCandidate) (string, error) {
	r.calls.Add(1)
	return "canonical-authenticated-source", nil
}

// B1 regression: source alias persistence is an authenticated binding step,
// not part of unauthenticated source resolution. A large invalid-credential
// spray must therefore leave the binder untouched.
func TestInvalidCredentialsNeverBindSourceAliases(t *testing.T) {
	term, raw := buildTerminator(t, credential.StatusNormal, nil)
	binder := new(sourceAliasBindRecorder)
	src := TrustedSource{
		Pseudonym:   "provisional-source",
		Aliases:     []SourceAliasCandidate{{Alias: "v1.provisional-source", Generation: 1}},
		ActiveAlias: SourceAliasCandidate{Alias: "v1.provisional-source", Generation: 1},
		AliasBinder: binder,
	}
	for i := 0; i < 10000; i++ {
		out := term.AdmitUsageContext(context.Background(), "invalid-source-alias-"+string(rune(i)), bearerHeaders("sk-invalid"), lane.Features{}, src, resource.UsageEstimate{Requests: 1})
		if out.Authorized || out.CredentialAuthenticated {
			t.Fatalf("invalid request %d outcome=%+v, want unauthenticated denial", i, out)
		}
	}
	if got := binder.calls.Load(); got != 0 {
		t.Fatalf("invalid credential spray invoked source alias binder %d times", got)
	}

	out := term.AdmitUsageContext(context.Background(), "valid-source-alias", bearerHeaders(raw), lane.Features{}, src, resource.UsageEstimate{Requests: 1})
	if !out.Authorized || !out.CredentialAuthenticated {
		t.Fatalf("valid request outcome=%+v, want authenticated authorization", out)
	}
	if got := binder.calls.Load(); got != 1 {
		t.Fatalf("authenticated request invoked source alias binder %d times, want 1", got)
	}
	if out.Trace == nil || out.Trace.SourcePseudonym != "canonical-authenticated-source" {
		t.Fatalf("authenticated source was not rebound canonically: trace=%+v", out.Trace)
	}
}

// sourceTestTerm builds a terminator with a spray detector and a governor so
// source-scoped behavior is fully wired.
func sourceTestTerm(t *testing.T) (*Terminator, evidence.Store, string) {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('a' + i%26)
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg := credential.NewMemoryRegistry()
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_src", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()
	store := evidence.NewMemoryStore()
	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Evidence: store,
		Spray:    anomaly.NewDetector(nil, anomaly.DefaultThresholds()),
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}
	return term, store, raw
}

// P0.4 regression, part 1: with NO trusted source identity on the request,
// source-spray detection must stay INERT. The old process-global Dependencies.
// SourceID either attributed every client to one shared bucket or (empty)
// silently disabled source security; with per-request identity, an unknown
// source must not be lumped into any bucket at all.
func TestAdmitWithoutSourceDoesNotFeedSprayDetector(t *testing.T) {
	term, store, raw := sourceTestTerm(t)

	// Five different credentials-worth of ASNs through ONE credential — if a
	// source bucket existed, the detector would track it.
	for _, asn := range []string{"AS1", "AS2", "AS3", "AS4", "AS5"} {
		out := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: asn})
		if !out.Authorized {
			t.Fatalf("admit: %s", out.Reason)
		}
	}
	// No SOURCE-scoped evidence may exist: no source identity → no attribution.
	snap, _ := store.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeSource, ID: ""}}, time.Now())
	for _, e := range snap {
		if e.Scope == evidence.ScopeSource {
			t.Fatalf("no-source request must not mint source-scoped evidence: %s", e.Code)
		}
	}
}

// P0.4 regression, part 2: source identity is PER REQUEST — two different
// clients through the same Terminator are separate sources, not one bucket.
func TestAdmitSourcePerRequestSeparation(t *testing.T) {
	term, store, raw := sourceTestTerm(t)

	// One credential presented from 6 distinct sources with distinct ASNs:
	// each source sees ONE credential, so no source-spray fires per source.
	// (The old global SourceID would have merged them into one bucket showing
	// 1 source with many credentials — or attributed all ASNs to one source.)
	for i := 0; i < 6; i++ {
		src := TrustedSource{Pseudonym: string(rune('A' + i))}
		asn := string([]byte{'A', 'S', byte('1' + i)})
		out := term.AdmitSource(bearerHeaders(raw), lane.Features{NetworkASN: asn}, src)
		if !out.Authorized {
			t.Fatalf("admit %d: %s", i, out.Reason)
		}
	}
	// No single source crossed the spray threshold (each presented 1 credential).
	for _, s := range []string{"A", "B", "C", "D", "E", "F"} {
		snap, _ := store.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeSource, ID: s}}, time.Now())
		for _, e := range snap {
			if e.Code == "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS" {
				t.Fatalf("separate sources must not merge into a spray bucket: source %s", s)
			}
		}
	}
}

// P0.4 regression, part 3: the SOURCE resource scope keys on the REQUEST's
// pseudonym (verified indirectly: two different sources under a credential
// each get their own SOURCE hold, and the no-source path skips SOURCE).
func TestAdmitSourceResourceScopePerRequest(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	pep := &credential.PepperKey{Version: 1, Key: []byte("test-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('z' + -1*(i%26))
	}
	raw := "sk-test-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_srcres", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	signer, _ := GenerateSigner()
	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Evidence: evidence.NewMemoryStore(),
		Resource: resource.NewGovernor(nil),
	}
	term, err := New(dep)
	if err != nil {
		t.Fatal(err)
	}

	// With a source: the hold must include SOURCE (5 scopes: P0.34 adds GLOBAL).
	out := term.AdmitSource(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"}, TrustedSource{Pseudonym: "srcR1"})
	if !out.Authorized {
		t.Fatalf("admit: %s", out.Reason)
	}
	if n := len(out.ResourceRes.Leases()); n != 5 {
		t.Fatalf("with source: want 5 scope leases (SOURCE+ACCT+CRED+LANE+GLOBAL), got %d", n)
	}
	out.ResourceRes.Release()

	// Without a source: SOURCE is skipped (4 scopes), not bucketed under "".
	out2 := term.Admit(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"})
	if !out2.Authorized {
		t.Fatalf("admit no-source: %s", out2.Reason)
	}
	if n := len(out2.ResourceRes.Leases()); n != 4 {
		t.Fatalf("no source: want 4 scope leases (SOURCE skipped; ACCT+CRED+LANE+GLOBAL), got %d", n)
	}
	out2.ResourceRes.Release()
}
