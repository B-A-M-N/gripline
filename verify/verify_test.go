package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequireMTLSChecksVerifiedServiceIdentity(t *testing.T) {
	trust := RequireMTLS(MTLSOptions{AllowedDNSNames: []string{"gateway.internal"}})
	request := httptest.NewRequest("POST", "https://backend/v1/messages", nil)
	request.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{{DNSNames: []string{"gateway.internal"}}},
		VerifiedChains:    [][]*x509.Certificate{{{}}},
	}
	if !trust.Trusted(request) {
		t.Fatal("allow-listed verified SPIFFE identity must be trusted")
	}
	request.TLS.PeerCertificates[0].DNSNames = []string{"wrong.internal"}
	if trust.Trusted(request) {
		t.Fatal("unallow-listed certificate identity must be rejected")
	}
	request.TLS.VerifiedChains = nil
	if trust.Trusted(request) {
		t.Fatal("unverified client certificate must be rejected")
	}
}

func TestRequireMTLSSeparatesInferenceAndControlIdentities(t *testing.T) {
	inferenceTrust := RequireMTLS(MTLSOptions{AllowedDNSNames: []string{"inference.internal"}})
	controlTrust := RequireMTLS(MTLSOptions{AllowedDNSNames: []string{"verifier-control.internal"}})
	request := httptest.NewRequest("POST", "https://backend/v1/messages", nil)
	request.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{{DNSNames: []string{"inference.internal"}}},
		VerifiedChains:    [][]*x509.Certificate{{{}}},
	}
	if !inferenceTrust.Trusted(request) {
		t.Fatal("inference identity must be trusted by the inference policy")
	}
	if controlTrust.Trusted(request) {
		t.Fatal("inference identity must not be trusted by the verifier-control policy")
	}
	request.TLS.PeerCertificates[0].DNSNames = []string{"verifier-control.internal"}
	if inferenceTrust.Trusted(request) {
		t.Fatal("verifier-control identity must not be trusted by the inference policy")
	}
	if !controlTrust.Trusted(request) {
		t.Fatal("verifier-control identity must be trusted by the control policy")
	}
}

func TestMemoryReplayGuardClaimsAndExpiresJTIs(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_700_000_000, 0)
	set, err := NewKeySet(map[int]ed25519.PublicKey{1: pub}, 1)
	if err != nil {
		t.Fatal(err)
	}
	guard := NewMemoryReplayGuard(2)
	guard.now = func() time.Time { return now }
	v, err := New(set, "provider")
	if err != nil {
		t.Fatal(err)
	}
	v.WithClock(func() time.Time { return now }).WithReplayGuard(guard)
	token := testToken(t, priv, testClaims(now))
	req := httptest.NewRequest("POST", "http://backend/v1/messages", nil)
	req.Header.Set(AssertionHeader, token)
	if _, err := v.Verify(req); err != nil {
		t.Fatalf("first assertion use rejected: %v", err)
	}
	if _, err := v.Verify(req); err != ErrReplayDetected {
		t.Fatalf("second assertion use error=%v, want ErrReplayDetected", err)
	}

	if accepted, err := guard.Accept(context.Background(), ReplayClaim{Issuer: "gripline", Audience: "provider", JTI: "expired-jti", ExpiresAt: now.Add(time.Second)}); err != nil || !accepted {
		t.Fatalf("seed replay entry rejected: accepted=%v err=%v", accepted, err)
	}
	guard.now = func() time.Time { return now.Add(21 * time.Second) }
	if accepted, err := guard.Accept(context.Background(), ReplayClaim{Issuer: "gripline", Audience: "provider", JTI: "new-jti", ExpiresAt: now.Add(22 * time.Second)}); err != nil || !accepted {
		t.Fatalf("expired entries should be evicted before capacity check: accepted=%v err=%v", accepted, err)
	}
}

func TestMemoryReplayGuardSeparatesIssuerAndAudience(t *testing.T) {
	guard := NewMemoryReplayGuard(2)
	expires := time.Now().Add(time.Minute)
	for _, claim := range []ReplayClaim{
		{Issuer: "issuer-a", Audience: "audience-a", JTI: "same", ExpiresAt: expires},
		{Issuer: "issuer-a", Audience: "audience-b", JTI: "same", ExpiresAt: expires},
	} {
		accepted, err := guard.Accept(context.Background(), claim)
		if err != nil || !accepted {
			t.Fatalf("namespaced claim rejected: accepted=%v err=%v", accepted, err)
		}
	}
}

func TestMemoryReplayGuardParallelClaims(t *testing.T) {
	guard := NewMemoryReplayGuard(100)
	claim := ReplayClaim{Issuer: "gripline", Audience: "provider", JTI: "parallel", ExpiresAt: time.Now().Add(time.Minute)}
	var wg sync.WaitGroup
	var accepted atomic.Int32
	var rejected atomic.Int32
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := guard.Accept(context.Background(), claim)
			if err != nil {
				t.Errorf("parallel claim error: %v", err)
				return
			}
			if ok {
				accepted.Add(1)
			} else {
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || rejected.Load() != 63 {
		t.Fatalf("parallel claims accepted=%d rejected=%d, want 1/63", accepted.Load(), rejected.Load())
	}
}

func TestMemoryReplayGuardCapacityAndExpiry(t *testing.T) {
	now := time.Unix(1_700_100_000, 0)
	guard := NewMemoryReplayGuard(1)
	guard.now = func() time.Time { return now }
	claim := func(jti string, expires time.Time) ReplayClaim {
		return ReplayClaim{Issuer: "gripline", Audience: "provider", JTI: jti, ExpiresAt: expires}
	}
	if ok, err := guard.Accept(context.Background(), claim("one", now.Add(time.Second))); err != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, err)
	}
	if ok, err := guard.Accept(context.Background(), claim("two", now.Add(time.Second))); err != ErrReplayGuardCapacity || ok {
		t.Fatalf("capacity result: ok=%v err=%v", ok, err)
	}
	guard.now = func() time.Time { return now.Add(2 * time.Second) }
	if ok, err := guard.Accept(context.Background(), claim("two", now.Add(3*time.Second))); err != nil || !ok {
		t.Fatalf("expired claim did not restore capacity: ok=%v err=%v", ok, err)
	}
}

func BenchmarkMemoryReplayGuard1K(b *testing.B)   { benchmarkMemoryReplayGuard(b, 1_000) }
func BenchmarkMemoryReplayGuard10K(b *testing.B)  { benchmarkMemoryReplayGuard(b, 10_000) }
func BenchmarkMemoryReplayGuard100K(b *testing.B) { benchmarkMemoryReplayGuard(b, 100_000) }

func benchmarkMemoryReplayGuard(b *testing.B, capacity int) {
	guard := NewMemoryReplayGuard(capacity)
	claims := make([]ReplayClaim, capacity)
	for i := range claims {
		claims[i] = ReplayClaim{Issuer: "gripline", Audience: "provider", JTI: fmt.Sprintf("seed-%d", i), ExpiresAt: time.Now().Add(time.Hour)}
		if _, err := guard.Accept(context.Background(), claims[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	var sequence atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			claim := claims[0]
			claim.JTI = fmt.Sprintf("bench-%d", sequence.Add(1))
			_, _ = guard.Accept(context.Background(), claim)
		}
	})
}

func testToken(t testing.TB, priv ed25519.PrivateKey, c Claims) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return AssertionWireVersion + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

func testClaims(now time.Time) Claims {
	return Claims{Issuer: "gripline", Subject: "acct", CredID: "cred", Audience: "provider", IssuedAt: now.Unix() - 1, ExpiresAt: now.Unix() + 20, JTI: "req", PolicyRev: 3, CredRev: 4, Scope: []string{"inference"}, KeyID: 1}
}

func TestConformanceVectors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_700_000_000, 0)
	set, err := NewKeySet(map[int]ed25519.PublicKey{1: pub}, 1)
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(set, "provider")
	if err != nil {
		t.Fatal(err)
	}
	v.WithClock(func() time.Time { return now })
	valid := testToken(t, priv, testClaims(now))
	tampered := valid
	sigStart := strings.LastIndex(tampered, ".") + 1
	replacement := byte('A')
	if tampered[sigStart] == replacement {
		replacement = 'B'
	}
	tampered = tampered[:sigStart] + string(replacement) + tampered[sigStart+1:]
	cases := []struct {
		name  string
		token string
		err   error
	}{
		{"valid", valid, nil},
		{"unversioned", strings.TrimPrefix(valid, AssertionWireVersion+"."), ErrBadAssertion},
		{"expired", testToken(t, priv, Claims{Issuer: "gripline", Subject: "acct", CredID: "cred", Audience: "provider", IssuedAt: now.Add(-20 * time.Second).Unix(), ExpiresAt: now.Add(-time.Second).Unix(), JTI: "expired", PolicyRev: 1, CredRev: 1, Scope: []string{"inference"}, KeyID: 1}), ErrExpired},
		{"wrong-audience", testToken(t, priv, func() Claims { c := testClaims(now); c.Audience = "other"; return c }()), ErrWrongAudience},
		{"wrong-kid", testToken(t, priv, func() Claims { c := testClaims(now); c.KeyID = 2; return c }()), ErrUnknownKey},
		{"tampered", tampered, ErrBadSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://backend/v1/messages", nil)
			r.Header.Set(AssertionHeader, tc.token)
			_, got := v.Verify(r)
			if tc.err == nil {
				if got != nil {
					t.Fatalf("valid vector: %v", got)
				}
				return
			}
			if got != tc.err {
				t.Fatalf("got %v, want %v", got, tc.err)
			}
		})
	}
}

func TestVerifyAndStripAndDuplicateClaims(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_700_000_000, 0)
	set, _ := NewKeySet(map[int]ed25519.PublicKey{1: pub}, 1)
	v, _ := New(set, "provider")
	v.WithClock(func() time.Time { return now })
	r := httptest.NewRequest("POST", "http://backend", nil)
	r.Header.Add(AssertionHeader, testToken(t, priv, testClaims(now)))
	r.Header.Add(AssertionHeader, "duplicate")
	if _, err := v.Verify(r); err != ErrDuplicateAssertion {
		t.Fatalf("duplicate header: %v", err)
	}
	r.Header.Del(AssertionHeader)
	payload := `{"iss":"gripline","iss":"gripline","sub":"acct","cid":"cred","aud":"provider","iat":1699999999,"exp":1700000020,"jti":"dup","policy_rev":1,"cred_rev":1,"scope":["inference"],"kid":1}`
	token := AssertionWireVersion + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload)))
	r.Header.Set(AssertionHeader, token)
	if _, err := v.Verify(r); err != ErrBadAssertion {
		t.Fatalf("duplicate claims: %v", err)
	}

	r.Header.Set(AssertionHeader, testToken(t, priv, testClaims(now)))
	if _, err := v.VerifyAndStrip(r); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get(AssertionHeader) != "" {
		t.Fatal("assertion not stripped")
	}
}

func TestLoadKeySetRejectsDuplicatesAndBadFingerprint(t *testing.T) {
	pub := make([]byte, ed25519.PublicKeySize)
	b64 := base64.StdEncoding.EncodeToString(pub)
	for name, doc := range map[string]string{
		"duplicate":   `{"active_kid":1,"keys":[{"kid":1,"algorithm":"Ed25519","public":"` + b64 + `"},{"kid":1,"algorithm":"Ed25519","public":"` + b64 + `"}]}`,
		"fingerprint": `{"active_kid":1,"keys":[{"kid":1,"algorithm":"Ed25519","public":"` + b64 + `","fingerprint":"bad"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadKeySet(strings.NewReader(doc)); err == nil {
				t.Fatal("invalid key set accepted")
			}
		})
	}
}

type epochSource uint64

func (e epochSource) PolicyEpoch() (uint64, bool) { return uint64(e), true }

type contextEpochSource struct {
	epoch uint64
	seen  context.Context
}

func (s *contextEpochSource) PolicyEpoch() (uint64, bool) { return s.epoch, true }

func (s *contextEpochSource) PolicyEpochContext(ctx context.Context) (uint64, error) {
	s.seen = ctx
	return s.epoch, nil
}

type contextOnlyRevisionSource struct {
	revision int
	seen     context.Context
}

func (s *contextOnlyRevisionSource) CredentialRevisionContext(ctx context.Context, _ string) (int, error) {
	s.seen = ctx
	return s.revision, nil
}

type contextOnlyPolicyEpochSource struct {
	epoch uint64
	seen  context.Context
}

func (s *contextOnlyPolicyEpochSource) PolicyEpochContext(ctx context.Context) (uint64, error) {
	s.seen = ctx
	return s.epoch, nil
}

func TestContextFreshnessChecksAcceptContextOnlyAuthorities(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set, _ := NewKeySet(map[int]ed25519.PublicKey{1: pub}, 1)
	now := time.Unix(1_700_000_000, 0)
	revisions := &contextOnlyRevisionSource{revision: 4}
	epochs := &contextOnlyPolicyEpochSource{epoch: 7}
	v, _ := New(set, "provider")
	v.WithClock(func() time.Time { return now }).
		WithContextRevisionChecks(revisions, 3).
		WithContextPolicyEpochChecks(epochs, 1)
	c := testClaims(now)
	c.PolicyEpoch = 7
	r := httptest.NewRequest("POST", "http://backend/v1/messages", nil)
	r.Header.Set(AssertionHeader, testToken(t, priv, c))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := v.VerifyContext(ctx, r); err != nil {
		t.Fatalf("context-only freshness authorities: %v", err)
	}
	if revisions.seen != ctx || epochs.seen != ctx {
		t.Fatal("context-only freshness authorities did not receive request context")
	}
}

func TestPolicyEpochChecksRejectRollbackStaleAssertions(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set, _ := NewKeySet(map[int]ed25519.PublicKey{1: pub}, 1)
	v, _ := New(set, "provider")
	now := time.Unix(1_700_000_000, 0)
	v.WithClock(func() time.Time { return now }).WithPolicyEpochChecks(epochSource(3), 1)
	c := testClaims(now)
	c.PolicyRev = 1 // rollback can lower artifact revision
	c.PolicyEpoch = 3
	r := httptest.NewRequest("POST", "http://backend", nil)
	r.Header.Set(AssertionHeader, testToken(t, priv, c))
	if _, err := v.Verify(r); err != nil {
		t.Fatalf("current epoch should accept assertion: %v", err)
	}
	c.PolicyEpoch = 2
	r.Header.Set(AssertionHeader, testToken(t, priv, c))
	if _, err := v.Verify(r); err != ErrStalePolicyEpoch {
		t.Fatalf("stale epoch: %v", err)
	}
}

func TestVerifyContextPropagatesToPolicyEpochSource(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set, _ := NewKeySet(map[int]ed25519.PublicKey{1: pub}, 1)
	source := &contextEpochSource{epoch: 1}
	v, _ := New(set, "provider")
	v.WithPolicyEpochChecks(source, 1)
	now := time.Unix(1_700_000_000, 0)
	v.WithClock(func() time.Time { return now })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "http://backend", nil).WithContext(ctx)
	c := testClaims(now)
	c.PolicyEpoch = 1
	r.Header.Set(AssertionHeader, testToken(t, priv, c))
	if _, err := v.VerifyContext(ctx, r); err != nil {
		t.Fatalf("context verification: %v", err)
	}
	if source.seen != ctx {
		t.Fatal("policy epoch source did not receive request context")
	}
}
