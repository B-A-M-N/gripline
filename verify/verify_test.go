package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testToken(t *testing.T, priv ed25519.PrivateKey, c Claims) string {
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
