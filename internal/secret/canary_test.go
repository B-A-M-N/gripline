package secret_test

// P0.15/P0.16 central canary suite: every cryptographic-secret-bearing type
// must redact under generic formatting AND under formatting of a VALUE COPY.
// The failure class this guards: a type adds redaction with pointer-receiver
// Formatters only — the original redacts, but copy := *original falls back to
// struct formatting and exposes raw key material. Each type below registers
// itself by being listed in the table; adding a new secret-bearing type without
// updating this suite leaves it unguarded.

import (
	"fmt"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/pseudonym"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

func checkRedacted(t *testing.T, name string, v any) {
	t.Helper()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, v); out != "<redacted>" {
			t.Errorf("%s: format %q = %q, want \"<redacted>\"", name, verb, out)
		}
	}
}

// copyOf returns a value copy of v (copy := *ptr) for pointer-bearing types so
// the copy's formatting is exercised. Types whose zero-value copies are
// meaningless are handled by dedicated tests below.
func TestSecretBearingTypesRedactOnValueCopy(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("pepperbytes-canary")}
	ring, err := credential.NewPepperRing(pep)
	if err != nil {
		t.Fatal(err)
	}
	checkRedacted(t, "PepperKey", *pep)
	checkRedacted(t, "PepperRing", *ring)

	pring, err := pseudonym.NewRing(&pseudonym.Key{Version: 1, Secret: []byte("pseudokey-canary")})
	if err != nil {
		t.Fatal(err)
	}
	checkRedacted(t, "pseudonym.Key", pseudonym.Key{Version: 1, Secret: []byte("pseudokey-canary")})
	checkRedacted(t, "pseudonym.Ring", *pring)

	ss := secret.NewFromBytes([]byte("topsecret-canary"))
	checkRedacted(t, "SealedSecret", ss)

	signer, err := terminator.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	signerCopy := *signer
	checkRedacted(t, "Signer(value copy)", signerCopy)

	a, err := signer.Issue(terminator.Claims{
		Issuer: "gripline", Subject: "s", CredID: "cred_1", Audience: "aud", JTI: "j",
		PolicyRev: 1, CredRev: 1, Scope: []string{"inference"},
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Second).Unix(),
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	aCopy := *a
	checkRedacted(t, "Assertion(value copy)", aCopy)

	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	krCopy := *kr
	checkRedacted(t, "Keyring(value copy)", krCopy)
}

// Pointer-bearing types must redact through the pointer too (fmt follows the
// pointer to the value's methods).
func TestSecretBearingTypesRedactThroughPointer(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("pepperbytes-canary")}
	ring, _ := credential.NewPepperRing(pep)
	pring, err := pseudonym.NewRing(&pseudonym.Key{Version: 1, Secret: []byte("pseudokey-canary")})
	if err != nil {
		t.Fatal(err)
	}
	ss := secret.NewFromBytes([]byte("topsecret-canary"))
	signer, _ := terminator.GenerateSigner()
	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		v    any
	}{{"PepperKey", pep}, {"PepperRing", ring}, {"pseudonym.Ring", pring},
		{"SealedSecret", ss}, {"Signer", signer}, {"Keyring", kr}} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if out := fmt.Sprintf(verb, tc.v); out != "<redacted>" {
				t.Errorf("%s: %q = %q, want \"<redacted>\"", tc.name, verb, out)
			}
		}
	}
}
