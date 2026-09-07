package terminator

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// --- P0.17: issuer/verifier isolation ------------------------------------------

// TestVerifierKeyringIsolation proves the verifier keyring is verification
// material only, connected to the signer purely by key publication.
func TestVerifierKeyringIsolation(t *testing.T) {
	k, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	tok := issue(t, k, "acct_iso")

	vk := k.PublishVerifier()

	now := time.Now()
	if _, err := vk.Verify(tok.Encode(), "aud", now); err != nil {
		t.Fatalf("published verifier must accept the signer's token: %v", err)
	}

	// An INDEPENDENT verifier keyring (no publication) fails closed.
	independent := NewVerifierKeyring()
	if _, err := independent.Verify(tok.Encode(), "aud", now); err == nil {
		t.Fatal("an un-published verifier keyring must fail closed (no guessed keys)")
	}

	// Rotation publishes forward; retirement removes the generation.
	newKid, err := k.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := k.Public(newKid)
	if !ok {
		t.Fatal("rotated generation must expose its public key")
	}
	fresh := issue(t, k, "acct_iso2") // signed under the new kid
	vk.Publish(newKid, ed25519.PublicKey(pub))
	if _, err := vk.Verify(fresh.Encode(), "aud", now); err != nil {
		t.Fatalf("published rotation must verify: %v", err)
	}

	vk.Retire(1)
	if _, err := vk.Verify(tok.Encode(), "aud", now); err == nil {
		t.Fatal("retired generation must fail closed")
	}
}

// --- P0.18: strict claim validation ---------------------------------------------

func TestStrictClaimValidation(t *testing.T) {
	signer, _ := GenerateSigner()
	now := time.Now()

	// Missing scope → rejected at Issue AND at verify (hand-signed).
	bad := Claims{Subject: "s", CredID: "c", Audience: "aud", JTI: "j", PolicyRev: 1, CredRev: 1}
	if _, err := signer.Issue(bad, 30*time.Second); err == nil {
		t.Fatal("Issue must require scope (P0.18)")
	}
	if _, err := signRaw(t, signer, bad, now); err == nil {
		t.Fatal("ParseAndVerify must require scope (P0.18)")
	}

	// Zero policy_rev / cred_rev → rejected.
	bad2 := Claims{Subject: "s", CredID: "c", Audience: "aud", JTI: "j", Scope: []string{"inference"}}
	if _, err := signer.Issue(bad2, 30*time.Second); err == nil {
		t.Fatal("Issue must require PolicyRev>0/CredRev>0 (P0.18)")
	}

	// Disallowed scope value → rejected.
	bad3 := Claims{Subject: "s", CredID: "c", Audience: "aud", JTI: "j", PolicyRev: 1, CredRev: 1, Scope: []string{"superuser"}}
	if _, err := signer.Issue(bad3, 30*time.Second); err == nil {
		t.Fatal("scope values must be allowlisted (P0.18)")
	}

	// Lane scope without LaneID → rejected.
	bad4 := Claims{Subject: "s", CredID: "c", Audience: "aud", JTI: "j", PolicyRev: 1, CredRev: 1, Scope: []string{"LANE"}}
	if _, err := signer.Issue(bad4, 30*time.Second); err == nil {
		t.Fatal("LANE scope requires LaneID (P0.18)")
	}

	// A verifier without an audience binding fails closed, not open.
	a, err := signer.Issue(testClaims("s", "aud"), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndVerify(a.Encode(), signer.Public(), "", now); err == nil {
		t.Fatal("empty expected audience must fail closed (INV-11)")
	}
}

// signRaw hand-signs claims bypassing Issue (tests the verifier-side
// independently of the signer-side checks).
func signRaw(t *testing.T, s *Signer, c Claims, now time.Time) (*Claims, error) {
	t.Helper()
	c.Issuer = assertionIssuer
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(30 * time.Second).Unix()
	c.KeyID = s.Kid()
	payload, _ := json.Marshal(c)
	sig := ed25519.Sign(s.priv, payload)
	enc := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return ParseAndVerify(enc, s.Public(), "aud", now)
}

// --- anomaly bounds (P0.30/P0.31/P0.32) ------------------------------------------

// TestDetectorInvalidCredentialSpray proves P0.30: distinct invalid pseudonyms
// per source cross the threshold and emit the invalid-spray signal.
func TestDetectorInvalidCredentialSpray(t *testing.T) {
	base := time.Now()
	d := anomaly.NewDetector(func() time.Time { return base }, anomaly.DefaultThresholds())

	var got []anomaly.Signal
	for i := 0; i < 10; i++ {
		cand := "pseudonym-" + string(rune('a'+i))
		got = append(got, d.ObserveInvalidCredential("src-1", cand, base.Add(time.Duration(i)*time.Second))...)
	}
	if len(got) == 0 || got[len(got)-1].Code != "SOURCE_ATTEMPTING_MANY_INVALID_CREDENTIALS" {
		t.Fatalf("P0.30: invalid-credential spray must emit its signal, got %+v", got)
	}
}

// TestSprayPseudonymProperties proves the pseudonym is deterministic per key,
// key-separated, and never equal across different secrets.
func TestSprayPseudonymProperties(t *testing.T) {
	s1 := []byte("sk-test-secret-one-0000000000000000")
	s2 := []byte("sk-test-secret-two-0000000000000000")
	key := []byte("spray-key")
	a := secret.NewFromBytes(s1).SprayPseudonym(key)
	b := secret.NewFromBytes(s1).SprayPseudonym(key)
	c := secret.NewFromBytes(s2).SprayPseudonym(key)
	d := secret.NewFromBytes(s1).SprayPseudonym([]byte("other-key"))
	if a == "" || a != b {
		t.Fatal("pseudonym must be deterministic per (secret, key)")
	}
	if a == c {
		t.Fatal("different secrets must derive different pseudonyms")
	}
	if a == d {
		t.Fatal("different keys must derive different pseudonyms")
	}
	// Domain separation: the pseudonym must not equal the verifier digest.
	ver := secret.NewFromBytes(s1).DigestHMAC(key)
	if len(ver) > 16 && base64.RawURLEncoding.EncodeToString(ver[:16]) == a {
		t.Fatal("spray pseudonym must be domain-separated from verifier derivation")
	}
}

// TestDetectorEmitCooldown proves P0.32: after the threshold crosses, further
// observations do NOT re-emit until the cooldown elapses.
func TestDetectorEmitCooldown(t *testing.T) {
	base := time.Now()
	th := anomaly.DefaultThresholds()
	d := anomaly.NewDetector(func() time.Time { return base }, th)

	emit := func(at time.Time) int {
		n := 0
		for i := 0; i < 8; i++ {
			if sigs := d.Observe("src-cd", "cred-"+string(rune('a'+i)), "", at); len(sigs) > 0 {
				n++
			}
		}
		return n
	}
	// Crossing at t0: exactly one emission among the 8 observations.
	if n := emit(base); n != 1 {
		t.Fatalf("threshold crossing must emit exactly once, got %d", n)
	}
	// Still inside the cooldown: no re-emission.
	if n := emit(base.Add(th.Cooldown / 2)); n != 0 {
		t.Fatalf("P0.32: cooldown must suppress re-emission, got %d", n)
	}
	// After the cooldown: exactly one more.
	if n := emit(base.Add(th.Cooldown + time.Second)); n != 1 {
		t.Fatalf("after cooldown exactly one re-emission expected, got %d", n)
	}
}
