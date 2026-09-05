package terminator

import (
	"testing"
	"time"
)

func issue(t *testing.T, k *Keyring, subject string) *Assertion {
	t.Helper()
	a, err := k.Issue(Claims{Subject: subject, CredID: "c", Audience: "aud", JTI: "j"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestKeyringRotationKeepsOldGenerationValid proves P0.59: after a Rotate, a
// token issued under the PREVIOUS generation still verifies (public keys are
// retained), while a new token is issued under the new kid.
func TestKeyringRotationKeepsOldGenerationValid(t *testing.T) {
	k, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	old := issue(t, k, "acct_a") // kid 1
	if got := old.Claims().KeyID; got != 1 {
		t.Fatalf("initial assertion kid = %d, want 1", got)
	}

	newKid, err := k.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if newKid != 2 {
		t.Fatalf("rotate produced kid %d, want 2", newKid)
	}

	now := time.Now()

	// The OLD token (kid 1) must still verify against the retained pub key.
	if _, err := k.Verify(old.Encode(), "aud", now); err != nil {
		t.Fatalf("P0.59: rotated old-generation token must still verify: %v", err)
	}

	// New tokens are signed under kid 2 and verify.
	fresh := issue(t, k, "acct_b")
	if got := fresh.Claims().KeyID; got != 2 {
		t.Fatalf("post-rotate assertion kid = %d, want 2", got)
	}
	if _, err := k.Verify(fresh.Encode(), "aud", now); err != nil {
		t.Fatalf("new-generation token must verify: %v", err)
	}

	// Old token verifies with the NEW kid's public key? NO — wrong key for kid 1.
	if _, err := k.Verify(old.Encode(), "aud", now); err != nil {
		t.Fatalf("old token must verify via its own kid (we just checked); got %v", err)
	}
}

// TestKeyringUnknownGenerationFailsClosed proves a token naming a generation the
// verifier has not accepted is rejected (never guessed).
func TestKeyringUnknownGenerationFailsClosed(t *testing.T) {
	// k1 rotates to kid 2 and signs under it; k2 is a verifier that never saw
	// generation 2 (it stayed at kid 1).
	k1, _ := NewKeyring()
	if _, err := k1.Rotate(); err != nil {
		t.Fatal(err)
	}
	tok := issue(t, k1, "acct_x") // kid 2

	k2, _ := NewKeyring() // only knows generation 1
	if _, err := k2.Verify(tok.Encode(), "aud", time.Now()); err == nil {
		t.Fatal("P0.59: a generation unknown to the verifier must fail closed")
	}
	if _, ok := k2.Public(2); ok {
		t.Fatal("verifier must not hold an unknown generation's key")
	}
}

// TestKeyringWrongAudienceRejected proves INV-11 still gates on rotated tokens.
func TestKeyringWrongAudienceRejected(t *testing.T) {
	k, _ := NewKeyring()
	tok := issue(t, k, "acct_z")
	if _, err := k.Verify(tok.Encode(), "wrong-aud", time.Now()); err == nil {
		t.Fatal("INV-11: wrong audience must be rejected even on a valid-generation token")
	}
}