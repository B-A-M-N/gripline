package terminator

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKeyringSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	// Generate a keyring and save it.
	kr1, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr1.Save(path); err != nil {
		t.Fatal(err)
	}

	// Verify file permissions are restrictive.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	// Load it back.
	kr2, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}

	// Both should have the same active kid and be able to verify each other's assertions.
	if kr1.ActiveKid() != kr2.ActiveKid() {
		t.Fatalf("active kid mismatch: %d vs %d", kr1.ActiveKid(), kr2.ActiveKid())
	}

	// Issue with kr1, verify with kr2.
	assertion, err := kr1.Issue(Claims{Subject: "acct_test", Audience: "test-audience", CredID: "cred_test", JTI: "test-jti-1", Scope: []string{"inference"}, PolicyRev: 1, CredRev: 1}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr2.Verify(assertion.Encode(), "test-audience", time.Now()); err != nil {
		t.Fatalf("kr2 should verify kr1's assertion: %v", err)
	}
}

func TestKeyringLoadGeneratesIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	// Load from non-existent path: should generate and save.
	kr, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if kr == nil {
		t.Fatal("expected non-nil keyring")
	}

	// File should now exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected keyring file to exist: %v", err)
	}
}

// TestKeyringRotationPersistence (release hardening, P0.59+) proves that a
// keyring survives SAVE → ROTATE → SAVE → RELOAD cycles at every generation,
// that assertions issued by a reloaded keyring verify with a reloaded
// verifier, and that the active kid advances across generations.
func TestKeyringRotationPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	// Build a fresh keyring, persist kid 1.
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Save(path); err != nil {
		t.Fatal(err)
	}

	// Per-generation cycle: rotate → save → reload → issue → verify.
	// We verify that the loaded kid matches and that a loaded VERIFIER
	// (PublishVerifier) accepts an assertion signed by the reloaded signer.
	for want := 2; want <= 3; want++ {
		kid, err := kr.Rotate()
		if err != nil {
			t.Fatal(err)
		}
		if kid != want {
			t.Fatalf("rotate: got kid %d, want %d", kid, want)
		}
		if err := kr.Save(path); err != nil {
			t.Fatalf("save after rotate %d: %v", kid, err)
		}

		reloaded, err := LoadKeyring(path)
		if err != nil {
			t.Fatalf("reload after rotate %d: %v", kid, err)
		}
		if reloaded.ActiveKid() != kid {
			t.Fatalf("reloaded active kid = %d, want %d", reloaded.ActiveKid(), kid)
		}

		// Reloaded signer issues; reloaded verifier (publics only) verifies.
		assertion, err := reloaded.Issue(Claims{Subject: "acct", Audience: "aud", CredID: "cred", JTI: "jti", Scope: []string{"inference"}, PolicyRev: 1, CredRev: 1}, 10*time.Second)
		if err != nil {
			t.Fatalf("reloaded issue: %v", err)
		}
		verifier := reloaded.PublishVerifier()
		if _, err := verifier.Verify(assertion.Encode(), "aud", time.Now()); err != nil {
			t.Fatalf("reloaded verifier rejected reloaded signer kid %d: %v", kid, err)
		}

		// The retained value of the previous cycle's keyring must have been
		// PERSISTED and reloaded; assert generations 1..kid are all publishable.
		keys := reloaded.PublicKeys()
		if len(keys) != kid {
			t.Fatalf("reloaded keyring has %d generations, want %d", len(keys), kid)
		}
	}

	// After the loop, kr (in-memory) has advanced too; confirm a round-trip
	// assertion still verifies through the persisted on-disk keyring.
	assertion, err := kr.Issue(Claims{Subject: "acct", Audience: "aud", CredID: "cred", JTI: "final", Scope: []string{"inference"}, PolicyRev: 1, CredRev: 1}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	final, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := final.Verify(assertion.Encode(), "aud", time.Now()); err != nil {
		t.Fatalf("final reloaded keyring failed to verify in-memory keyring's assertion: %v", err)
	}
}

func TestPreparedRotationPersistsPhaseAndRetirementHorizon(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Save(path); err != nil {
		t.Fatal(err)
	}
	var phases []string
	candidate, err := kr.PrepareRotationWithAudit(path, func(event RotationEvent) error {
		phases = append(phases, event.Phase)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadExistingKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ActiveKid() != 1 || len(reloaded.PublicKeys()) != 2 {
		t.Fatalf("prepared candidate changed active publication: kid=%d keys=%d", reloaded.ActiveKid(), len(reloaded.PublicKeys()))
	}
	if err := reloaded.RetireAfter(path, 1, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("retirement before assertion TTL/skew horizon must be rejected")
	}
	if err := reloaded.ActivatePreparedWithAudit(path, candidate.KID, func(public []byte) error {
		if len(public) != ed25519.PublicKeySize {
			return fmt.Errorf("bad public key")
		}
		return nil
	}, func(event RotationEvent) error {
		phases = append(phases, event.Phase)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.RetireAfterWithAudit(path, 1, time.Now().Add(-time.Second), func(event RotationEvent) error {
		phases = append(phases, event.Phase)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(phases); got != "[prepared activated retired]" {
		t.Fatalf("rotation phases=%s", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted keyringPersist
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.RotationHistory) != 3 || persisted.RotationHistory[0].Phase != "prepared" || persisted.RotationHistory[1].Phase != "activated" || persisted.RotationHistory[2].Phase != "retired" {
		t.Fatalf("durable rotation history=%+v", persisted.RotationHistory)
	}
}

// TestKeyringLoadRejectsCorruptPack fails closed on a hand-edited or truncated
// persisted keyring (release hardening): a mismatched active key / verifier
// table, a non-monotonic next kid, or a zero active kid must refuse to load
// rather than serve a wrong signing pair.
func TestKeyringLoadRejectsCorruptPack(t *testing.T) {
	dir := t.TempDir()

	// corruptPack saves a fresh keyring then rewrites it with `mutate` applied
	// to the decoded persisted fields.
	corruptPack := func(mutate func(p *keyringPersist)) {
		path := filepath.Join(dir, mutateKey()+".json")
		kr, err := NewKeyring()
		if err != nil {
			t.Fatal(err)
		}
		if err := kr.Save(path); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var p keyringPersist
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		mutate(&p)
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeyring(path); err == nil {
			t.Fatalf("expected LoadKeyring to reject corruption: active_kid=%d next=%d verifiers=%d",
				p.ActiveKid, p.Next, len(p.Verifiers))
		}
	}

	// Next not greater than ActiveKid.
	corruptPack(func(p *keyringPersist) { p.Next = p.ActiveKid })
	// Active kid below 1.
	corruptPack(func(p *keyringPersist) { p.ActiveKid = 0 })
	// Verifier table missing the active kid.
	corruptPack(func(p *keyringPersist) { delete(p.Verifiers, p.ActiveKid) })
	// Active private key's public component disagrees with the persisted verifier.
	corruptPack(func(p *keyringPersist) { p.Active = mustReplacePublic(p.Active) })
	// A verifier key of the wrong length.
	corruptPack(func(p *keyringPersist) {
		p.Verifiers[p.ActiveKid] = base64.StdEncoding.EncodeToString(make([]byte, 16))
	})
}

var mutateCounter int

func mutateKey() string {
	mutateCounter++
	return fmt.Sprintf("kr%d", mutateCounter)
}

// mustReplacePublic returns a base64 private key whose embedded public half is
// a DIFFERENT fixed key than the original, so the active private key's public
// component no longer matches the persisted verifier for the same kid.
func mustReplacePublic(activeB64 string) string {
	priv, err := base64.StdEncoding.DecodeString(activeB64)
	if err != nil {
		panic(err)
	}
	// A fixed, distinct Ed25519 secret scalar + public combination. We simply
	// overwrite the public half with 32 zero bytes (an invalid key, but a
	// mismatched public component is what we're testing) — LoadKeyring must
	// reject the mismatch before ever using it.
	copy(priv[32:], make([]byte, ed25519.PublicKeySize))
	return base64.StdEncoding.EncodeToString(priv)
}
