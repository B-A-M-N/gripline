package main

import (
	"context"
	"testing"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/pseudonym"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type recordingCryptoSynchronizer struct {
	identity statepg.CryptoIdentity
	called   bool
}

func (s *recordingCryptoSynchronizer) SynchronizeCrypto(_ context.Context, identity statepg.CryptoIdentity) (statepg.CryptoIdentity, error) {
	s.called = true
	s.identity = identity
	return identity, nil
}

func TestReconcileClusterCryptoSelectsSharedRingGenerations(t *testing.T) {
	signer, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	peppers := credential.MustPepperRing(
		&credential.PepperKey{Version: 1, Key: []byte("pepper-generation-one-0123456789")},
		&credential.PepperKey{Version: 2, Key: []byte("pepper-generation-two-0123456789")},
	)
	pseudonymRing, err := pseudonym.NewRing(
		&pseudonym.Key{Version: 1, Secret: []byte("pseudonym-generation-one-0123456789")},
		&pseudonym.Key{Version: 2, Secret: []byte("pseudonym-generation-two-0123456789")},
	)
	if err != nil {
		t.Fatal(err)
	}
	pseudonyms := &pseudonymRingAdapter{ring: pseudonymRing}
	// Simulate a node that started with the locally highest configured rings.
	if err := peppers.SetActiveVersion(1); err != nil {
		t.Fatal(err)
	}
	if err := pseudonyms.SetActiveVersion(1); err != nil {
		t.Fatal(err)
	}
	pepperFingerprint, _ := peppers.VersionFingerprint(2)
	pseudonymFingerprint, _ := pseudonyms.VersionFingerprint(2)
	shared := statepg.CryptoIdentity{
		SignerActiveKID:     1,
		PepperActiveVersion: 2, PepperActiveFingerprint: pepperFingerprint,
		PseudonymVersion: 2, PseudonymActiveFingerprint: pseudonymFingerprint,
	}
	shared.SignerActiveFingerprint, _ = signer.PublicKeyFingerprint(1)
	authority := &recordingCryptoSynchronizer{}
	if err := reconcileClusterCrypto(context.Background(), shared, authority, signer, peppers, pseudonyms); err != nil {
		t.Fatal(err)
	}
	if peppers.ActiveVersion() != 2 || pseudonyms.ActiveVersion() != 2 {
		t.Fatalf("active generations pepper=%d pseudonym=%d, want 2/2", peppers.ActiveVersion(), pseudonyms.ActiveVersion())
	}
	if !authority.called {
		t.Fatal("reconciliation must acknowledge the applied generations")
	}
	if authority.identity.PepperActiveVersion != 2 || authority.identity.PseudonymVersion != 2 {
		t.Fatalf("acknowledged identity=%+v, want shared ring generations", authority.identity)
	}
}

func TestReconcileClusterCryptoRefusesSignerSwitch(t *testing.T) {
	signer, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	peppers := credential.MustPepperRing(&credential.PepperKey{Version: 1, Key: []byte("pepper-generation-one-0123456789")})
	authority := &recordingCryptoSynchronizer{}
	shared := statepg.CryptoIdentity{SignerActiveKID: signer.ActiveKid() + 1, PepperActiveVersion: 1, PseudonymVersion: 0}
	if err := reconcileClusterCrypto(context.Background(), shared, authority, signer, peppers, nil); err == nil {
		t.Fatal("signer activation must require the explicit backend-acceptance lifecycle")
	}
	if authority.called {
		t.Fatal("refused signer switch must not acknowledge the authority")
	}
}
