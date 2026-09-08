package main

import (
	"context"
	"fmt"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/ingress"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type cryptoSynchronizer interface {
	SynchronizeCrypto(context.Context, statepg.CryptoIdentity) (statepg.CryptoIdentity, error)
}

func localCryptoIdentity(signer *terminator.Keyring, peppers *credential.PepperRing, pseudonyms ingress.PseudonymRing) (statepg.CryptoIdentity, error) {
	if signer == nil || peppers == nil {
		return statepg.CryptoIdentity{}, fmt.Errorf("gripline: signer and pepper ring are required")
	}
	loaded := make([]statepg.CryptoGeneration, 0)
	for kid, fingerprint := range signer.PublicKeyFingerprints() {
		loaded = append(loaded, statepg.CryptoGeneration{Kind: statepg.CryptoKindSigner, Generation: kid, Fingerprint: fingerprint})
	}
	for version, fingerprint := range peppers.VersionFingerprints() {
		loaded = append(loaded, statepg.CryptoGeneration{Kind: statepg.CryptoKindPepper, Generation: version, Fingerprint: fingerprint})
	}
	pseudonymVersion := 0
	pseudonymFingerprint := "disabled"
	pseudonymLoadedFingerprint := "disabled"
	if configured, ok := pseudonyms.(*pseudonymRingAdapter); ok {
		pseudonymVersion = configured.ActiveVersion()
		pseudonymLoadedFingerprint = configured.Fingerprint()
		if pseudonymVersion > 0 {
			var found bool
			pseudonymFingerprint, found = configured.VersionFingerprint(pseudonymVersion)
			if !found {
				return statepg.CryptoIdentity{}, fmt.Errorf("gripline: active pseudonym generation %d is not loaded", pseudonymVersion)
			}
		}
		for version, fingerprint := range configured.VersionFingerprints() {
			loaded = append(loaded, statepg.CryptoGeneration{Kind: statepg.CryptoKindPseudonym, Generation: version, Fingerprint: fingerprint})
		}
	}
	signerKID := signer.ActiveKid()
	signerFingerprint, ok := signer.PublicKeyFingerprint(signerKID)
	if !ok {
		return statepg.CryptoIdentity{}, fmt.Errorf("gripline: active signer generation %d is not loaded", signerKID)
	}
	pepperVersion := peppers.ActiveVersion()
	pepperFingerprint, ok := peppers.VersionFingerprint(pepperVersion)
	if !ok {
		return statepg.CryptoIdentity{}, fmt.Errorf("gripline: active pepper generation %d is not loaded", pepperVersion)
	}
	return statepg.CryptoIdentity{
		SignerActiveKID: signerKID, SignerFingerprint: signer.PublicKeysetFingerprint(), SignerActiveFingerprint: signerFingerprint,
		PepperActiveVersion: pepperVersion, PepperFingerprint: peppers.Fingerprint(), PepperActiveFingerprint: pepperFingerprint,
		PseudonymVersion: pseudonymVersion, PseudonymFingerprint: pseudonymLoadedFingerprint, PseudonymActiveFingerprint: pseudonymFingerprint,
		Loaded: loaded,
	}, nil
}

// reconcileClusterCrypto applies only authority-selected generations. A
// signer mismatch remains unready until the explicit signer lifecycle has
// activated the locally prepared private key; secret-ring generations must
// never be guessed from the highest loaded version.
func reconcileClusterCrypto(ctx context.Context, shared statepg.CryptoIdentity, authority cryptoSynchronizer, signer *terminator.Keyring, peppers *credential.PepperRing, pseudonyms ingress.PseudonymRing) error {
	if signer == nil || peppers == nil || authority == nil {
		return fmt.Errorf("gripline: incomplete cluster crypto reconciler")
	}
	if signer.ActiveKid() != shared.SignerActiveKID {
		return fmt.Errorf("gripline: active signer generation %d requires explicit local activation; authority selected %d", signer.ActiveKid(), shared.SignerActiveKID)
	}
	if err := peppers.SetActiveVersion(shared.PepperActiveVersion); err != nil {
		return fmt.Errorf("gripline: reconcile pepper generation: %w", err)
	}
	if configured, ok := pseudonyms.(*pseudonymRingAdapter); ok && shared.PseudonymVersion > 0 {
		if err := configured.SetActiveVersion(shared.PseudonymVersion); err != nil {
			return fmt.Errorf("gripline: reconcile pseudonym generation: %w", err)
		}
	}
	local, err := localCryptoIdentity(signer, peppers, pseudonyms)
	if err != nil {
		return err
	}
	if _, err := authority.SynchronizeCrypto(ctx, local); err != nil {
		return fmt.Errorf("gripline: acknowledge reconciled crypto generation: %w", err)
	}
	return nil
}
