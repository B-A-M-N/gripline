package main

import (
	"context"
	"fmt"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/ingress"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type cryptoSynchronizer interface {
	SynchronizeCrypto(context.Context, statepg.CryptoIdentity) (statepg.CryptoIdentity, error)
}

type preparedSignerAcceptor interface {
	AcceptPrepared(context.Context, *terminator.Keyring, int, []byte) error
}

type signerVerifierRetirer interface {
	RetireKey(context.Context, int, string) error
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
	return reconcileClusterCryptoWithSigner(ctx, shared, authority, signer, peppers, pseudonyms, "", nil)
}

func reconcileClusterCryptoWithSigner(ctx context.Context, shared statepg.CryptoIdentity, authority cryptoSynchronizer, signer *terminator.Keyring, peppers *credential.PepperRing, pseudonyms ingress.PseudonymRing, signerPath string, acceptor preparedSignerAcceptor) error {
	if signer == nil || peppers == nil || authority == nil {
		return fmt.Errorf("gripline: incomplete cluster crypto reconciler")
	}
	if signer.ActiveKid() != shared.SignerActiveKID {
		if signerPath == "" || acceptor == nil {
			return fmt.Errorf("gripline: active signer generation %d requires backend verifier acceptance; authority selected %d", signer.ActiveKid(), shared.SignerActiveKID)
		}
		prepared, ok := signer.PreparedKid()
		if !ok || prepared != shared.SignerActiveKID {
			return fmt.Errorf("gripline: signer generation %d is not locally prepared", shared.SignerActiveKID)
		}
		if err := signer.ActivatePrepared(signerPath, shared.SignerActiveKID, func(public []byte) error {
			return acceptor.AcceptPrepared(ctx, signer, shared.SignerActiveKID, public)
		}); err != nil {
			return fmt.Errorf("gripline: activate signer generation %d: %w", shared.SignerActiveKID, err)
		}
	}
	for _, retired := range shared.Retired {
		switch retired.Kind {
		case statepg.CryptoKindSigner:
			if signer.ActiveKid() == retired.Generation {
				return fmt.Errorf("gripline: shared retired signer generation %d is still active locally", retired.Generation)
			}
			if _, loaded := signer.Public(retired.Generation); loaded {
				retirer, ok := acceptor.(signerVerifierRetirer)
				if !ok {
					return fmt.Errorf("gripline: retired signer generation %d requires backend verifier retirement", retired.Generation)
				}
				if err := retirer.RetireKey(ctx, retired.Generation, retired.Fingerprint); err != nil {
					return fmt.Errorf("gripline: retire backend signer generation %d: %w", retired.Generation, err)
				}
				if signerPath == "" {
					return fmt.Errorf("gripline: signer keyring path required to retire generation %d", retired.Generation)
				}
				if err := signer.RetireAfter(signerPath, retired.Generation, time.Time{}); err != nil {
					return fmt.Errorf("gripline: retire local signer generation %d: %w", retired.Generation, err)
				}
			}
		case statepg.CryptoKindPepper:
			if _, loaded := peppers.VersionFingerprint(retired.Generation); loaded {
				if err := peppers.RetireVersion(retired.Generation); err != nil {
					return fmt.Errorf("gripline: retire local pepper generation %d: %w", retired.Generation, err)
				}
			}
		case statepg.CryptoKindPseudonym:
			if configured, ok := pseudonyms.(*pseudonymRingAdapter); ok {
				if _, loaded := configured.VersionFingerprint(retired.Generation); loaded {
					if err := configured.RetireVersion(retired.Generation); err != nil {
						return fmt.Errorf("gripline: retire local pseudonym generation %d: %w", retired.Generation, err)
					}
				}
			}
		}
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
