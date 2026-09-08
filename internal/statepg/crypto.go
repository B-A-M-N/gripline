package statepg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// CryptoIdentity is the public cluster-binding metadata for one node. The
// fingerprints are digests of loaded material, never the material itself.
// Active versions are separate so a cluster can stage a new generation on all
// nodes before an activation operation changes what new data uses.
type CryptoIdentity struct {
	SignerActiveKID      int
	SignerFingerprint    string
	PepperActiveVersion  int
	PepperFingerprint    string
	PseudonymVersion     int
	PseudonymFingerprint string
}

func validateCryptoIdentity(identity CryptoIdentity) error {
	if identity.SignerActiveKID < 1 || identity.PepperActiveVersion < 1 {
		return errors.New("statepg: crypto active generations must be positive")
	}
	if identity.PseudonymVersion < 0 {
		return errors.New("statepg: pseudonym generation cannot be negative")
	}
	if identity.SignerFingerprint == "" || identity.PepperFingerprint == "" || identity.PseudonymFingerprint == "" {
		return errors.New("statepg: crypto fingerprints are required")
	}
	return nil
}

func sameCryptoIdentity(a, b CryptoIdentity) bool {
	return a.SignerActiveKID == b.SignerActiveKID &&
		a.SignerFingerprint == b.SignerFingerprint &&
		a.PepperActiveVersion == b.PepperActiveVersion &&
		a.PepperFingerprint == b.PepperFingerprint &&
		a.PseudonymVersion == b.PseudonymVersion &&
		a.PseudonymFingerprint == b.PseudonymFingerprint
}

// SynchronizeCrypto creates the cluster crypto record once and thereafter
// requires every node to present the same loaded keysets and active
// generations. It returns the shared active record so a node with staged
// material can select the already-authoritative generation before serving.
func (s *Store) SynchronizeCrypto(ctx context.Context, local CryptoIdentity) (CryptoIdentity, error) {
	if err := validateCryptoIdentity(local); err != nil {
		return CryptoIdentity{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 0; attempt < 3; attempt++ {
		shared, retry, err := s.synchronizeCryptoOnce(ctx, local)
		if err == nil {
			s.cryptoReady.Store(true)
			return shared, nil
		}
		if !retry || ctx.Err() != nil {
			return CryptoIdentity{}, err
		}
	}
	return CryptoIdentity{}, errors.New("statepg: crypto identity remained conflicted after retries")
}

func (s *Store) synchronizeCryptoOnce(ctx context.Context, local CryptoIdentity) (CryptoIdentity, bool, error) {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return CryptoIdentity{}, retryableTransactionError(err), mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeMembership(ctx, tx, false, false); err != nil {
		return CryptoIdentity{}, false, err
	}
	var shared CryptoIdentity
	err = tx.QueryRow(ctx, `SELECT signer_active_kid, signer_fingerprint,
		pepper_active_version, pepper_fingerprint, pseudonym_version,
		pseudonym_fingerprint FROM gripline_cluster_crypto WHERE singleton=TRUE FOR UPDATE`).Scan(
		&shared.SignerActiveKID, &shared.SignerFingerprint,
		&shared.PepperActiveVersion, &shared.PepperFingerprint,
		&shared.PseudonymVersion, &shared.PseudonymFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx, `INSERT INTO gripline_cluster_crypto
			(singleton, signer_active_kid, signer_fingerprint, pepper_active_version,
			 pepper_fingerprint, pseudonym_version, pseudonym_fingerprint, updated_at)
			VALUES (TRUE,$1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)`,
			local.SignerActiveKID, local.SignerFingerprint, local.PepperActiveVersion,
			local.PepperFingerprint, local.PseudonymVersion, local.PseudonymFingerprint)
		if err != nil {
			return CryptoIdentity{}, retryableTransactionError(err), mapDBError(err)
		}
		shared = local
	} else if err != nil {
		return CryptoIdentity{}, retryableTransactionError(err), mapDBError(err)
	} else if !sameCryptoIdentity(shared, local) {
		return CryptoIdentity{}, false, fmt.Errorf("statepg: cluster crypto identity mismatch: shared signer=%d/%s pepper=%d/%s pseudonym=%d/%s",
			shared.SignerActiveKID, shared.SignerFingerprint,
			shared.PepperActiveVersion, shared.PepperFingerprint,
			shared.PseudonymVersion, shared.PseudonymFingerprint)
	}
	if err := tx.Commit(ctx); err != nil {
		return CryptoIdentity{}, retryableTransactionError(err), mapDBError(err)
	}
	return shared, false, nil
}
