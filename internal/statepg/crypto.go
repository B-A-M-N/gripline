package statepg

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

const (
	CryptoKindSigner    = "signer"
	CryptoKindPepper    = "pepper"
	CryptoKindPseudonym = "pseudonym"
)

// CryptoGeneration is one loaded cluster capability. Its fingerprint binds
// the generation's public/configuration material without storing secret bytes
// in PostgreSQL.
type CryptoGeneration struct {
	Kind        string
	Generation  int
	Fingerprint string
}

// CryptoIdentity is the public cluster-binding metadata for one node. The
// fingerprints are digests of loaded material, never the material itself.
// Active versions are separate so a cluster can stage a new generation on all
// nodes before an activation operation changes what new data uses.
type CryptoIdentity struct {
	SignerActiveKID            int
	SignerFingerprint          string // legacy/keyset fingerprint of all loaded signer keys
	SignerActiveFingerprint    string
	PepperActiveVersion        int
	PepperFingerprint          string // legacy/keyset fingerprint of all loaded pepper keys
	PepperActiveFingerprint    string
	PseudonymVersion           int
	PseudonymFingerprint       string // legacy/keyset fingerprint of all loaded pseudonym keys
	PseudonymActiveFingerprint string
	// Loaded lists every generation this node can use or verify. It is kept
	// separate from the active fields so adding a staged generation does not
	// change the cluster's active identity.
	Loaded []CryptoGeneration
	// GenerationEpoch is returned by the authority and is not a node-local
	// input during synchronization. It advances only through a cluster-wide
	// activation operation.
	GenerationEpoch uint64
}

func validateCryptoIdentity(identity CryptoIdentity) error {
	_, err := normalizeCryptoIdentity(identity)
	return err
}

func normalizeCryptoIdentity(identity CryptoIdentity) (CryptoIdentity, error) {
	if identity.SignerActiveKID < 1 || identity.PepperActiveVersion < 1 {
		return CryptoIdentity{}, errors.New("statepg: crypto active generations must be positive")
	}
	if identity.PseudonymVersion < 0 {
		return CryptoIdentity{}, errors.New("statepg: pseudonym generation cannot be negative")
	}
	if identity.SignerFingerprint == "" || identity.PepperFingerprint == "" || identity.PseudonymFingerprint == "" {
		return CryptoIdentity{}, errors.New("statepg: crypto fingerprints are required")
	}
	// The active fingerprint fields were added after the original singleton
	// stored whole-keyset fingerprints. Treat the old field as the active
	// fingerprint for source-compatible callers and fresh legacy records; the
	// database migration below backfills the active fields only after a node
	// proves its complete legacy keyset still matches.
	if identity.SignerActiveFingerprint == "" {
		identity.SignerActiveFingerprint = identity.SignerFingerprint
	}
	if identity.PepperActiveFingerprint == "" {
		identity.PepperActiveFingerprint = identity.PepperFingerprint
	}
	if identity.PseudonymActiveFingerprint == "" {
		identity.PseudonymActiveFingerprint = identity.PseudonymFingerprint
	}
	if identity.GenerationEpoch == 0 {
		identity.GenerationEpoch = 1
	}
	if len(identity.Loaded) == 0 {
		identity.Loaded = []CryptoGeneration{
			{Kind: CryptoKindSigner, Generation: identity.SignerActiveKID, Fingerprint: identity.SignerActiveFingerprint},
			{Kind: CryptoKindPepper, Generation: identity.PepperActiveVersion, Fingerprint: identity.PepperActiveFingerprint},
		}
		if identity.PseudonymVersion > 0 {
			identity.Loaded = append(identity.Loaded, CryptoGeneration{Kind: CryptoKindPseudonym, Generation: identity.PseudonymVersion, Fingerprint: identity.PseudonymActiveFingerprint})
		}
	}
	seen := make(map[string]struct{}, len(identity.Loaded))
	for _, generation := range identity.Loaded {
		if generation.Kind != CryptoKindSigner && generation.Kind != CryptoKindPepper && generation.Kind != CryptoKindPseudonym {
			return CryptoIdentity{}, fmt.Errorf("statepg: unknown crypto generation kind %q", generation.Kind)
		}
		if generation.Generation < 1 || generation.Fingerprint == "" {
			return CryptoIdentity{}, errors.New("statepg: loaded crypto generations require positive versions and fingerprints")
		}
		key := fmt.Sprintf("%s/%d", generation.Kind, generation.Generation)
		if _, ok := seen[key]; ok {
			return CryptoIdentity{}, fmt.Errorf("statepg: duplicate loaded crypto generation %s", key)
		}
		seen[key] = struct{}{}
	}
	active := []CryptoGeneration{
		{Kind: CryptoKindSigner, Generation: identity.SignerActiveKID, Fingerprint: identity.SignerActiveFingerprint},
		{Kind: CryptoKindPepper, Generation: identity.PepperActiveVersion, Fingerprint: identity.PepperActiveFingerprint},
	}
	if identity.PseudonymVersion > 0 {
		active = append(active, CryptoGeneration{Kind: CryptoKindPseudonym, Generation: identity.PseudonymVersion, Fingerprint: identity.PseudonymActiveFingerprint})
	}
	for _, want := range active {
		found := false
		for _, got := range identity.Loaded {
			if got.Kind == want.Kind && got.Generation == want.Generation {
				if got.Fingerprint != want.Fingerprint {
					return CryptoIdentity{}, fmt.Errorf("statepg: active %s generation %d fingerprint differs from loaded capability", want.Kind, want.Generation)
				}
				found = true
				break
			}
		}
		if !found {
			return CryptoIdentity{}, fmt.Errorf("statepg: active %s generation %d is not loaded", want.Kind, want.Generation)
		}
	}
	return identity, nil
}

func sameCryptoIdentity(a, b CryptoIdentity) bool {
	return a.SignerActiveKID == b.SignerActiveKID &&
		a.SignerActiveFingerprint == b.SignerActiveFingerprint &&
		a.PepperActiveVersion == b.PepperActiveVersion &&
		a.PepperActiveFingerprint == b.PepperActiveFingerprint &&
		a.PseudonymVersion == b.PseudonymVersion &&
		a.PseudonymActiveFingerprint == b.PseudonymActiveFingerprint
}

// SynchronizeCrypto creates the cluster crypto record once and thereafter
// requires every node to prove the shared active generations. Additional
// loaded generations are recorded as staged capabilities and acknowledged by
// the node, so preloading a future generation does not change active identity.
func (s *Store) SynchronizeCrypto(ctx context.Context, local CryptoIdentity) (CryptoIdentity, error) {
	normalized, err := normalizeCryptoIdentity(local)
	if err != nil {
		return CryptoIdentity{}, err
	}
	local = normalized
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
	err = tx.QueryRow(ctx, `SELECT signer_active_kid, signer_fingerprint, signer_active_fingerprint,
		pepper_active_version, pepper_fingerprint, pepper_active_fingerprint, pseudonym_version,
		pseudonym_fingerprint, pseudonym_active_fingerprint, generation_epoch FROM gripline_cluster_crypto WHERE singleton=TRUE FOR UPDATE`).Scan(
		&shared.SignerActiveKID, &shared.SignerFingerprint, &shared.SignerActiveFingerprint,
		&shared.PepperActiveVersion, &shared.PepperFingerprint, &shared.PepperActiveFingerprint,
		&shared.PseudonymVersion, &shared.PseudonymFingerprint, &shared.PseudonymActiveFingerprint, &shared.GenerationEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx, `INSERT INTO gripline_cluster_crypto
			(singleton, signer_active_kid, signer_fingerprint, signer_active_fingerprint, pepper_active_version,
				pepper_fingerprint, pepper_active_fingerprint, pseudonym_version, pseudonym_fingerprint,
				pseudonym_active_fingerprint, generation_epoch, updated_at)
			VALUES (TRUE,$1,$2,$3,$4,$5,$6,$7,$8,$9,1,CURRENT_TIMESTAMP)`,
			local.SignerActiveKID, local.SignerFingerprint, local.SignerActiveFingerprint, local.PepperActiveVersion,
			local.PepperFingerprint, local.PepperActiveFingerprint, local.PseudonymVersion, local.PseudonymFingerprint,
			local.PseudonymActiveFingerprint)
		if err != nil {
			return CryptoIdentity{}, retryableTransactionError(err), mapDBError(err)
		}
		shared = local
		shared.GenerationEpoch = 1
	} else if err != nil {
		return CryptoIdentity{}, retryableTransactionError(err), mapDBError(err)
	} else if shared.SignerActiveFingerprint == "" {
		if local.SignerFingerprint != shared.SignerFingerprint || local.PepperFingerprint != shared.PepperFingerprint || local.PseudonymFingerprint != shared.PseudonymFingerprint {
			return CryptoIdentity{}, false, errors.New("statepg: legacy cluster crypto keyset fingerprint mismatch")
		}
		shared.SignerActiveFingerprint = local.SignerActiveFingerprint
		shared.PepperActiveFingerprint = local.PepperActiveFingerprint
		shared.PseudonymActiveFingerprint = local.PseudonymActiveFingerprint
		if _, err := tx.Exec(ctx, `UPDATE gripline_cluster_crypto SET signer_active_fingerprint=$1, pepper_active_fingerprint=$2, pseudonym_active_fingerprint=$3 WHERE singleton=TRUE`, shared.SignerActiveFingerprint, shared.PepperActiveFingerprint, shared.PseudonymActiveFingerprint); err != nil {
			return CryptoIdentity{}, retryableTransactionError(err), mapDBError(err)
		}
	} else if local.SignerActiveKID != shared.SignerActiveKID {
		return CryptoIdentity{}, false, fmt.Errorf("statepg: local signer active generation %d differs from shared generation %d", local.SignerActiveKID, shared.SignerActiveKID)
	} else if !matchesLoaded(local, CryptoKindSigner, shared.SignerActiveKID, shared.SignerActiveFingerprint) ||
		!matchesLoaded(local, CryptoKindPepper, shared.PepperActiveVersion, shared.PepperActiveFingerprint) ||
		(shared.PseudonymVersion > 0 && !matchesLoaded(local, CryptoKindPseudonym, shared.PseudonymVersion, shared.PseudonymActiveFingerprint)) {
		return CryptoIdentity{}, false, fmt.Errorf("statepg: cluster crypto identity mismatch: shared signer=%d/%s pepper=%d/%s pseudonym=%d/%s",
			shared.SignerActiveKID, shared.SignerFingerprint,
			shared.PepperActiveVersion, shared.PepperFingerprint,
			shared.PseudonymVersion, shared.PseudonymFingerprint)
	}
	if err := recordCryptoCapabilities(ctx, tx, s, local, shared); err != nil {
		return CryptoIdentity{}, retryableTransactionError(err), err
	}
	if err := tx.Commit(ctx); err != nil {
		return CryptoIdentity{}, retryableTransactionError(err), mapDBError(err)
	}
	return shared, false, nil
}

func matchesLoaded(identity CryptoIdentity, kind string, generation int, fingerprint string) bool {
	for _, loaded := range identity.Loaded {
		if loaded.Kind == kind && loaded.Generation == generation {
			return loaded.Fingerprint == fingerprint
		}
	}
	return false
}

func recordCryptoCapabilities(ctx context.Context, tx pgx.Tx, s *Store, local, shared CryptoIdentity) error {
	loaded := append([]CryptoGeneration(nil), local.Loaded...)
	sort.Slice(loaded, func(i, j int) bool {
		if loaded[i].Kind != loaded[j].Kind {
			return loaded[i].Kind < loaded[j].Kind
		}
		return loaded[i].Generation < loaded[j].Generation
	})
	for _, generation := range loaded {
		var storedFingerprint, state string
		err := tx.QueryRow(ctx, `SELECT fingerprint, state FROM gripline_cluster_crypto_generations
			WHERE kind=$1 AND generation=$2 FOR UPDATE`, generation.Kind, generation.Generation).Scan(&storedFingerprint, &state)
		active := (generation.Kind == CryptoKindSigner && generation.Generation == shared.SignerActiveKID && generation.Fingerprint == shared.SignerActiveFingerprint) ||
			(generation.Kind == CryptoKindPepper && generation.Generation == shared.PepperActiveVersion && generation.Fingerprint == shared.PepperActiveFingerprint) ||
			(generation.Kind == CryptoKindPseudonym && shared.PseudonymVersion > 0 && generation.Generation == shared.PseudonymVersion && generation.Fingerprint == shared.PseudonymActiveFingerprint)
		if errors.Is(err, pgx.ErrNoRows) {
			state = "loaded"
			if active {
				state = "active"
			}
			if _, err := tx.Exec(ctx, `INSERT INTO gripline_cluster_crypto_generations
				(kind, generation, fingerprint, state, updated_at) VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP)`, generation.Kind, generation.Generation, generation.Fingerprint, state); err != nil {
				return mapDBError(err)
			}
		} else if err != nil {
			return mapDBError(err)
		} else if storedFingerprint != generation.Fingerprint {
			return fmt.Errorf("statepg: crypto generation mismatch: %s/%d shared fingerprint differs", generation.Kind, generation.Generation)
		} else if state == "retired" {
			return fmt.Errorf("statepg: crypto generation %s/%d is retired", generation.Kind, generation.Generation)
		} else if active && state != "active" {
			if _, err := tx.Exec(ctx, `UPDATE gripline_cluster_crypto_generations SET state='active', updated_at=CURRENT_TIMESTAMP WHERE kind=$1 AND generation=$2`, generation.Kind, generation.Generation); err != nil {
				return mapDBError(err)
			}
		}
		if s.nodeID != "" {
			if _, err := tx.Exec(ctx, `INSERT INTO gripline_cluster_crypto_acks
				(node_id, node_epoch, kind, generation, fingerprint, acknowledged_at)
				VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP)
				ON CONFLICT (node_id,node_epoch,kind,generation) DO UPDATE SET fingerprint=EXCLUDED.fingerprint, acknowledged_at=EXCLUDED.acknowledged_at`,
				s.nodeID, s.nodeEpoch, generation.Kind, generation.Generation, generation.Fingerprint); err != nil {
				return mapDBError(err)
			}
		}
	}
	return nil
}
