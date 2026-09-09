package statepg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/jackc/pgx/v5"
)

const (
	CryptoKindSigner    = "signer"
	CryptoKindPepper    = "pepper"
	CryptoKindPseudonym = "pseudonym"
	// Signer assertions can remain valid for the configured policy TTL plus a
	// bounded clock-skew allowance. The authority persists this horizon when a
	// signer is superseded so retirement does not depend on a client clock.
	cryptoSignerRetirementHorizon = 35 * time.Second
)

// CryptoGeneration is one loaded cluster capability. Its fingerprint binds
// the generation's public/configuration material without storing secret bytes
// in PostgreSQL.
type CryptoGeneration struct {
	Kind        string
	Generation  int
	Fingerprint string
}

// CryptoActivationRequest is the operator-approved request to make one
// staged generation active for new cluster data. The operation ID is
// mandatory: activation changes shared security authority, so an ambiguous
// commit must be safely retryable rather than repeated.
type CryptoActivationRequest struct {
	Kind        string
	Generation  int
	Fingerprint string
	OperationID string
	Actor       string
	Reason      string
}

// CryptoRetirementRequest removes one generation from the cluster's accepted
// capability set after the authority-owned overlap horizon. NotBefore is an
// optional operator-supplied lower bound; the persisted supersession horizon
// always wins. Retirement is separate from activation because it must never
// remove the currently active generation and because secret-ring/source-scope
// safety checks differ from activation.
type CryptoRetirementRequest struct {
	Kind        string
	Generation  int
	Fingerprint string
	NotBefore   time.Time
	OperationID string
	Actor       string
	Reason      string
}

// ErrCryptoActivationBarrier means one or more live nodes have not loaded
// and acknowledged the exact generation being activated.
var (
	ErrCryptoActivationBarrier = errors.New("statepg: crypto activation barrier not satisfied")
	ErrCryptoIdentityStale     = errors.New("statepg: local crypto identity is stale")
)

type cryptoObservation struct {
	signerKID, pepperVersion, pseudonymVersion int
	signerFingerprint, pepperFingerprint       string
	pseudonymFingerprint                       string
	epoch                                      uint64
}

func observationFor(identity CryptoIdentity) cryptoObservation {
	return cryptoObservation{
		signerKID: identity.SignerActiveKID, signerFingerprint: identity.SignerActiveFingerprint,
		pepperVersion: identity.PepperActiveVersion, pepperFingerprint: identity.PepperActiveFingerprint,
		pseudonymVersion: identity.PseudonymVersion, pseudonymFingerprint: identity.PseudonymActiveFingerprint,
		epoch: identity.GenerationEpoch,
	}
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
	// Retired lists generations that the node must remove locally before it can
	// acknowledge the next crypto epoch. It is intentionally not part of the
	// active observation; the epoch changes whenever this list changes.
	Retired []CryptoGeneration
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
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	normalized, err := normalizeCryptoIdentity(local)
	if err != nil {
		return CryptoIdentity{}, err
	}
	local = normalized
	for attempt := 0; attempt < 3; attempt++ {
		shared, retry, err := s.synchronizeCryptoOnce(ctx, local)
		if err == nil {
			s.cryptoObserved.Store(observationFor(shared))
			s.cryptoReady.Store(true)
			return shared, nil
		}
		if !retry || ctx.Err() != nil {
			return CryptoIdentity{}, err
		}
		if attempt+1 < maxTransactionAttempts {
			if waitErr := waitTransactionRetry(ctx, attempt); waitErr != nil {
				return CryptoIdentity{}, waitErr
			}
		}
	}
	return CryptoIdentity{}, errors.New("statepg: crypto identity remained conflicted after retries")
}

// CryptoReady verifies that the node is still observing the same shared
// crypto generation epoch it acknowledged at startup or reconciliation. A
// live activation elsewhere must withdraw an unreconciled node from service;
// otherwise it could continue issuing assertions or deriving new verifiers
// under an old cluster generation.
func (s *Store) CryptoReady(ctx context.Context) error {
	if s == nil || s.nodeID == "" {
		return nil
	}
	if !s.cryptoReady.Load() {
		return ErrCryptoIdentityStale
	}
	value := s.cryptoObserved.Load()
	observed, ok := value.(cryptoObservation)
	if !ok {
		return ErrCryptoIdentityStale
	}
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	var current cryptoObservation
	err := s.pool.QueryRow(ctx, `SELECT signer_active_kid, signer_active_fingerprint,
		pepper_active_version, pepper_active_fingerprint, pseudonym_version,
		pseudonym_active_fingerprint, generation_epoch
		FROM gripline_cluster_crypto WHERE singleton=TRUE`).Scan(
		&current.signerKID, &current.signerFingerprint,
		&current.pepperVersion, &current.pepperFingerprint,
		&current.pseudonymVersion, &current.pseudonymFingerprint, &current.epoch)
	if err != nil {
		return mapDBError(err)
	}
	if current != observed {
		s.cryptoReady.Store(false)
		return fmt.Errorf("%w: observed epoch %d, authority epoch %d", ErrCryptoIdentityStale, observed.epoch, current.epoch)
	}
	return nil
}

// LoadCryptoIdentity returns the authority-selected active generations. It is
// intentionally separate from ClusterStatus so the runtime reconciler gets a
// typed authority value rather than parsing an operator diagnostic response.
func (s *Store) LoadCryptoIdentity(ctx context.Context) (CryptoIdentity, error) {
	if s == nil || s.pool == nil {
		return CryptoIdentity{}, errors.New("statepg: authority is unavailable")
	}
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	var shared CryptoIdentity
	err := s.pool.QueryRow(ctx, `SELECT signer_active_kid, signer_fingerprint, signer_active_fingerprint,
		pepper_active_version, pepper_fingerprint, pepper_active_fingerprint, pseudonym_version,
		pseudonym_fingerprint, pseudonym_active_fingerprint, generation_epoch
		FROM gripline_cluster_crypto WHERE singleton=TRUE`).Scan(
		&shared.SignerActiveKID, &shared.SignerFingerprint, &shared.SignerActiveFingerprint,
		&shared.PepperActiveVersion, &shared.PepperFingerprint, &shared.PepperActiveFingerprint,
		&shared.PseudonymVersion, &shared.PseudonymFingerprint, &shared.PseudonymActiveFingerprint,
		&shared.GenerationEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return CryptoIdentity{}, errors.New("statepg: cluster crypto identity is not initialized")
	}
	if err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	if shared.SignerActiveFingerprint == "" {
		shared.SignerActiveFingerprint = shared.SignerFingerprint
	}
	if shared.PepperActiveFingerprint == "" {
		shared.PepperActiveFingerprint = shared.PepperFingerprint
	}
	if shared.PseudonymActiveFingerprint == "" {
		shared.PseudonymActiveFingerprint = shared.PseudonymFingerprint
	}
	if shared.GenerationEpoch == 0 {
		return CryptoIdentity{}, errors.New("statepg: invalid cluster crypto generation epoch")
	}
	rows, err := s.pool.Query(ctx, `SELECT kind, generation, fingerprint FROM gripline_cluster_crypto_generations
		WHERE state='retired' ORDER BY kind, generation`)
	if err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var generation CryptoGeneration
		if err := rows.Scan(&generation.Kind, &generation.Generation, &generation.Fingerprint); err != nil {
			return CryptoIdentity{}, mapDBError(err)
		}
		shared.Retired = append(shared.Retired, generation)
	}
	if err := rows.Err(); err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	return shared, nil
}

// StartCryptoWatcher periodically checks the shared generation epoch so a
// node is fenced even when no load balancer readiness probe happens to run.
// The returned stop function is idempotent and must be joined before the
// authority pool closes.
func (s *Store) StartCryptoWatcher(parent context.Context, interval, operationTimeout time.Duration) func() {
	if s == nil || s.nodeID == "" {
		return func() {}
	}
	if interval <= 0 {
		interval = time.Second
	}
	if operationTimeout <= 0 {
		operationTimeout = 2 * time.Second
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checkCtx, checkCancel := context.WithTimeout(ctx, operationTimeout)
				_ = s.CryptoReady(checkCtx)
				checkCancel()
			case <-ctx.Done():
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// StartCryptoReconciler periodically detects an authority generation change
// and gives the runtime a chance to apply the exact locally-loaded generation
// before acknowledging it. The callback must leave the node unready on error;
// SynchronizeCrypto is the final acknowledgement and readiness transition.
func (s *Store) StartCryptoReconciler(parent context.Context, interval, operationTimeout time.Duration, reconcile func(context.Context, CryptoIdentity) error) func() {
	if s == nil || s.nodeID == "" || reconcile == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = time.Second
	}
	if operationTimeout <= 0 {
		operationTimeout = 2 * time.Second
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checkCtx, checkCancel := context.WithTimeout(ctx, operationTimeout)
				stale := !s.cryptoReady.Load()
				if !stale {
					stale = errors.Is(s.CryptoReady(checkCtx), ErrCryptoIdentityStale)
				}
				if stale {
					if shared, err := s.LoadCryptoIdentity(checkCtx); err == nil {
						_ = reconcile(checkCtx, shared)
					}
				}
				checkCancel()
			case <-ctx.Done():
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// ActivateCryptoGeneration atomically advances one shared active generation.
// Every live membership epoch must have acknowledged the exact target
// fingerprint before the active singleton is changed. The operation claim
// and operator audit are committed in the same transaction as the activation.
// This is the authority-side half of rotation; callers must separately prove
// that their signer/verifier or secret-ring implementation can apply the
// returned generation before serving it.
func (s *Store) ActivateCryptoGeneration(ctx context.Context, req CryptoActivationRequest) (CryptoIdentity, error) {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := validateCryptoActivationRequest(req); err != nil {
		return CryptoIdentity{}, err
	}
	returnCrypto := CryptoIdentity{}
	err := s.withTransactionRetry(ctx, "crypto generation activation", func() error {
		var err error
		returnCrypto, err = s.activateCryptoGenerationOnce(ctx, req)
		return err
	})
	if err != nil {
		return CryptoIdentity{}, err
	}
	return returnCrypto, nil
}

// RetireCryptoGeneration durably removes one non-active generation from the
// cluster capability set. The caller must have already waited until no
// assertion signed by a signer generation can still be live and, for secret
// generations, until the corresponding migration/scope safety condition is
// satisfied. Exact operation retries return the original shared result.
func (s *Store) RetireCryptoGeneration(ctx context.Context, req CryptoRetirementRequest) (CryptoIdentity, error) {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := validateCryptoRetirementRequest(req); err != nil {
		return CryptoIdentity{}, err
	}
	var returnCrypto CryptoIdentity
	err := s.withTransactionRetry(ctx, "crypto generation retirement", func() error {
		var err error
		returnCrypto, err = s.retireCryptoGenerationOnce(ctx, req)
		return err
	})
	if err != nil {
		return CryptoIdentity{}, err
	}
	return returnCrypto, nil
}

func validateCryptoActivationRequest(req CryptoActivationRequest) error {
	if req.Kind != CryptoKindSigner && req.Kind != CryptoKindPepper && req.Kind != CryptoKindPseudonym {
		return fmt.Errorf("statepg: unknown crypto activation kind %q", req.Kind)
	}
	if req.Generation < 1 || strings.TrimSpace(req.Fingerprint) == "" {
		return errors.New("statepg: crypto activation requires a positive generation and fingerprint")
	}
	if strings.TrimSpace(req.OperationID) == "" {
		return control.ErrOperationIDRequired
	}
	if strings.TrimSpace(req.Actor) == "" {
		return errors.New("statepg: crypto activation actor required")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return control.ErrReasonRequired
	}
	return nil
}

func validateCryptoRetirementRequest(req CryptoRetirementRequest) error {
	if req.Kind != CryptoKindSigner && req.Kind != CryptoKindPepper && req.Kind != CryptoKindPseudonym {
		return fmt.Errorf("statepg: unknown crypto retirement kind %q", req.Kind)
	}
	if req.Generation < 1 || strings.TrimSpace(req.Fingerprint) == "" {
		return errors.New("statepg: crypto retirement requires a positive generation and fingerprint")
	}
	if strings.TrimSpace(req.OperationID) == "" {
		return control.ErrOperationIDRequired
	}
	if strings.TrimSpace(req.Actor) == "" {
		return errors.New("statepg: crypto retirement actor required")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return control.ErrReasonRequired
	}
	return nil
}

func (s *Store) activateCryptoGenerationOnce(ctx context.Context, req CryptoActivationRequest) (CryptoIdentity, error) {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	// An activation retry may arrive after this node has observed the committed
	// epoch and withdrawn itself from readiness. Validate the fenced instance,
	// but defer the crypto-ready check until after the durable operation claim so
	// an exact replay can return the original authority result and let the
	// runtime reconcile locally.
	if err := s.requireNodeMembership(ctx, tx, false, false); err != nil {
		return CryptoIdentity{}, err
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return CryptoIdentity{}, err
	}
	replayed, err := claimControlOperation(ctx, tx, req.OperationID, "crypto.activate",
		struct {
			Kind        string `json:"kind"`
			Generation  int    `json:"generation"`
			Fingerprint string `json:"fingerprint"`
			Actor       string `json:"actor"`
			Reason      string `json:"reason"`
		}{req.Kind, req.Generation, req.Fingerprint, req.Actor, req.Reason}, now)
	if err != nil {
		return CryptoIdentity{}, err
	}
	shared, err := lockCryptoIdentity(ctx, tx)
	if err != nil {
		return CryptoIdentity{}, err
	}
	if replayed {
		if err := mapDBError(tx.Commit(ctx)); err != nil {
			return CryptoIdentity{}, err
		}
		return shared, nil
	}
	if !s.cryptoReady.Load() {
		return CryptoIdentity{}, ErrCryptoIdentityStale
	}

	var storedFingerprint, state string
	err = tx.QueryRow(ctx, `SELECT fingerprint, state FROM gripline_cluster_crypto_generations
		WHERE kind=$1 AND generation=$2 FOR UPDATE`, req.Kind, req.Generation).Scan(&storedFingerprint, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return CryptoIdentity{}, fmt.Errorf("statepg: crypto generation %s/%d is not loaded", req.Kind, req.Generation)
	}
	if err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	if storedFingerprint != req.Fingerprint {
		return CryptoIdentity{}, fmt.Errorf("statepg: crypto generation %s/%d fingerprint mismatch", req.Kind, req.Generation)
	}
	if state == "retired" {
		return CryptoIdentity{}, fmt.Errorf("statepg: crypto generation %s/%d is retired", req.Kind, req.Generation)
	}
	if err := requireCryptoActivationBarrier(ctx, tx, s.leaseTTL, req); err != nil {
		return CryptoIdentity{}, err
	}
	if shared.GenerationEpoch == ^uint64(0) || shared.GenerationEpoch >= uint64(1<<63-1) {
		return CryptoIdentity{}, errors.New("statepg: crypto generation epoch exhausted")
	}
	newEpoch := shared.GenerationEpoch + 1
	active := shared
	active.GenerationEpoch = newEpoch
	switch req.Kind {
	case CryptoKindSigner:
		active.SignerActiveKID = req.Generation
		active.SignerActiveFingerprint = req.Fingerprint
	case CryptoKindPepper:
		active.PepperActiveVersion = req.Generation
		active.PepperActiveFingerprint = req.Fingerprint
	case CryptoKindPseudonym:
		active.PseudonymVersion = req.Generation
		active.PseudonymActiveFingerprint = req.Fingerprint
	}
	if _, err := tx.Exec(ctx, `UPDATE gripline_cluster_crypto SET
		signer_active_kid=$1, signer_active_fingerprint=$2,
		pepper_active_version=$3, pepper_active_fingerprint=$4,
		pseudonym_version=$5, pseudonym_active_fingerprint=$6,
		generation_epoch=$7, updated_at=$8 WHERE singleton=TRUE`,
		active.SignerActiveKID, active.SignerActiveFingerprint,
		active.PepperActiveVersion, active.PepperActiveFingerprint,
		active.PseudonymVersion, active.PseudonymActiveFingerprint,
		postgresEpoch(newEpoch), now); err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	previousGeneration := cryptoActiveGeneration(shared, req.Kind)
	if previousGeneration > 0 && previousGeneration != req.Generation {
		retireAfter := now
		if req.Kind == CryptoKindSigner {
			retireAfter = now.Add(cryptoSignerRetirementHorizon)
		}
		if _, err := tx.Exec(ctx, `UPDATE gripline_cluster_crypto_generations
			SET state='loaded', superseded_at=$1, retire_after=$2, updated_at=$1
			WHERE kind=$3 AND generation=$4 AND state='active'`, now, retireAfter, req.Kind, previousGeneration); err != nil {
			return CryptoIdentity{}, mapDBError(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE gripline_cluster_crypto_generations
		SET state=CASE WHEN generation=$1 THEN 'active' ELSE state END,
			activated_at=CASE WHEN generation=$1 THEN COALESCE(activated_at, $2) ELSE activated_at END,
			superseded_at=CASE WHEN generation=$1 THEN NULL ELSE superseded_at END,
			retire_after=CASE WHEN generation=$1 THEN NULL ELSE retire_after END,
			updated_at=$2 WHERE kind=$3`, req.Generation, now, req.Kind); err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	posture, err := loadPostureForAudit(ctx, tx)
	if err != nil {
		return CryptoIdentity{}, err
	}
	if err := appendOperator(ctx, tx, control.OperatorRecord{
		At: now, Actor: req.Actor, Action: "crypto.activate", Target: fmt.Sprintf("%s/%d", req.Kind, req.Generation),
		Reason: req.Reason, Posture: posture.String(), Committed: true,
	}); err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	if err := mapDBError(tx.Commit(ctx)); err != nil {
		return CryptoIdentity{}, err
	}
	// The authority has advanced before this process has necessarily applied
	// the corresponding local signer/secret-ring generation. Withdraw this
	// instance immediately; the crypto reconciler must re-apply the local
	// generation and call SynchronizeCrypto before it can serve again.
	s.cryptoReady.Store(false)
	return active, nil
}

func (s *Store) retireCryptoGenerationOnce(ctx context.Context, req CryptoRetirementRequest) (CryptoIdentity, error) {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	// As with activation, an exact retry may be needed after this node has
	// withdrawn itself because the shared epoch changed. Fencing still applies;
	// the crypto-ready check is deliberately deferred until after the replay
	// claim has been inspected.
	if err := s.requireNodeMembership(ctx, tx, false, false); err != nil {
		return CryptoIdentity{}, err
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return CryptoIdentity{}, err
	}
	replayed, err := claimControlOperation(ctx, tx, req.OperationID, "crypto.retire",
		struct {
			Kind        string    `json:"kind"`
			Generation  int       `json:"generation"`
			Fingerprint string    `json:"fingerprint"`
			NotBefore   time.Time `json:"not_before"`
			Actor       string    `json:"actor"`
			Reason      string    `json:"reason"`
		}{req.Kind, req.Generation, req.Fingerprint, req.NotBefore.UTC(), req.Actor, req.Reason}, now)
	if err != nil {
		return CryptoIdentity{}, err
	}
	shared, err := lockCryptoIdentity(ctx, tx)
	if err != nil {
		return CryptoIdentity{}, err
	}
	if replayed {
		if err := mapDBError(tx.Commit(ctx)); err != nil {
			return CryptoIdentity{}, err
		}
		return shared, nil
	}
	if !s.cryptoReady.Load() {
		return CryptoIdentity{}, ErrCryptoIdentityStale
	}

	var storedFingerprint, state string
	var authorityRetireAfter *time.Time
	err = tx.QueryRow(ctx, `SELECT fingerprint, state, retire_after FROM gripline_cluster_crypto_generations
		WHERE kind=$1 AND generation=$2 FOR UPDATE`, req.Kind, req.Generation).Scan(&storedFingerprint, &state, &authorityRetireAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return CryptoIdentity{}, fmt.Errorf("statepg: crypto generation %s/%d is not loaded", req.Kind, req.Generation)
	}
	if err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	if storedFingerprint != req.Fingerprint {
		return CryptoIdentity{}, fmt.Errorf("statepg: crypto generation %s/%d fingerprint mismatch", req.Kind, req.Generation)
	}
	if state == "retired" {
		return CryptoIdentity{}, fmt.Errorf("statepg: crypto generation %s/%d is already retired", req.Kind, req.Generation)
	}
	safeAfter := req.NotBefore
	if authorityRetireAfter != nil && authorityRetireAfter.After(safeAfter) {
		safeAfter = *authorityRetireAfter
	}
	if now.Before(safeAfter) {
		return CryptoIdentity{}, fmt.Errorf("statepg: crypto generation %s/%d cannot retire before %s", req.Kind, req.Generation, safeAfter.UTC().Format(time.RFC3339))
	}
	if cryptoGenerationIsActive(shared, req.Kind, req.Generation) {
		return CryptoIdentity{}, fmt.Errorf("statepg: cannot retire active crypto generation %s/%d", req.Kind, req.Generation)
	}
	if err := requireCryptoRetirementSafety(ctx, tx, req); err != nil {
		return CryptoIdentity{}, err
	}
	if shared.GenerationEpoch == ^uint64(0) || shared.GenerationEpoch >= uint64(1<<63-1) {
		return CryptoIdentity{}, errors.New("statepg: crypto generation epoch exhausted")
	}
	newEpoch := shared.GenerationEpoch + 1
	if _, err := tx.Exec(ctx, `UPDATE gripline_cluster_crypto SET generation_epoch=$1, updated_at=$2 WHERE singleton=TRUE`, postgresEpoch(newEpoch), now); err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE gripline_cluster_crypto_generations SET state='retired', updated_at=$1
		WHERE kind=$2 AND generation=$3`, now, req.Kind, req.Generation); err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	posture, err := loadPostureForAudit(ctx, tx)
	if err != nil {
		return CryptoIdentity{}, err
	}
	if err := appendOperator(ctx, tx, control.OperatorRecord{
		At: now, Actor: req.Actor, Action: "crypto.retire", Target: fmt.Sprintf("%s/%d", req.Kind, req.Generation),
		Reason: req.Reason, Posture: posture.String(), Committed: true,
	}); err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	if err := mapDBError(tx.Commit(ctx)); err != nil {
		return CryptoIdentity{}, err
	}
	shared.GenerationEpoch = newEpoch
	shared.Retired = append(shared.Retired, CryptoGeneration{Kind: req.Kind, Generation: req.Generation, Fingerprint: req.Fingerprint})
	// Active fields did not change, but the accepted key/capability set did;
	// every node must re-read and reconcile before it acknowledges this epoch.
	s.cryptoReady.Store(false)
	return shared, nil
}

func cryptoGenerationIsActive(identity CryptoIdentity, kind string, generation int) bool {
	switch kind {
	case CryptoKindSigner:
		return identity.SignerActiveKID == generation
	case CryptoKindPepper:
		return identity.PepperActiveVersion == generation
	case CryptoKindPseudonym:
		return identity.PseudonymVersion == generation
	default:
		return false
	}
}

func cryptoActiveGeneration(identity CryptoIdentity, kind string) int {
	switch kind {
	case CryptoKindSigner:
		return identity.SignerActiveKID
	case CryptoKindPepper:
		return identity.PepperActiveVersion
	case CryptoKindPseudonym:
		return identity.PseudonymVersion
	default:
		return 0
	}
}

func requireCryptoRetirementSafety(ctx context.Context, tx pgx.Tx, req CryptoRetirementRequest) error {
	switch req.Kind {
	case CryptoKindPepper:
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_credentials WHERE pepper_version=$1`, req.Generation).Scan(&count); err != nil {
			return mapDBError(err)
		}
		if count != 0 {
			return fmt.Errorf("statepg: pepper generation %d is still used by %d credential(s)", req.Generation, count)
		}
	case CryptoKindPseudonym:
		var count int
		prefix := fmt.Sprintf("v%d.", req.Generation)
		if err := tx.QueryRow(ctx, `WITH referenced_sources(source_id) AS (
			SELECT alias FROM gripline_source_aliases WHERE generation=$1
			UNION SELECT scope_id FROM gripline_resource_source_scopes WHERE scope_id LIKE $2
			UNION SELECT subject_id FROM gripline_evidence WHERE scope='SOURCE' AND subject_id LIKE $2
			UNION SELECT subject_id FROM gripline_evidence_guards WHERE scope='SOURCE' AND subject_id LIKE $2
			UNION SELECT subject FROM gripline_adaptive_window_subjects WHERE subject LIKE $2
			UNION SELECT subject FROM gripline_adaptive_baselines WHERE subject LIKE $2
		), unresolved(source_id) AS (
			SELECT DISTINCT r.source_id
			FROM referenced_sources r
			WHERE NOT EXISTS (
				SELECT 1 FROM gripline_source_aliases old
				WHERE old.alias=r.source_id AND old.generation=$1
			)
			OR NOT EXISTS (
				SELECT 1
				FROM gripline_source_aliases old
				JOIN gripline_source_aliases retained
				  ON retained.canonical_source_id=old.canonical_source_id
				 AND retained.generation<>$1
				WHERE old.alias=r.source_id AND old.generation=$1
			)
		)
		SELECT COUNT(*) FROM unresolved`, req.Generation, prefix+"%").Scan(&count); err != nil {
			return mapDBError(err)
		}
		if count != 0 {
			return fmt.Errorf("statepg: pseudonym generation %d still has %d source state reference(s); migrate aliases before retirement", req.Generation, count)
		}
	}
	return nil
}

func lockCryptoIdentity(ctx context.Context, tx pgx.Tx) (CryptoIdentity, error) {
	var shared CryptoIdentity
	err := tx.QueryRow(ctx, `SELECT signer_active_kid, signer_fingerprint, signer_active_fingerprint,
		pepper_active_version, pepper_fingerprint, pepper_active_fingerprint, pseudonym_version,
		pseudonym_fingerprint, pseudonym_active_fingerprint, generation_epoch
		FROM gripline_cluster_crypto WHERE singleton=TRUE FOR UPDATE`).Scan(
		&shared.SignerActiveKID, &shared.SignerFingerprint, &shared.SignerActiveFingerprint,
		&shared.PepperActiveVersion, &shared.PepperFingerprint, &shared.PepperActiveFingerprint,
		&shared.PseudonymVersion, &shared.PseudonymFingerprint, &shared.PseudonymActiveFingerprint,
		&shared.GenerationEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return CryptoIdentity{}, errors.New("statepg: cluster crypto identity is not initialized")
	}
	if err != nil {
		return CryptoIdentity{}, mapDBError(err)
	}
	if shared.GenerationEpoch < 1 {
		return CryptoIdentity{}, errors.New("statepg: invalid cluster crypto generation epoch")
	}
	retired, err := loadRetiredCryptoGenerations(ctx, tx)
	if err != nil {
		return CryptoIdentity{}, err
	}
	shared.Retired = retired
	return shared, nil
}

func loadRetiredCryptoGenerations(ctx context.Context, tx pgx.Tx) ([]CryptoGeneration, error) {
	rows, err := tx.Query(ctx, `SELECT kind, generation, fingerprint FROM gripline_cluster_crypto_generations
		WHERE state='retired' ORDER BY kind, generation`)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	var retired []CryptoGeneration
	for rows.Next() {
		var generation CryptoGeneration
		if err := rows.Scan(&generation.Kind, &generation.Generation, &generation.Fingerprint); err != nil {
			return nil, mapDBError(err)
		}
		retired = append(retired, generation)
	}
	return retired, mapDBError(rows.Err())
}

func requireCryptoActivationBarrier(ctx context.Context, tx pgx.Tx, leaseTTL time.Duration, req CryptoActivationRequest) error {
	var lagging int
	err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_membership m
		LEFT JOIN gripline_cluster_crypto_acks a
			ON a.node_id=m.node_id AND a.node_epoch=m.node_epoch
			AND a.kind=$1 AND a.generation=$2 AND a.fingerprint=$3
		WHERE m.state IN ('ready','draining')
		  AND m.last_seen_at > CURRENT_TIMESTAMP - ($4::double precision * interval '1 second')
		  AND a.node_id IS NULL`, req.Kind, req.Generation, req.Fingerprint, leaseTTL.Seconds()).Scan(&lagging)
	if err != nil {
		return mapDBError(err)
	}
	if lagging != 0 {
		return fmt.Errorf("%w: %d live node(s) have not acknowledged %s/%d", ErrCryptoActivationBarrier, lagging, req.Kind, req.Generation)
	}
	return nil
}

func loadPostureForAudit(ctx context.Context, tx pgx.Tx) (control.Posture, error) {
	var raw int
	err := tx.QueryRow(ctx, `SELECT COALESCE(posture,0) FROM gripline_operator_posture WHERE singleton=TRUE`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return control.Normal, nil
	}
	if err != nil {
		return control.Normal, mapDBError(err)
	}
	if raw < int(control.Normal) || raw > int(control.EmergencyLockdown) {
		return control.Normal, fmt.Errorf("statepg: unknown persisted posture %d", raw)
	}
	return control.Posture(raw), nil
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
		// The signer is different from the derivation rings: a node whose
		// local signer is already active on another KID could issue assertions
		// before the backend verifier and cluster authority have accepted that
		// generation. Signer activation therefore remains an explicit startup
		// agreement. Pepper and pseudonym rings, by contrast, can safely load a
		// future generation and select the shared active one immediately after
		// synchronization, before the node is exposed to traffic.
		return CryptoIdentity{}, false, fmt.Errorf("statepg: local active signer generation %d differs from shared signer=%d",
			local.SignerActiveKID, shared.SignerActiveKID)
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
				(kind, generation, fingerprint, state, activated_at, updated_at) VALUES ($1,$2,$3,$4,CASE WHEN $4='active' THEN CURRENT_TIMESTAMP ELSE NULL END,CURRENT_TIMESTAMP)`, generation.Kind, generation.Generation, generation.Fingerprint, state); err != nil {
				return mapDBError(err)
			}
		} else if err != nil {
			return mapDBError(err)
		} else if storedFingerprint != generation.Fingerprint {
			return fmt.Errorf("statepg: crypto generation mismatch: %s/%d shared fingerprint differs", generation.Kind, generation.Generation)
		} else if state == "retired" {
			return fmt.Errorf("statepg: crypto generation %s/%d is retired", generation.Kind, generation.Generation)
		} else if active && state != "active" {
			if _, err := tx.Exec(ctx, `UPDATE gripline_cluster_crypto_generations SET state='active', activated_at=COALESCE(activated_at, CURRENT_TIMESTAMP), superseded_at=NULL, retire_after=NULL, updated_at=CURRENT_TIMESTAMP WHERE kind=$1 AND generation=$2`, generation.Kind, generation.Generation); err != nil {
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
