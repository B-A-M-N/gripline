package statepg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/jackc/pgx/v5"
)

var (
	ErrClusterBehaviorDigestMismatch     = errors.New("statepg: cluster behavior digest does not match expected authority")
	ErrClusterBehaviorNotInitialized     = errors.New("statepg: cluster behavior authority is not initialized")
	ErrClusterBehaviorRequiresQuiescence = errors.New("statepg: cluster behavior update requires a quiescent authority")
)

// ClusterBehaviorConfig contains only settings whose values change the
// meaning of shared authority decisions. Per-node pool, timeout, batching,
// and scheduler tuning deliberately do not belong here.
type ClusterBehaviorConfig struct {
	LeaseTTL                    time.Duration `json:"lease_ttl_ns"`
	RenewEvery                  time.Duration `json:"renew_every_ns"`
	MaxSourceScopes             int           `json:"max_source_scopes"`
	SourceScopeIdle             time.Duration `json:"source_scope_idle_ns"`
	MaxSourceAliasIdentities    int           `json:"max_source_alias_identities"`
	EvidenceGrace               time.Duration `json:"evidence_grace_ns"`
	ReleasedLeaseRetention      time.Duration `json:"released_lease_retention_ns"`
	CredentialReceiptRetention  time.Duration `json:"credential_receipt_retention_ns"`
	ControlOperationRetention   time.Duration `json:"control_operation_retention_ns"`
	AdmissionAuditRetention     time.Duration `json:"admission_audit_retention_ns"`
	SecurityTransitionRetention time.Duration `json:"security_transition_retention_ns"`
	OperatorAuditRetention      time.Duration `json:"operator_audit_retention_ns"`
	PolicyAuditRetention        time.Duration `json:"policy_audit_retention_ns"`
	MembershipRetention         time.Duration `json:"membership_retention_ns"`
	AdaptiveRetention           time.Duration `json:"adaptive_retention_ns"`
	EvidenceGuardRetention      time.Duration `json:"evidence_guard_retention_ns"`
	LaneOperatorAuditRetention  time.Duration `json:"lane_operator_audit_retention_ns"`
	PolicyNodeStateRetention    time.Duration `json:"policy_node_state_retention_ns"`
	ClusterCryptoAckRetention   time.Duration `json:"cluster_crypto_ack_retention_ns"`
	SourceAliasRetention        time.Duration `json:"source_alias_retention_ns"`
}

// normalize applies the same conservative defaults used by Store.Open. This
// keeps direct statepg users and config-driven runtime users on one digest.
func (c ClusterBehaviorConfig) normalize() ClusterBehaviorConfig {
	if c.LeaseTTL <= 0 {
		c.LeaseTTL = 30 * time.Second
	}
	if c.RenewEvery <= 0 || c.RenewEvery >= c.LeaseTTL/2 {
		c.RenewEvery = c.LeaseTTL / 3
	}
	if c.MaxSourceScopes <= 0 {
		c.MaxSourceScopes = 4096
	}
	if c.SourceScopeIdle <= 0 {
		c.SourceScopeIdle = 10 * time.Minute
	}
	if c.MaxSourceAliasIdentities <= 0 {
		c.MaxSourceAliasIdentities = defaultMaxSourceAliasIdentities
	}
	m := (MaintenanceOptions{
		EvidenceGrace: c.EvidenceGrace, ReleasedLeaseRetention: c.ReleasedLeaseRetention,
		CredentialReceiptRetention: c.CredentialReceiptRetention, ControlOperationRetention: c.ControlOperationRetention,
		AdmissionAuditRetention: c.AdmissionAuditRetention, SecurityTransitionRetention: c.SecurityTransitionRetention,
		OperatorAuditRetention: c.OperatorAuditRetention, PolicyAuditRetention: c.PolicyAuditRetention,
		MembershipRetention: c.MembershipRetention, AdaptiveRetention: c.AdaptiveRetention,
		EvidenceGuardRetention: c.EvidenceGuardRetention, LaneOperatorAuditRetention: c.LaneOperatorAuditRetention,
		PolicyNodeStateRetention: c.PolicyNodeStateRetention, ClusterCryptoAckRetention: c.ClusterCryptoAckRetention,
		SourceAliasRetention: c.SourceAliasRetention,
	}).withDefaults()
	c.EvidenceGrace, c.ReleasedLeaseRetention = m.EvidenceGrace, m.ReleasedLeaseRetention
	c.CredentialReceiptRetention, c.ControlOperationRetention = m.CredentialReceiptRetention, m.ControlOperationRetention
	c.AdmissionAuditRetention, c.SecurityTransitionRetention = m.AdmissionAuditRetention, m.SecurityTransitionRetention
	c.OperatorAuditRetention, c.PolicyAuditRetention = m.OperatorAuditRetention, m.PolicyAuditRetention
	c.MembershipRetention, c.AdaptiveRetention = m.MembershipRetention, m.AdaptiveRetention
	c.EvidenceGuardRetention, c.LaneOperatorAuditRetention = m.EvidenceGuardRetention, m.LaneOperatorAuditRetention
	c.PolicyNodeStateRetention, c.ClusterCryptoAckRetention = m.PolicyNodeStateRetention, m.ClusterCryptoAckRetention
	c.SourceAliasRetention = m.SourceAliasRetention
	return c
}

// CanonicalJSON returns the deterministic representation committed to the
// authority. Struct field order is intentional; maps are not used.
func (c ClusterBehaviorConfig) CanonicalJSON() ([]byte, error) {
	return json.Marshal(c.normalize())
}

// Digest returns the SHA-256 digest of CanonicalJSON.
func (c ClusterBehaviorConfig) Digest() (string, error) {
	b, err := c.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ClusterBehaviorStatus reports the local and authority digests without
// exposing the canonical policy-like configuration itself.
type ClusterBehaviorStatus struct {
	AuthoritativeDigest string `json:"authoritative_digest,omitempty"`
	LocalDigest         string `json:"local_digest,omitempty"`
	Match               bool   `json:"match"`
	Mismatch            bool   `json:"mismatch"`
}

// ClusterBehaviorChange is one non-secret semantic setting that differs
// between the configured desired contract and the authoritative contract.
type ClusterBehaviorChange struct {
	Field   string `json:"field"`
	Current any    `json:"current,omitempty"`
	Desired any    `json:"desired"`
}

// ClusterBehaviorPlan is the read-only result used by the offline plan and
// apply lifecycle. Canonical values are included so operators can review the
// exact non-secret contract represented by each digest.
type ClusterBehaviorPlan struct {
	Initialized   bool                    `json:"initialized"`
	CurrentDigest string                  `json:"current_digest"`
	DesiredDigest string                  `json:"desired_digest"`
	Current       map[string]any          `json:"current,omitempty"`
	Desired       map[string]any          `json:"desired"`
	Changes       []ClusterBehaviorChange `json:"changes,omitempty"`
}

func (s *Store) ensureClusterBehavior(ctx context.Context) error {
	canonical, err := s.clusterBehavior.CanonicalJSON()
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_cluster_behavior
		(singleton, digest, canonical, updated_at) VALUES (TRUE, $1, $2::jsonb, CURRENT_TIMESTAMP)
		ON CONFLICT (singleton) DO NOTHING`, s.behaviorDigest, string(canonical)); err != nil {
		return fmt.Errorf("statepg: seed cluster behavior: %w", mapDBError(err))
	}
	var authoritative string
	if err := tx.QueryRow(ctx, `SELECT digest FROM gripline_cluster_behavior WHERE singleton=TRUE`).Scan(&authoritative); err != nil {
		return fmt.Errorf("statepg: read cluster behavior: %w", mapDBError(err))
	}
	if authoritative != s.behaviorDigest {
		s.behaviorMismatch.Store(true)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapDBError(err)
	}
	return nil
}

// behaviorLeaseTTL decodes the lease portion of an authoritative canonical
// contract. A missing field is treated like a pre-behavior authority and uses
// the caller's configured fallback rather than inventing a new authority.
func behaviorLeaseTTL(canonical []byte, fallback time.Duration) (time.Duration, error) {
	var behavior ClusterBehaviorConfig
	if err := json.Unmarshal(canonical, &behavior); err != nil {
		return 0, fmt.Errorf("statepg: decode authoritative cluster behavior: %w", err)
	}
	if behavior.LeaseTTL <= 0 {
		return fallback, nil
	}
	return behavior.LeaseTTL, nil
}

func behaviorValues(canonical []byte) (map[string]any, error) {
	values := make(map[string]any)
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&values); err != nil {
		return nil, fmt.Errorf("statepg: decode canonical cluster behavior: %w", err)
	}
	return values, nil
}

func loadClusterBehavior(ctx context.Context, tx pgx.Tx, forUpdate bool) (digest string, canonical []byte, initialized bool, err error) {
	query := `SELECT digest, canonical FROM gripline_cluster_behavior WHERE singleton=TRUE`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err = tx.QueryRow(ctx, query).Scan(&digest, &canonical)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, mapDBError(err)
	}
	return digest, canonical, true, nil
}

func makeClusterBehaviorPlan(currentDigest string, currentCanonical []byte, initialized bool, desired ClusterBehaviorConfig) (ClusterBehaviorPlan, error) {
	desiredCanonical, err := desired.CanonicalJSON()
	if err != nil {
		return ClusterBehaviorPlan{}, err
	}
	desiredDigest, err := desired.Digest()
	if err != nil {
		return ClusterBehaviorPlan{}, err
	}
	desiredValues, err := behaviorValues(desiredCanonical)
	if err != nil {
		return ClusterBehaviorPlan{}, err
	}
	plan := ClusterBehaviorPlan{
		Initialized: initialized, CurrentDigest: currentDigest, DesiredDigest: desiredDigest,
		Desired: desiredValues,
	}
	if !initialized {
		return plan, nil
	}
	currentValues, err := behaviorValues(currentCanonical)
	if err != nil {
		return ClusterBehaviorPlan{}, err
	}
	plan.Current = currentValues
	keys := make(map[string]struct{}, len(currentValues)+len(desiredValues))
	for key := range currentValues {
		keys[key] = struct{}{}
	}
	for key := range desiredValues {
		keys[key] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		current, currentOK := currentValues[key]
		desired, desiredOK := desiredValues[key]
		if currentOK && desiredOK && reflect.DeepEqual(current, desired) {
			continue
		}
		change := ClusterBehaviorChange{Field: key, Desired: desired}
		if currentOK {
			change.Current = current
		}
		plan.Changes = append(plan.Changes, change)
	}
	return plan, nil
}

// PlanClusterBehavior compares the configured desired contract with the
// singleton authority without registering a membership lease or mutating the
// database.
func (s *Store) PlanClusterBehavior(ctx context.Context, desired ClusterBehaviorConfig) (ClusterBehaviorPlan, error) {
	var plan ClusterBehaviorPlan
	if s == nil || s.pool == nil {
		return plan, errors.New("statepg: authority is unavailable")
	}
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return plan, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	digest, canonical, initialized, err := loadClusterBehavior(ctx, tx, false)
	if err != nil {
		return plan, err
	}
	plan, err = makeClusterBehaviorPlan(digest, canonical, initialized, desired)
	if err != nil {
		return plan, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterBehaviorPlan{}, mapDBError(err)
	}
	return plan, nil
}

// ApplyClusterBehavior performs an explicit offline behavior transition. It
// serializes with schema migration, checks the old authority's lease horizon,
// rejects live memberships and active resource leases, then updates the
// singleton with a compare-and-swap and durable audit record in one
// transaction. The expected digest may be "none" for first initialization.
func (s *Store) ApplyClusterBehavior(ctx context.Context, desired ClusterBehaviorConfig, expectedDigest, actor, reason string) (ClusterBehaviorPlan, error) {
	var plan ClusterBehaviorPlan
	if s == nil || s.pool == nil {
		return plan, errors.New("statepg: authority is unavailable")
	}
	if strings.TrimSpace(reason) == "" {
		return plan, errors.New("statepg: cluster behavior update reason is required")
	}
	if strings.TrimSpace(actor) == "" {
		actor = "operator"
	}
	expectedDigest = strings.TrimSpace(expectedDigest)
	if expectedDigest == "" {
		return plan, errors.New("statepg: cluster behavior expected current digest is required")
	}
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return plan, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('gripline-authority-schema'))`); err != nil {
		return plan, mapDBError(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('gripline-authority-cluster-behavior'))`); err != nil {
		return plan, mapDBError(err)
	}
	currentDigest, currentCanonical, initialized, err := loadClusterBehavior(ctx, tx, true)
	if err != nil {
		return plan, err
	}
	authoritativeDigest := currentDigest
	if !initialized {
		authoritativeDigest = "none"
	}
	if authoritativeDigest != expectedDigest {
		return plan, fmt.Errorf("%w: expected %q, found %q", ErrClusterBehaviorDigestMismatch, expectedDigest, authoritativeDigest)
	}
	leaseTTL := s.leaseTTL
	if initialized {
		leaseTTL, err = behaviorLeaseTTL(currentCanonical, leaseTTL)
		if err != nil {
			return plan, err
		}
	}
	if err := requireMigrationQuiescence(ctx, tx, leaseTTL); err != nil {
		return plan, fmt.Errorf("%w: %w", ErrClusterBehaviorRequiresQuiescence, err)
	}
	if err := requireNoLiveAuthorityLeases(ctx, tx); err != nil {
		return plan, err
	}
	plan, err = makeClusterBehaviorPlan(currentDigest, currentCanonical, initialized, desired)
	if err != nil {
		return plan, err
	}
	desiredCanonical, err := desired.CanonicalJSON()
	if err != nil {
		return plan, err
	}
	detail, err := json.Marshal(map[string]any{
		"before_digest": authoritativeDigest,
		"after_digest":  plan.DesiredDigest,
		"changes":       plan.Changes,
	})
	if err != nil {
		return plan, fmt.Errorf("statepg: encode cluster behavior audit: %w", err)
	}
	committed := authoritativeDigest != plan.DesiredDigest
	if committed {
		if initialized {
			result, execErr := tx.Exec(ctx, `UPDATE gripline_cluster_behavior
				SET digest=$1, canonical=$2::jsonb, updated_at=CURRENT_TIMESTAMP
				WHERE singleton=TRUE AND digest=$3`, plan.DesiredDigest, string(desiredCanonical), expectedDigest)
			if execErr != nil {
				return plan, mapDBError(execErr)
			}
			if result.RowsAffected() != 1 {
				return plan, fmt.Errorf("%w: authority changed during update", ErrClusterBehaviorDigestMismatch)
			}
		} else {
			result, execErr := tx.Exec(ctx, `INSERT INTO gripline_cluster_behavior
				(singleton, digest, canonical, updated_at) VALUES (TRUE,$1,$2::jsonb,CURRENT_TIMESTAMP)
				ON CONFLICT (singleton) DO NOTHING`, plan.DesiredDigest, string(desiredCanonical))
			if execErr != nil {
				return plan, mapDBError(execErr)
			}
			if result.RowsAffected() != 1 {
				return plan, fmt.Errorf("%w: authority was initialized concurrently", ErrClusterBehaviorDigestMismatch)
			}
		}
	}
	authorityNow, err := dbNow(ctx, tx)
	if err != nil {
		return plan, err
	}
	if err := appendOperator(ctx, tx, control.OperatorRecord{
		At: authorityNow, Actor: actor, Action: "cluster.behavior.apply", Target: "cluster-behavior",
		Reason: reason, Posture: "NORMAL", Committed: committed, Detail: string(detail),
	}); err != nil {
		return plan, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ClusterBehaviorPlan{}, mapDBError(err)
	}
	return plan, nil
}

func (s *Store) clusterBehaviorStatus(ctx context.Context, tx pgx.Tx) (ClusterBehaviorStatus, error) {
	status := ClusterBehaviorStatus{LocalDigest: s.behaviorDigest}
	err := tx.QueryRow(ctx, `SELECT digest FROM gripline_cluster_behavior WHERE singleton=TRUE`).Scan(&status.AuthoritativeDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		return status, mapDBError(err)
	}
	status.Match = status.AuthoritativeDigest == status.LocalDigest
	status.Mismatch = !status.Match
	if status.Mismatch {
		s.behaviorMismatch.Store(true)
	}
	return status, nil
}
