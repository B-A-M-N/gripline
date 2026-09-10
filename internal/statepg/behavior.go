package statepg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
