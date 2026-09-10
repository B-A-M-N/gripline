package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/authority"
	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/statepg"
)

// runtimeAuthoritySet is the backend-specific half of the composition root.
// It owns construction and shutdown registration for exactly one authority;
// request routing and control-plane wiring stay in runtime.go.
type runtimeAuthoritySet struct {
	registry      credential.Registry
	lanes         lane.Repository
	evidence      evidence.Store
	state         *statebolt.Store
	postgres      *statepg.Store
	stateHealth   StateHealth
	adminState    adminStateAuthority
	adaptiveState adaptiveStateAuthority
	authorities   authority.Bundle
}

func openRuntimeAuthorities(cfg *config.Config, connectTimeout, operationTimeout time.Duration) (_ *runtimeAuthoritySet, closers []func() error, retErr error) {
	var cleanup []func() error
	defer func() {
		if retErr == nil {
			closers = cleanup
			return
		}
		for i := len(cleanup) - 1; i >= 0; i-- {
			_ = cleanup[i]()
		}
	}()

	set := &runtimeAuthoritySet{}
	switch strings.ToLower(strings.TrimSpace(cfg.Authority.Backend)) {
	case "postgres":
		dsn := os.Getenv(cfg.Authority.DSNEnv)
		if dsn == "" {
			return nil, nil, fmt.Errorf("gripline: authority DSN environment variable %q is empty", cfg.Authority.DSNEnv)
		}
		connectCtx, connectCancel := context.WithTimeout(context.Background(), connectTimeout)
		s, err := statepg.Open(connectCtx, statepg.Options{
			DSN: dsn, MaxConns: cfg.Authority.MaxConns, MinConns: cfg.Authority.MinConns,
			NodeID: cfg.Authority.NodeID, LeaseTTL: cfg.Authority.LeaseTTL.D(), RenewEvery: cfg.Authority.RenewEvery.D(), MaxSourceScopes: cfg.Server.MaxSourceScopes, SourceScopeIdle: cfg.Server.SourceScopeIdle.D(), MaxSourceAliasIdentities: cfg.Authority.MaxSourceAliasIdentities,
			ClusterBehavior: clusterBehaviorFromConfig(cfg),
			ConnectTimeout:  connectTimeout, OperationTimeout: operationTimeout, Maintenance: statepg.MaintenanceOptions{
				Interval: cfg.Authority.Maintenance.Interval.D(), BatchSize: cfg.Authority.Maintenance.BatchSize,
				MaxBatchesPerPass: cfg.Authority.Maintenance.MaxBatchesPerPass, MaxRowsPerPass: cfg.Authority.Maintenance.MaxRowsPerPass,
				MaxRuntimePerPass: cfg.Authority.Maintenance.MaxRuntimePerPass.D(),
				EvidenceGrace:     cfg.Authority.Maintenance.EvidenceGrace.D(), ReleasedLeaseRetention: cfg.Authority.Maintenance.ReleasedLeaseRetention.D(),
				CredentialReceiptRetention: cfg.Authority.Maintenance.CredentialReceiptRetention.D(), ControlOperationRetention: cfg.Authority.Maintenance.ControlOperationRetention.D(),
				AdmissionAuditRetention: cfg.Authority.Maintenance.AdmissionAuditRetention.D(), SecurityTransitionRetention: cfg.Authority.Maintenance.SecurityTransitionRetention.D(),
				OperatorAuditRetention: cfg.Authority.Maintenance.OperatorAuditRetention.D(), PolicyAuditRetention: cfg.Authority.Maintenance.PolicyAuditRetention.D(),
				MembershipRetention: cfg.Authority.Maintenance.MembershipRetention.D(), AdaptiveRetention: cfg.Authority.Maintenance.AdaptiveRetention.D(),
				EvidenceGuardRetention: cfg.Authority.Maintenance.EvidenceGuardRetention.D(), LaneOperatorAuditRetention: cfg.Authority.Maintenance.LaneOperatorAuditRetention.D(),
				PolicyNodeStateRetention: cfg.Authority.Maintenance.PolicyNodeStateRetention.D(), ClusterCryptoAckRetention: cfg.Authority.Maintenance.ClusterCryptoAckRetention.D(), SourceAliasRetention: cfg.Authority.Maintenance.SourceAliasRetention.D(),
			}, Migrate: false,
		})
		connectCancel()
		if err != nil {
			return nil, nil, fmt.Errorf("gripline: postgres authority: %w", err)
		}
		cleanup = append(cleanup, func() error { s.Close(); return nil })
		set.registry, set.lanes, set.evidence, set.postgres = s, s, s, s
		set.stateHealth, set.adminState = s, s
		set.authorities = authority.Bundle{
			Credentials: s, Lanes: s, Evidence: s, AdaptiveRows: s, Health: s, Membership: s,
			Posture: s, Mutations: s, AuditSink: s, Audit: s, SecurityLog: s,
		}
	case "", "standalone":
		if cfg.Paths.State != "" {
			if cfg.Paths.Evidence != "" {
				return nil, nil, fmt.Errorf("gripline: paths.evidence must be empty when paths.state is configured: the Bolt state database is the single evidence authority (P0.2)")
			}
			s, err := statebolt.Open(cfg.Paths.State, statebolt.Options{})
			if err != nil {
				return nil, nil, fmt.Errorf("gripline: state db: %w", err)
			}
			cleanup = append(cleanup, func() error { return s.Close() })
			// Sweep expired evidence before releasing the database on shutdown.
			cleanup = append(cleanup, startStateMaintenance(s))
			set.registry, set.lanes, set.evidence, set.state = s, s, s, s
			set.stateHealth, set.adminState, set.adaptiveState = s, s, s
			set.authorities = authority.Bundle{
				Credentials: s, Lanes: s, Evidence: s, Adaptive: s, Health: s,
				Posture: s, Mutations: s, AuditSink: s, Audit: s, SecurityLog: s,
			}
		} else {
			set.registry = credential.NewMemoryRegistry()
			set.lanes = lane.NewStore(nil, time.Now)
			set.evidence = evidence.NewMemoryStore()
			set.authorities = authority.Bundle{Credentials: set.registry, Lanes: set.lanes, Evidence: set.evidence}
		}
	default:
		return nil, nil, fmt.Errorf("gripline: unsupported authority backend %q", cfg.Authority.Backend)
	}
	return set, cleanup, nil
}

func clusterBehaviorFromConfig(cfg *config.Config) *statepg.ClusterBehaviorConfig {
	if cfg == nil {
		return nil
	}
	m := cfg.Authority.Maintenance
	return &statepg.ClusterBehaviorConfig{
		LeaseTTL: cfg.Authority.LeaseTTL.D(), RenewEvery: cfg.Authority.RenewEvery.D(),
		MaxSourceScopes: cfg.Server.MaxSourceScopes, SourceScopeIdle: cfg.Server.SourceScopeIdle.D(),
		MaxSourceAliasIdentities: cfg.Authority.MaxSourceAliasIdentities,
		EvidenceGrace:            m.EvidenceGrace.D(), ReleasedLeaseRetention: m.ReleasedLeaseRetention.D(),
		CredentialReceiptRetention: m.CredentialReceiptRetention.D(), ControlOperationRetention: m.ControlOperationRetention.D(),
		AdmissionAuditRetention: m.AdmissionAuditRetention.D(), SecurityTransitionRetention: m.SecurityTransitionRetention.D(),
		OperatorAuditRetention: m.OperatorAuditRetention.D(), PolicyAuditRetention: m.PolicyAuditRetention.D(),
		MembershipRetention: m.MembershipRetention.D(), AdaptiveRetention: m.AdaptiveRetention.D(),
		EvidenceGuardRetention: m.EvidenceGuardRetention.D(), LaneOperatorAuditRetention: m.LaneOperatorAuditRetention.D(),
		PolicyNodeStateRetention: m.PolicyNodeStateRetention.D(), ClusterCryptoAckRetention: m.ClusterCryptoAckRetention.D(),
		SourceAliasRetention: m.SourceAliasRetention.D(),
	}
}
