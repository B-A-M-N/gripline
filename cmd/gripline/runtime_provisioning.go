package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/statepg"
)

type cryptoStatusReader interface {
	ClusterStatus(context.Context) (statepg.ClusterStatus, error)
}

var errCredentialPolicyInactive = errors.New("credential: requested policy is not active")

// activeCredentialPolicy resolves the server-side policy binding for ordinary
// provisioning. Reconcile is deliberately performed on the control-plane
// request so a delayed watcher cannot bind a new credential to an old policy.
func activeCredentialPolicy(ctx context.Context, manager *policy.Manager, requested string) (string, error) {
	if manager == nil {
		return "", errors.New("credential: policy authority unavailable")
	}
	if err := manager.Reconcile(ctx); err != nil {
		return "", fmt.Errorf("credential: reconcile policy authority: %w", err)
	}
	active := manager.Current()
	if active == nil || active.ID == "" {
		return "", errors.New("credential: active policy unavailable")
	}
	if requested != "" && requested != active.ID {
		return "", fmt.Errorf("%w: requested %q, active %q", errCredentialPolicyInactive, requested, active.ID)
	}
	return active.ID, nil
}

// activeCredentialPepperVersion resolves the only pepper generation ordinary
// provisioning may use. PostgreSQL is authoritative in clustered mode;
// loaded-but-staged keys are intentionally not accepted. Standalone mode
// uses the ring's selected active generation.
func activeCredentialPepperVersion(ctx context.Context, peppers *credential.PepperRing, authority cryptoStatusReader) (int, error) {
	if peppers == nil {
		return 0, errors.New("credential: verifier pepper authority unavailable")
	}
	version := peppers.ActiveVersion()
	if authority != nil {
		status, err := authority.ClusterStatus(ctx)
		if err != nil {
			return 0, fmt.Errorf("credential: read shared crypto authority: %w", err)
		}
		if !status.Crypto.Initialized || status.Crypto.PepperActiveVersion < 1 {
			return 0, errors.New("credential: shared pepper generation is not initialized")
		}
		version = status.Crypto.PepperActiveVersion
	}
	if _, ok := peppers.VersionFingerprint(version); !ok {
		return 0, fmt.Errorf("credential: active pepper generation %d is not loaded locally", version)
	}
	return version, nil
}
