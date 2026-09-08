// Package authority defines the backend-neutral authority bundle assembled by
// the executable composition root. It contains independent domain contracts,
// not a database-shaped god interface: each consumer should depend on the
// smallest field it needs.
package authority

import (
	"context"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/resource"
)

// Health is the bounded readiness probe for the selected state authority.
type Health interface {
	Ready(context.Context) error
}

// AdaptiveState is the checkpoint seam for adaptive detectors. Adaptive state
// remains separate from hard security authorities so its failure can produce a
// degraded posture without weakening credential or resource enforcement.
type AdaptiveState interface {
	LoadDetectorState(string) ([]byte, bool, error)
	SaveDetectorState(string, []byte) error
}

// Bundle is the composition-root view of all authorities. Fields are optional
// only for explicitly ephemeral/test deployments; production cluster mode
// supplies the shared PostgreSQL implementations for the authoritative paths.
type Bundle struct {
	Credentials credential.Registry
	Lanes       lane.Repository
	Evidence    evidence.Store
	Resource    resource.ResourceAuthority
	Posture     control.PostureAuthority
	Mutations   control.MutationStore
	AuditSink   control.AuditRepository
	Audit       control.AuditRecordReader
	SecurityLog control.SecurityTransitionReader
	Adaptive    AdaptiveState
	Health      Health
}
