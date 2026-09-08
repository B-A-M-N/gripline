package statepg

import (
	"context"
	"errors"
	"testing"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
)

func TestOpenRequiresDSNBeforeDialing(t *testing.T) {
	_, err := Open(context.Background(), Options{})
	if err == nil || !errors.Is(err, ErrDSNRequired) {
		t.Fatalf("Open without DSN = %v", err)
	}
}

func TestSharedAuthorityInterfaceConformance(t *testing.T) {
	var _ credential.Registry = (*Store)(nil)
	var _ credential.VerifierLookup = (*Store)(nil)
	var _ credential.Provisioner = (*Store)(nil)
	var _ lane.Repository = (*Store)(nil)
	var _ lane.PolicyAwareRepository = (*Store)(nil)
	var _ lane.ReadRepository = (*Store)(nil)
	var _ evidence.Store = (*Store)(nil)
	var _ evidence.ContextStore = (*Store)(nil)
}
