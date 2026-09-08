package statepg

import (
	"context"
	"errors"
	"testing"

	"github.com/B-A-M-N/gripline/internal/adaptive"
	"github.com/B-A-M-N/gripline/internal/authority"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/resource"
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
	var _ control.AuditRepository = (*Store)(nil)
	var _ control.MutationStore = (*Store)(nil)
	var _ control.PostureAuthority = (*Store)(nil)
	var _ control.SecurityTransitionReader = (*Store)(nil)
	var _ resource.Authority = (*Store)(nil)
	var _ resource.ResourceAuthority = (*Store)(nil)
	var _ resource.DistributedAuthority = (*Store)(nil)
	var _ resource.RequestDistributedAuthority = (*Store)(nil)
	var _ authority.Membership = (*Store)(nil)
	var _ adaptive.Store = (*Store)(nil)
}

func TestMembershipStateClassification(t *testing.T) {
	for _, state := range []string{"ready", "draining"} {
		if !isLiveMembershipState(state) {
			t.Fatalf("%q should be live for takeover protection", state)
		}
	}
	for _, state := range []string{"stopped", ""} {
		if isLiveMembershipState(state) {
			t.Fatalf("%q should not block a replacement instance", state)
		}
	}
}

func TestResourceLeaseRefundRequiresUnforwardedState(t *testing.T) {
	tests := []struct {
		name      string
		state     string
		settled   bool
		shouldRef bool
	}{
		{name: "reserved", state: leaseReserved, shouldRef: true},
		{name: "forwarded", state: leaseForwarded},
		{name: "forwarded settled", state: leaseForwarded, settled: true},
		{name: "settled", state: leaseSettled, settled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRefundLeaseHold(tt.state, tt.settled); got != tt.shouldRef {
				t.Fatalf("shouldRefundLeaseHold(%q, %t) = %t, want %t", tt.state, tt.settled, got, tt.shouldRef)
			}
		})
	}
}
