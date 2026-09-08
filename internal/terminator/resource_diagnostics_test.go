package terminator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/resource"
)

type diagnosticsResource struct {
	used         int
	err          error
	seenContext  context.Context
	removed      []string
	removeCalled bool
}

type diagnosticsContextKey struct{}

func (r *diagnosticsResource) RemoveScope(scope resource.Scope, id string) bool {
	return r.remove(scope, id)
}

func (r *diagnosticsResource) InUseFor(resource.Scope, string) int {
	return r.used
}

func (r *diagnosticsResource) Reserve(context.Context, resource.ReserveRequest) (resource.UsageReservation, error) {
	return diagnosticsReservation{}, nil
}

func (r *diagnosticsResource) InUseForContext(ctx context.Context, _ resource.Scope, _ string) (int, error) {
	r.seenContext = ctx
	return r.used, r.err
}

func (r *diagnosticsResource) RemoveScopeContext(_ context.Context, scope resource.Scope, id string) (bool, error) {
	r.removeCalled = true
	return r.remove(scope, id), nil
}

func (r *diagnosticsResource) remove(_ resource.Scope, id string) bool {
	r.removed = append(r.removed, id)
	return true
}

type diagnosticsReservation struct{}

func (diagnosticsReservation) Release() {}

func (diagnosticsReservation) MarkForwarded(context.Context) error { return nil }

func (diagnosticsReservation) Renew(context.Context) error { return nil }

func (diagnosticsReservation) SettleContext(context.Context, resource.UsageEstimate) error {
	return nil
}

func (diagnosticsReservation) ExpiresAt() time.Time { return time.Time{} }

func TestCurrentConcurrencyUsesContextAwareDiagnostics(t *testing.T) {
	ctx := context.WithValue(context.Background(), diagnosticsContextKey{}, "request")
	authority := &diagnosticsResource{used: 4}
	term := &Terminator{dep: Dependencies{Resource: authority}}

	got, err := term.currentConcurrency(ctx, "lane-1")
	if err != nil {
		t.Fatalf("currentConcurrency: %v", err)
	}
	if got != 5 {
		t.Fatalf("currentConcurrency=%d, want 5 including the attempted request", got)
	}
	if authority.seenContext != ctx {
		t.Fatal("diagnostics did not receive the request context")
	}
}

func TestCurrentConcurrencyPreservesDiagnosticsError(t *testing.T) {
	wantErr := errors.New("authority unavailable")
	authority := &diagnosticsResource{err: wantErr}
	term := &Terminator{dep: Dependencies{Resource: authority}}

	got, err := term.currentConcurrency(context.Background(), "lane-1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("currentConcurrency error=%v, want %v", err, wantErr)
	}
	if got != 0 {
		t.Fatalf("currentConcurrency=%d, want 0 with no usable diagnostic", got)
	}
}

func TestCleanupRemovedLaneResourcesUsesContextAwareDiagnostics(t *testing.T) {
	ctx := context.WithValue(context.Background(), diagnosticsContextKey{}, "request")
	authority := &diagnosticsResource{}

	cleanupRemovedLaneResources(ctx, authority, []string{"lane-old", "lane-kept"}, []string{"lane-kept"})

	if !authority.removeCalled {
		t.Fatal("cleanup did not use context-aware scope removal")
	}
	if len(authority.removed) != 1 || authority.removed[0] != "lane-old" {
		t.Fatalf("removed lanes=%v, want [lane-old]", authority.removed)
	}
}
