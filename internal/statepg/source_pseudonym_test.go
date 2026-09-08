package statepg

import (
	"context"
	"testing"
)

func TestResolveExistingSourcePseudonymRequiresAuthority(t *testing.T) {
	if _, err := (*Store)(nil).ResolveExistingSourcePseudonym(context.Background(), []string{"v1.example"}); err == nil {
		t.Fatal("nil authority must fail closed")
	}
	store := &Store{operationTimeout: 0}
	if got, err := store.ResolveExistingSourcePseudonym(context.Background(), nil); err == nil || got != "" {
		t.Fatalf("nil pool with empty candidates: got=%q err=%v, want an unavailable-authority error", got, err)
	}
}
