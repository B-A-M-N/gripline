package statepg

import (
	"context"
	"testing"
	"time"
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

func TestSourceAliasTouchThrottle(t *testing.T) {
	store := &Store{}
	alias := "v1.touch-throttle"
	if len(store.claimSourceAliasTouch([]string{alias}, time.Now())) == 0 {
		t.Fatal("first source alias touch should be claimed")
	}
	if len(store.claimSourceAliasTouch([]string{alias}, time.Now().Add(30*time.Second))) != 0 {
		t.Fatal("source alias touch should be throttled within the interval")
	}
	if len(store.claimSourceAliasTouch([]string{alias}, time.Now().Add(61*time.Second))) == 0 {
		t.Fatal("source alias touch should be claimable after the interval")
	}
}
