package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/B-A-M-N/gripline/internal/statebolt"
)

func TestRuntimeCloseAggregatesAndRunsInReverse(t *testing.T) {
	errFirst := errors.New("first close failure")
	errSecond := errors.New("second close failure")
	var order []int
	rt := &Runtime{closers: []func() error{
		func() error { order = append(order, 1); return errFirst },
		func() error { order = append(order, 2); return errSecond },
	}}
	got := rt.Close()
	if !errors.Is(got, errFirst) || !errors.Is(got, errSecond) {
		t.Fatalf("Close lost an error: %v", got)
	}
	if !reflect.DeepEqual(order, []int{2, 1}) {
		t.Fatalf("close order=%v, want reverse construction order", order)
	}
	if again := rt.Close(); again != got {
		t.Fatal("Close must be idempotent and return the same aggregated error")
	}
}

func TestBuildRuntimeCleansStateOnConstructionError(t *testing.T) {
	dir := t.TempDir()
	cfg := writeStatefulConfig(t, dir, "http://127.0.0.1:1", false)
	badParent := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(badParent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Paths.SignerKeyring = filepath.Join(badParent, "keyring.json")
	if _, err := BuildRuntime(cfg); err == nil {
		t.Fatal("invalid signer path must fail construction")
	}

	// A leaked Bolt handle would keep this reopen blocked until its timeout;
	// successful reopen proves the central construction-error cleanup ran.
	state, err := statebolt.Open(filepath.Join(dir, "state.db"), statebolt.Options{})
	if err != nil {
		t.Fatalf("state handle leaked after BuildRuntime failure: %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
}
