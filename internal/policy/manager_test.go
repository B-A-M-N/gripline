package policy

import (
	"context"
	"errors"
	"testing"
)

func TestManagerPrepareActivateRollback(t *testing.T) {
	var manifests []Manifest
	var events []Event
	m, err := NewManager(Default(), Options{
		Persist: func(manifest Manifest) error {
			manifests = append(manifests, manifest)
			return nil
		},
		Audit: func(event Event) error {
			events = append(events, event)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if epoch, ok := m.PolicyEpoch(); !ok || epoch != 1 {
		t.Fatalf("initial policy epoch: %d, %v", epoch, ok)
	}
	next := Default()
	next.Revision = 2
	prepared, err := m.Prepare(next)
	if err != nil || prepared.Revision != 2 {
		t.Fatalf("prepare: %v", err)
	}
	if m.Current().Revision != 1 {
		t.Fatal("prepare must not change the active policy")
	}
	if err := m.Activate("scheduled rollout"); err != nil {
		t.Fatal(err)
	}
	if m.Current().Revision != 2 || len(manifests) != 2 || len(events) != 2 {
		t.Fatalf("activation state: rev=%d manifests=%d events=%d", m.Current().Revision, len(manifests), len(events))
	}
	if epoch, ok := m.PolicyEpoch(); !ok || epoch != 2 || events[1].FromEpoch != 1 || events[1].ToEpoch != 2 {
		t.Fatalf("activation epoch: %d, %v event=%+v", epoch, ok, events[1])
	}
	if err := m.Rollback(1, "failed canary"); err != nil {
		t.Fatal(err)
	}
	if m.Current().Revision != 1 || events[2].Action != "rollback" {
		t.Fatalf("rollback state: rev=%d events=%+v", m.Current().Revision, events)
	}
	if epoch, ok := m.PolicyEpoch(); !ok || epoch != 3 || events[2].FromEpoch != 2 || events[2].ToEpoch != 3 {
		t.Fatalf("rollback epoch: %d, %v event=%+v", epoch, ok, events[2])
	}
}

func TestManagerFailedPersistenceDoesNotActivate(t *testing.T) {
	m, err := NewManager(Default(), Options{Persist: func(Manifest) error { return errors.New("disk full") }})
	if err != nil {
		t.Fatal(err)
	}
	next := Default()
	next.Revision = 2
	if _, err := m.Prepare(next); err == nil {
		t.Fatal("candidate preparation must fail when the durable manifest cannot be persisted")
	}
	if m.Current().Revision != 1 || m.Candidate() != nil {
		t.Fatal("failed preparation changed lifecycle state")
	}
}

func TestManagerRejectsReplayAndUnreasonedRollback(t *testing.T) {
	m, err := NewManager(Default(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	same := Default()
	if _, err := m.Prepare(same); err == nil {
		t.Fatal("manager must reject a replayed revision")
	}
	if err := m.Rollback(1, ""); err == nil {
		t.Fatal("rollback must require an operator reason")
	}
}

func TestManagerSnapshotsAreDefensiveCopies(t *testing.T) {
	m, err := NewManager(Default(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	first := m.Current()
	rule := first.EvidenceRules["NEW_LANE"]
	rule.Score = 0
	first.EvidenceRules["NEW_LANE"] = rule
	first.Risk.Watch = 99
	second := m.Current()
	if second.EvidenceRules["NEW_LANE"].Score == 0 || second.Risk.Watch == 99 {
		t.Fatal("mutating Current result changed manager-owned policy")
	}
}

func TestManagerRefreshesCommittedSharedPolicy(t *testing.T) {
	var manifest Manifest
	var active *CompiledPolicy
	m, err := NewManager(Default(), Options{
		LoadManifest: func() (Manifest, error) { return manifest, nil },
		LoadArtifact: func(ref PolicyRef) (*CompiledPolicy, error) {
			if active == nil || active.ID != ref.ID || active.Revision != ref.Revision {
				return nil, errors.New("artifact not found")
			}
			return active, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	next := Default()
	next.Revision = 2
	active, err = Compile(next)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = manifestFor(active, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile shared active policy: %v", err)
	}
	if got := m.Current(); got == nil || got.Revision != 2 {
		t.Fatalf("manager did not refresh shared active policy: %+v", got)
	}
	if epoch, ok := m.PolicyEpoch(); !ok || epoch != 1 {
		t.Fatalf("shared policy epoch: %d, %v", epoch, ok)
	}
}

func TestManagerRefreshesSharedPolicyEpochWithoutArtifactChange(t *testing.T) {
	active, err := Compile(Default())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := manifestFor(active, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ActivationEpoch = 7
	m, err := NewManager(Default(), Options{
		LoadManifest: func() (Manifest, error) { return manifest, nil },
		LoadArtifact: func(ref PolicyRef) (*CompiledPolicy, error) { return active, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if epoch, ok := m.PolicyEpoch(); !ok || epoch != 7 {
		t.Fatalf("loaded policy epoch: %d, %v", epoch, ok)
	}
	manifest.ActivationEpoch = 8
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile shared policy epoch: %v", err)
	}
	if epoch, ok := m.PolicyEpoch(); !ok || epoch != 8 {
		t.Fatalf("refreshed policy epoch: %d, %v", epoch, ok)
	}
}

func TestManagerInitializesSharedPolicyCreateOnly(t *testing.T) {
	var shared Manifest
	var initializeCalls int
	load := func() func() (Manifest, error) {
		first := true
		return func() (Manifest, error) {
			if first {
				first = false
				return Manifest{}, nil
			}
			return shared, nil
		}
	}
	initialize := func(manifest Manifest) error {
		initializeCalls++
		if shared.Active.Revision == 0 {
			shared = manifest
		}
		return nil
	}

	if _, err := NewManager(Default(), Options{Initialize: initialize, LoadManifest: load()}); err != nil {
		t.Fatalf("same-policy first boot: %v", err)
	}
	if initializeCalls != 1 || shared.Active.Revision != 1 {
		t.Fatalf("initialization state: calls=%d manifest=%+v", initializeCalls, shared)
	}

	conflicting := Default()
	conflicting.Revision = 2
	if _, err := NewManager(conflicting, Options{Initialize: initialize, LoadManifest: load()}); err == nil {
		t.Fatal("conflicting concurrent first boot must fail")
	}
	if shared.Active.Revision != 1 {
		t.Fatalf("conflicting first boot replaced shared policy: %+v", shared.Active)
	}
}

func TestManagerReadyFailsWhenSharedPolicyCannotRefresh(t *testing.T) {
	loadCalls := 0
	m, err := NewManager(Default(), Options{
		LoadManifest: func() (Manifest, error) {
			loadCalls++
			if loadCalls == 1 {
				return Manifest{}, nil
			}
			return Manifest{}, errors.New("authority unavailable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Ready(context.Background()); err == nil {
		t.Fatal("readiness must fail when the shared policy authority cannot refresh")
	}
}

func TestManagerSnapshotDoesNotTouchDurableAuthority(t *testing.T) {
	compiled, err := Compile(Default())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := manifestFor(compiled, nil)
	if err != nil {
		t.Fatal(err)
	}
	loads := 0
	m, err := NewManager(Default(), Options{
		LoadManifest: func() (Manifest, error) {
			loads++
			return manifest, nil
		},
		LoadArtifact: func(PolicyRef) (*CompiledPolicy, error) { return compiled, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	initialLoads := loads
	for i := 0; i < 100; i++ {
		if m.Snapshot() == nil {
			t.Fatal("published policy snapshot unexpectedly unavailable")
		}
	}
	if loads != initialLoads {
		t.Fatalf("hot Snapshot performed durable reads: before=%d after=%d", initialLoads, loads)
	}
}

func TestManagerContextHooksReceiveCallerContext(t *testing.T) {
	type contextKey string
	const key contextKey = "request"
	ctx := context.WithValue(context.Background(), key, "control-request")
	var seen context.Context
	m, err := NewManager(Default(), Options{
		PersistContext: func(got context.Context, _ Manifest) error {
			seen = got
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	next := Default()
	next.Revision = 2
	if _, err := m.PrepareByContext(ctx, next, "operator", "test"); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.Value(key) != "control-request" {
		t.Fatal("policy persistence did not receive the caller context")
	}
}
