package policy

import (
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
	if epoch, ok := m.PolicyEpoch(); !ok || epoch != 8 {
		t.Fatalf("refreshed policy epoch: %d, %v", epoch, ok)
	}
}
