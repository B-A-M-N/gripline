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
	if err := m.Rollback(1, "failed canary"); err != nil {
		t.Fatal(err)
	}
	if m.Current().Revision != 1 || events[2].Action != "rollback" {
		t.Fatalf("rollback state: rev=%d events=%+v", m.Current().Revision, events)
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
