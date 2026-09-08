package statebolt

import (
	"testing"

	"github.com/B-A-M-N/gripline/internal/policy"
)

func TestPolicyLifecycleManifestArtifactAndAuditSurviveRestart(t *testing.T) {
	path := t.TempDir() + "/state.db"
	store, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}

	initial := policy.Default()
	initialCompiled, err := policy.Compile(initial)
	if err != nil {
		t.Fatal(err)
	}
	initialDigest, err := policy.Digest(&initialCompiled.Policy)
	if err != nil {
		t.Fatal(err)
	}
	initialRef := policy.PolicyRef{ID: initialCompiled.ID, Revision: initialCompiled.Revision, Digest: initialDigest}
	initialManifest := policy.Manifest{SchemaVersion: 1, Active: initialRef}
	if err := store.PersistPolicyArtifact(initialCompiled); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistPolicyManifest(initialManifest); err != nil {
		t.Fatal(err)
	}

	candidate := *initial
	candidate.Revision = initial.Revision + 1
	candidate.Risk.WatchObs++
	candidateCompiled, err := policy.Compile(&candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidateDigest, err := policy.Digest(&candidateCompiled.Policy)
	if err != nil {
		t.Fatal(err)
	}
	candidateRef := policy.PolicyRef{ID: candidateCompiled.ID, Revision: candidateCompiled.Revision, Digest: candidateDigest}
	if err := store.PersistPolicyArtifact(candidateCompiled); err != nil {
		t.Fatal(err)
	}
	transition := policy.Manifest{SchemaVersion: 1, Active: candidateRef, Previous: &initialRef}
	if err := store.PersistPolicyTransition(transition, policy.Event{
		Action: "activate", Actor: "test-operator", FromRevision: initialCompiled.Revision,
		ToRevision: candidateCompiled.Revision, PolicyID: candidateCompiled.ID,
		Reason: "test activation",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	gotManifest, err := store.LoadPolicyManifest()
	if err != nil {
		t.Fatal(err)
	}
	if gotManifest.Active != candidateRef || gotManifest.Previous == nil || *gotManifest.Previous != initialRef {
		t.Fatalf("manifest did not survive restart: %+v", gotManifest)
	}
	gotCandidate, err := store.LoadPolicyArtifact(candidateRef)
	if err != nil {
		t.Fatal(err)
	}
	if gotCandidate.Revision != candidateCompiled.Revision || gotCandidate.Risk.WatchObs != candidateCompiled.Risk.WatchObs {
		t.Fatalf("artifact did not survive restart: %+v", gotCandidate)
	}
	events, err := store.ListPolicyAudit(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Actor != "test-operator" || events[0].Action != "activate" {
		t.Fatalf("transition audit did not survive atomically: %+v", events)
	}
}
