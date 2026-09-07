package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileCompilesBoundedArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	compiled, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load policy artifact: %v", err)
	}
	if compiled.ID != Default().ID || compiled.Revision != Default().Revision {
		t.Fatalf("loaded policy identity=%s@%d, want default %s@%d", compiled.ID, compiled.Revision, Default().ID, Default().Revision)
	}
}

func TestLoadFileRejectsOversizedArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, make([]byte, (4<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("oversized policy artifact must be rejected before decoding")
	}
}
