package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

func TestPolicyArtifactsRejectLinksAndBroadPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "policy-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(link); err == nil {
		t.Fatal("policy symlink must be rejected")
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("group-writable policy artifact must be rejected")
	}
}

func TestLoadAuthenticatedFileRequiresAndVerifiesSignature(t *testing.T) {
	dir := t.TempDir()
	policyBytes, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope := SignedArtifact{Version: 1, Policy: policyBytes, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, policyBytes))}
	path := filepath.Join(dir, "signed-policy.json")
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthenticatedFile(path, public); err != nil {
		t.Fatalf("signed policy rejected: %v", err)
	}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	data, _ = json.Marshal(envelope)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthenticatedFile(path, public); err == nil {
		t.Fatal("forged policy signature must be rejected")
	}
	envelope.Policy = append(append([]byte(nil), policyBytes...), []byte(` {}`)...)
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, policyBytes))
	data, _ = json.Marshal(envelope)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthenticatedFile(path, public); err == nil {
		t.Fatal("signed policy with trailing JSON must be rejected")
	}
}

func TestFileStorePersistsCandidateAndRestoresLastKnownGood(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(Default(), Options{
		Persist: store.Persist, PersistArtifact: store.PersistArtifact,
		PersistTransition: store.PersistTransition, LoadManifest: store.LoadManifest,
		LoadArtifact: store.LoadArtifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	next := Default()
	next.Revision = 2
	if _, err := m.Prepare(next); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(Default(), Options{
		Persist: store.Persist, PersistArtifact: store.PersistArtifact,
		PersistTransition: store.PersistTransition, LoadManifest: store.LoadManifest,
		LoadArtifact: store.LoadArtifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Current().Revision != 1 || restarted.Candidate() == nil || restarted.Candidate().Revision != 2 {
		t.Fatalf("restart lifecycle lost candidate: current=%d candidate=%v", restarted.Current().Revision, restarted.Candidate())
	}
	if err := restarted.Activate("test"); err != nil {
		t.Fatal(err)
	}
	activeAfterRestart, err := NewManager(Default(), Options{
		Persist: store.Persist, PersistArtifact: store.PersistArtifact,
		PersistTransition: store.PersistTransition, LoadManifest: store.LoadManifest,
		LoadArtifact: store.LoadArtifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	if activeAfterRestart.Current().Revision != 2 {
		t.Fatalf("durable active policy was not restored: revision=%d", activeAfterRestart.Current().Revision)
	}
	if err := activeAfterRestart.Rollback(1, "test rollback"); err != nil {
		t.Fatalf("restored last-known-good rollback failed: %v", err)
	}
}
