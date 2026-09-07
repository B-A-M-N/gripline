package statebolt

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
)

func mustAudit(action string) control.OperatorRecord {
	return control.OperatorRecord{
		Action: action,
		Actor:  "operator-t",
		At:     time.Now(),
	}
}

// TestPosturePersistsAcrossReopen proves a restart in EMERGENCY_LOCKDOWN does
// not silently boot into NORMAL (P0.10): the posture is durable and restored.
func TestPosturePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadPosture(); got != control.Normal {
		t.Fatalf("fresh store must default to NORMAL, got %v", got)
	}
	if err := s.SavePosture(control.EmergencyLockdown); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.LoadPosture()
	if err != nil {
		t.Fatalf("reopen load posture: %v", err)
	}
	if got != control.EmergencyLockdown {
		t.Fatalf("EMERGENCY_LOCKDOWN must survive restart, got %v", got)
	}
}

// TestPostureCorruptFailsClosed: a garbage posture value fails LoadPosture, it
// must never guess towards NORMAL.
func TestPostureCorruptFailsClosed(t *testing.T) {
	s := openTest(t)
	if err := s.SavePosture(control.Normal); err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored posture value directly through the underlying DB.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOperatorState).Put(keyPosture, []byte("not-an-int"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadPosture(); err == nil {
		t.Fatalf("corrupt posture must fail closed, got nil error")
	}
}

// TestRevokeCredentialWithAuditAtomic proves P0.18: a mutation and its audit
// row commit or fail together — a successful revoke is durably audited.
func TestRevokeCredentialWithAuditAtomic(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	rec := mustRecord("cred_txn", "sk-txn")
	if err := s.Insert(rec); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCredentialWithAudit(ctx, "cred_txn", mustAudit("revoke")); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Lookup("cred_txn")
	if !ok || got.Status != credential.StatusRevoked {
		t.Fatalf("credential must be revoked, got %+v ok=%v", got, ok)
	}
	n, err := s.CountAuditRecords()
	if err != nil || n != 1 {
		t.Fatalf("expected exactly 1 audit row after revoke, got n=%d err=%v", n, err)
	}
}

// TestRevokeMissingCredentialNotAudited: a no-op revocation (target absent) is
// not a durable mutation, so it must not leave an audit row behind either.
func TestRevokeMissingCredentialNotAudited(t *testing.T) {
	s := openTest(t)
	err := s.RevokeCredentialWithAudit(context.Background(), "missing", mustAudit("revoke"))
	if !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("missing revoke must be ErrNotFound, got %v", err)
	}
	n, err := s.CountAuditRecords()
	if err != nil || n != 0 {
		t.Fatalf("a failed mutation must not append an audit row, got n=%d err=%v", n, err)
	}
}

// TestSetPostureWithAudit: an emergency transition persists the posture AND its
// audit row atomically — the audit survives restart.
func TestSetPostureWithAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPostureWithAudit(context.Background(), control.EmergencyLockdown, mustAudit("emergency-on")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadPosture(); got != control.EmergencyLockdown {
		t.Fatalf("posture must be emergency, got %v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	n, err := s2.CountAuditRecords()
	if err != nil || n != 1 {
		t.Fatalf("audit row must survive restart, got n=%d err=%v", n, err)
	}
	if got, _ := s2.LoadPosture(); got != control.EmergencyLockdown {
		t.Fatalf("posture must survive restart, got %v", got)
	}
}
