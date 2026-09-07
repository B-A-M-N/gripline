package statebolt

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
)

func mustRecord(id, raw string) *credential.CredentialRecord {
	sum := sha256.Sum256([]byte(raw))
	return &credential.CredentialRecord{
		CredentialID:    id,
		AccountID:       "acct",
		Verifier:        sum[:],
		VerifierVersion: 1,
		PepperVersion:   1,
		Status:          credential.StatusNormal,
		CreatedAt:       time.Now().Add(-time.Hour),
		Revision:        1,
	}
}

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"), Options{Now: time.Now})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStateboltCredentialRoundTrip(t *testing.T) {
	s := openTest(t)
	rec := mustRecord("cred_a", "sk-secret-a")
	if err := s.Insert(rec); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Lookup("cred_a")
	if !ok || got.CredentialID != "cred_a" || got.Revision != 1 {
		t.Fatalf("lookup: %+v ok=%v", got, ok)
	}
	// index resolves by verifier
	if byV, ok := s.FindByVerifier(rec.Verifier, 1); !ok || byV.CredentialID != "cred_a" {
		t.Fatalf("find by verifier failed: %+v ok=%v", byV, ok)
	}
	if byV, err := s.FindByVerifierContext(context.Background(), rec.Verifier, 1); err != nil || byV.CredentialID != "cred_a" {
		t.Fatalf("find by verifier ctx: %+v err=%v", byV, err)
	}
	// unknown verifier is a typed not-found
	if _, err := s.FindByVerifierContext(context.Background(), []byte("nope"), 1); !credential.IsUnknownCredential(err) {
		t.Fatalf("unknown verifier should be ErrNotFound, got %v", err)
	}
}

func TestStateboltProvisionInsertIfAbsent(t *testing.T) {
	s := openTest(t)
	rec := mustRecord("cred_b", "sk-b")
	created, err := s.InsertIfAbsent(rec)
	if err != nil || !created {
		t.Fatalf("first provision: created=%v err=%v", created, err)
	}
	// Second provision with a DIFFERENT verifier must NOT overwrite.
	rec2 := mustRecord("cred_b", "sk-b-replaced")
	created, err = s.InsertIfAbsent(rec2)
	if err != nil || created {
		t.Fatalf("second provision must be created=false, got created=%v err=%v", created, err)
	}
	got, ok := s.Lookup("cred_b")
	if !ok {
		t.Fatalf("cred_b missing after second provision")
	}
	if got.CredentialID != "cred_b" {
		t.Fatalf("wrong record after second provision: %q", got.CredentialID)
	}
	// The ORIGINAL verifier is retained (bootstrap never overwrites managed state).
	same, err := s.FindByVerifierContext(context.Background(), rec.Verifier, 1)
	if err != nil {
		t.Fatalf("original verifier should still authenticate: %v", err)
	}
	if same.CredentialID != "cred_b" {
		t.Fatalf("unexpected resolved id %q", same.CredentialID)
	}
	if _, err := s.FindByVerifierContext(context.Background(), rec2.Verifier, 1); !credential.IsUnknownCredential(err) {
		t.Fatalf("replacement verifier must NOT authenticate: %v", err)
	}
}

func TestStateboltObserveAndCommitSingleTxn(t *testing.T) {
	s := openTest(t)
	rec := mustRecord("cred_c", "sk-c")
	if err := s.Insert(rec); err != nil {
		t.Fatal(err)
	}
	hy := credential.DefaultHysteresis()
	// WatchObs qualifying observations are needed to enter WATCH. The first is a
	// no-status-change observation (state persisted, no revision bump); the final
	// qualifying observation commits the transition with exactly one revision bump.
	var last credential.TransitionResult
	base := time.Now()
	for i := 0; i < hy.WatchObs; i++ {
		res, err := s.ObserveAndCommit(context.Background(), "cred_c", 60, hy, base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("observe[%d]: %v", i, err)
		}
		last = res
	}
	if last.Status != credential.TransitionCommitted {
		t.Fatalf("expected committed transition after WatchObs observations, got %v", last.Status)
	}
	if last.Record.Revision != 2 {
		t.Fatalf("revision must bump exactly once on commit, got %d", last.Record.Revision)
	}
	// A subsequent observation that keeps the current WATCH status (score in
	// [Watch, Constrained), above the down-threshold, inside the dwell window)
	// persists security state but does NOT bump revision.
	res2, err := s.ObserveAndCommit(context.Background(), "cred_c", 40, hy, base.Add(time.Minute))
	if err != nil {
		t.Fatalf("observe after commit: %v", err)
	}
	if res2.Status != credential.TransitionNoChange {
		t.Fatalf("expected NoChange, got %v", res2.Status)
	}
	if res2.Record.Revision != 2 {
		t.Fatalf("revision must be stable on NoChange, got %d", res2.Record.Revision)
	}
}

func TestStateboltUpdateStatusCAS(t *testing.T) {
	s := openTest(t)
	rec := mustRecord("cred_d", "sk-d")
	if err := s.Insert(rec); err != nil {
		t.Fatal(err)
	}
	// Stale revision rejected.
	if _, err := s.UpdateStatusCAS("cred_d", 99, credential.StatusNormal, credential.StatusConstrained); !errors.Is(err, credential.ErrStaleCAS) {
		t.Fatalf("stale revision must be ErrStaleCAS, got %v", err)
	}
	out, err := s.UpdateStatusCAS("cred_d", 1, credential.StatusNormal, credential.StatusConstrained)
	if err != nil {
		t.Fatalf("update CAS: %v", err)
	}
	if out.Status != credential.StatusConstrained || out.Revision != 2 {
		t.Fatalf("bad post-CAS: %+v", out)
	}
	// Recovery downgrade CONSTRAINED→NORMAL is legal via this path.
	recov, err := s.UpdateStatusCAS("cred_d", 2, credential.StatusConstrained, credential.StatusNormal)
	if err != nil || recov.Status != credential.StatusNormal || recov.Revision != 3 {
		t.Fatalf("constrained→normal recovery must succeed, got %+v err=%v", recov, err)
	}
	// QUARANTINED is terminal — nothing may exit it through this path.
	if _, err := s.UpdateStatusCAS("cred_d", 3, credential.StatusNormal, credential.StatusQuarantined); err != nil {
		t.Fatalf("escalate to quarantined: %v", err)
	}
	if _, err := s.UpdateStatusCAS("cred_d", 4, credential.StatusQuarantined, credential.StatusNormal); err == nil {
		t.Fatalf("quarantined downgrade must fail closed")
	}
	// REVOKED is terminal and reached via the lifecycle path, not CAS.
	if err := s.Revoke("cred_d"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, ok := s.Lookup("cred_d")
	if !ok || got.Status != credential.StatusRevoked {
		t.Fatalf("revoke must yield revoked, got %+v", got)
	}
	if _, err := s.UpdateStatusCAS("cred_d", got.Revision, credential.StatusRevoked, credential.StatusNormal); err == nil {
		t.Fatalf("revoked downgrade must fail closed")
	}
}

func TestStateboltCredentialPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	rec := mustRecord("cred_e", "sk-e")
	// Elevate the credential so we can prove a managed state survives restart.
	if err := s.Insert(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateStatusCAS("cred_e", 1, credential.StatusNormal, credential.StatusConstrained); err != nil {
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
	got, err := s2.LookupAuthoritative(context.Background(), "cred_e")
	if err != nil {
		t.Fatalf("reopen lookup: %v", err)
	}
	if got.Status != credential.StatusConstrained || got.Revision != 2 {
		t.Fatalf("managed CONSTRAINED state must survive restart: %+v", got)
	}
}

func TestStateboltRotationRemovesOldVerifier(t *testing.T) {
	s := openTest(t)
	rec1 := mustRecord("cred_f", "sk-f1")
	if err := s.Insert(rec1); err != nil {
		t.Fatal(err)
	}
	rec2 := mustRecord("cred_f", "sk-f2")
	rec2.Revision = 2 // replacement row
	if err := s.Insert(rec2); err != nil {
		t.Fatal(err)
	}
	// Old verifier must no longer resolve.
	if _, ok := s.FindByVerifier(rec1.Verifier, 1); ok {
		t.Fatalf("old verifier must be removed on rotation")
	}
	// New verifier resolves.
	if _, ok := s.FindByVerifier(rec2.Verifier, 1); !ok {
		t.Fatalf("new verifier must resolve")
	}
}
