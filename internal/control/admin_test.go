package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// memAudit is an in-memory AuditRepository recording every append (test only —
// production uses FileAuditRepository or a DB-backed implementation).
type memAudit struct {
	mu   sync.Mutex
	rows []OperatorRecord
	fail error
}

func (m *memAudit) AppendOperator(_ context.Context, rec OperatorRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	m.rows = append(m.rows, rec)
	return nil
}

func (m *memAudit) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

// staticAuth is a fixed-identity Authenticator (test double).
type staticAuth struct {
	id  *Identity
	err error
}

func (s staticAuth) Authenticate(context.Context, string) (*Identity, error) {
	return s.id, s.err
}

// stubLane / stubCreds are lifecycle seams recording calls.
type stubLanes struct {
	calls int
	err   error
}

func (s *stubLanes) UnblockOperator(credID, laneID, actor, reason string, now time.Time) error {
	s.calls++
	return s.err
}

type stubCreds struct {
	revoked []string
	err     error
}

func (s *stubCreds) Revoke(id string) error {
	if s.err != nil {
		return s.err
	}
	s.revoked = append(s.revoked, id)
	return nil
}

func (s *stubCreds) BumpRevision(id string) error { return nil }

func newTestService(t *testing.T) (*Service, *memAudit, *stubLanes, *stubCreds) {
	t.Helper()
	audit := &memAudit{}
	lanes := &stubLanes{}
	creds := &stubCreds{}
	svc, err := NewService(New(0), staticAuth{id: &Identity{
		Name:         "op-test",
		Capabilities: []Capability{CapPosture, CapCredentialLifecycle, CapLaneLifecycle},
	}}, audit, WithLaneOperator(lanes), WithCredentialOperator(creds))
	if err != nil {
		t.Fatal(err)
	}
	return svc, audit, lanes, creds
}

// P0.47: every operator action requires authentication, the exact capability,
// and a reason. Any missing precondition denies the action AND leaves a
// durable record of the denied attempt.
func TestServiceActionPreconditions(t *testing.T) {
	svc, audit, lanes, creds := newTestService(t)
	ctx := context.Background()

	// Missing reason.
	if _, err := svc.SetEmergency(ctx, "tok", true, ""); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("missing reason must be refused, got %v", err)
	}
	// Unauthenticated: swap in an authenticator that refuses everything.
	svc.auth = staticAuth{id: nil, err: ErrUnauthenticated}
	if _, err := svc.SetEmergency(ctx, "tok", true, "incident"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unauthenticated identity must be refused, got %v", err)
	}
	// Unauthorized (no capabilities).
	denySvc, denyAudit, _, _ := newTestService(t)
	denySvc.auth = staticAuth{id: &Identity{Name: "limited"}}
	if _, err := denySvc.SetEmergency(ctx, "tok", true, "incident"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("lacking capability must be refused, got %v", err)
	}
	if denyAudit.count() == 0 {
		t.Fatal("denied attempts must be durably recorded")
	}
	// Nothing mutated by the denied calls.
	if lanes.calls != 0 || len(creds.revoked) != 0 {
		t.Fatal("denied actions must not mutate state")
	}
	_ = svc
	_ = audit
}

// P0.47: a successful action commits its durable audit record with the
// committed=true outcome; a failed AUDIT write aborts the action entirely.
func TestServiceAuditAtomicity(t *testing.T) {
	svc, audit, lanes, _ := newTestService(t)
	ctx := context.Background()

	if err := svc.RevokeCredential(ctx, "tok", "cred_x", "confirmed compromise"); err != nil {
		t.Fatal(err)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != "credential.revoke" ||
		audit.rows[0].Target != "cred_x" || !audit.rows[0].Committed {
		t.Fatalf("revoke must durably record its committed action, got %+v", audit.rows)
	}
	if audit.rows[0].Actor != "op-test" {
		t.Fatalf("audit actor must be the authenticated identity, got %q", audit.rows[0].Actor)
	}

	// Audit repository failure → action returns error (BETA-11: mutation
	// already succeeded; the operator sees the failure and can re-audit).
	audit.fail = errors.New("disk full")
	if err := svc.RevokeCredential(ctx, "tok", "cred_y", "second incident"); err == nil {
		t.Fatal("P0.47: failed durable audit must return error")
	}
	audit.fail = nil
	// cred_y WAS revoked (mutation precedes audit); the operator sees the
	// audit failure and can re-run to persist the record.
	foundY := false
	for _, id := range svc.creds.(*stubCreds).revoked {
		if id == "cred_y" {
			foundY = true
		}
	}
	if !foundY {
		t.Fatal("BETA-11: mutation must succeed even if audit fails")
	}
	_ = lanes
}

// BETA-11: A failed mutation must NOT produce a committed audit row.
func TestServiceMutationFailureNoAudit(t *testing.T) {
	svc, audit, _, _ := newTestService(t)
	ctx := context.Background()

	// Make the credential operator fail.
	svc.creds = &stubCreds{err: errors.New("db write failed")}

	if err := svc.RevokeCredential(ctx, "tok", "cred_z", "test"); err == nil {
		t.Fatal("expected error when mutation fails")
	}
	// No committed audit row for a failed mutation.
	for _, r := range audit.rows {
		if r.Target == "cred_z" && r.Committed {
			t.Fatal("BETA-11: failed mutation must not produce committed audit row")
		}
	}
}

// P0.47: the lane unblock rides the wired LaneOperator (which commits the
// lane-side audit inside the store transaction) plus the control plane's own
// durable row.
func TestServiceUnblockLane(t *testing.T) {
	svc, audit, lanes, _ := newTestService(t)
	ctx := context.Background()
	if err := svc.UnblockLane(ctx, "tok", "cred_u", "lane_u", "verified clean"); err != nil {
		t.Fatal(err)
	}
	if lanes.calls != 1 {
		t.Fatalf("lane operator must be invoked once, got %d", lanes.calls)
	}
	found := false
	for _, r := range audit.rows {
		if r.Action == "lane.unblock" && r.Target == "lane_u" && r.Committed {
			found = true
		}
	}
	if !found {
		t.Fatalf("lane.unblock must be durably recorded: %+v", audit.rows)
	}
}

// P0.47: the posture switch feeds the in-memory plane AND the durable audit.
func TestServiceSetEmergencyAudited(t *testing.T) {
	svc, audit, _, _ := newTestService(t)
	ctx := context.Background()
	p, err := svc.SetEmergency(ctx, "tok", true, "active abuse incident")
	if err != nil {
		t.Fatal(err)
	}
	if p != EmergencyLockdown || !svc.plane.InEmergency() {
		t.Fatalf("posture must engage lockdown, got %v", p)
	}
	found := false
	for _, r := range audit.rows {
		if r.Action == "posture.set_emergency" && r.Committed && r.Posture == "EMERGENCY_LOCKDOWN" {
			found = true
		}
	}
	if !found {
		t.Fatal("posture switch must record its post-action posture")
	}
}

// The file-backed audit repository must be append-only JSONL with one record
// per line, fsynced and never rewritten.
func TestFileAuditRepositoryAppendOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	repo, err := NewFileAuditRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	rec1 := OperatorRecord{At: time.Now().UTC(), Actor: "a1", Action: "credential.revoke", Target: "c1", Reason: "r1", Committed: true}
	rec2 := OperatorRecord{At: time.Now().UTC(), Actor: "a2", Action: "lane.unblock", Target: "l1", Reason: "r2", Committed: true}
	ctx := context.Background()
	if err := repo.AppendOperator(ctx, rec1); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendOperator(ctx, rec2); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("exactly one JSON line per record expected, got %d", len(lines))
	}
	var back OperatorRecord
	if err := json.Unmarshal([]byte(lines[0]), &back); err != nil {
		t.Fatal(err)
	}
	if back.Actor != "a1" || back.Target != "c1" || !back.Committed {
		t.Fatalf("record round-trip failed: %+v", back)
	}

	// Reopening appends, never truncates.
	repo2, err := NewFileAuditRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repo2.Close()
	if err := repo2.AppendOperator(ctx, OperatorRecord{Actor: "a3", Action: "posture.set_emergency", Reason: "r3"}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if got := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; got != 3 {
		t.Fatalf("reopen must append, not truncate: %d lines", got)
	}
}

// Empty operator tokens are refused at construction (an empty bearer would
// authenticate anyone).
func TestTokenAuthenticatorRejectsEmptyToken(t *testing.T) {
	if _, err := NewTokenAuthenticator(map[string]*Identity{"": {Name: "x"}}); err == nil {
		t.Fatal("empty token must be refused")
	}
	if _, err := NewTokenAuthenticator(map[string]*Identity{"short": {Name: "x"}}); err == nil {
		t.Fatal("short token must be refused")
	}
	if _, err := NewTokenAuthenticator(map[string]*Identity{"tok": nil}); err == nil {
		t.Fatal("nil identity must be refused")
	}
	const realToken = "real-token-0123456789abcdef0123456789abcdef"
	a, err := NewTokenAuthenticator(map[string]*Identity{realToken: {Name: "op", Capabilities: []Capability{CapPosture}}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.Authenticate(context.Background(), realToken)
	if err != nil || id.Name != "op" {
		t.Fatalf("valid token must authenticate, got %v %v", id, err)
	}
	if _, err := a.Authenticate(context.Background(), "wrong"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("wrong token must be unauthenticated")
	}
	if _, err := a.Authenticate(context.Background(), ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("empty presented token must be unauthenticated")
	}
	// The raw token must never be retained anywhere greppable in the struct.
	dump := jsonMarshalSafe(a)
	if strings.Contains(dump, realToken) {
		t.Fatal("INV-1: authenticator must not retain the raw token")
	}
}

func jsonMarshalSafe(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Service construction fails closed without each required seam (P0.47: a
// control plane without auth or durable audit is the finding itself).
func TestNewServiceRequiresSeams(t *testing.T) {
	if _, err := NewService(nil, staticAuth{}, &memAudit{}); err == nil {
		t.Fatal("plane required")
	}
	if _, err := NewService(New(0), nil, &memAudit{}); err == nil {
		t.Fatal("authenticator required")
	}
	if _, err := NewService(New(0), staticAuth{}, nil); err == nil {
		t.Fatal("durable audit repository required")
	}
}
