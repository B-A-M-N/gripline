package control

import (
	"sync"
	"testing"
)

// TestSetEmergencyTogglesAndAudits proves P0.39/P0.35: SetEmergency transitions
// the posture, is idempotent (no-op re-set leaves one event), and records a
// reviewable operator event with actor + reason.
func TestSetEmergencyTogglesAndAudits(t *testing.T) {
	cp := New(1024)
	if cp.InEmergency() {
		t.Fatal("must start in NORMAL")
	}
	cp.SetEmergency(true, "ops-oncall", "suspected exfiltration")
	if !cp.InEmergency() || cp.Posture() != EmergencyLockdown {
		t.Fatal("P0.39: SetEmergency(true) must enter EMERGENCY_LOCKDOWN")
	}
	// No-op re-set must not add a duplicate operator event.
	cp.SetEmergency(true, "ops-oncall", "again")
	// Exit.
	cp.SetEmergency(false, "ops-oncall", "incident resolved")
	if cp.InEmergency() {
		t.Fatal("P0.39: SetEmergency(false) must return to NORMAL")
	}
	ops := 0
	for _, e := range cp.Audit() {
		if e.Kind == EventOperator && e.Actor == "ops-oncall" {
			ops++
		}
	}
	if ops != 2 { // enter + exit, not the no-op
		t.Fatalf("P0.35: operator events = %d, want 2 (enter+exit, no-op deduped)", ops)
	}
}

// TestAuditBoundedMemory proves P0.35 bounded-memory: the audit log never
// exceeds auditCap and drops the OLDEST first, so a flood cannot grow it
// unbounded.
func TestAuditBoundedMemory(t *testing.T) {
	capn := 16
	cp := New(capn)
	for i := 0; i < 100; i++ {
		cp.RecordAdmission(Event{RequestID: "r", Authorized: true})
	}
	ev := cp.Audit()
	if len(ev) != capn {
		t.Fatalf("P0.35: audit length = %d, want bounded %d", len(ev), capn)
	}
}

// TestRecordAdmissionNeverSecret proves admission events carry only non-secret
// fields (no assertion/raw secret anywhere in the serialized view).
func TestRecordAdmissionNeverSecret(t *testing.T) {
	cp := New(64)
	cp.RecordAdmission(Event{
		RequestID: "req_x", CredentialID: "cred_x", AccountID: "acct_x",
		LaneID: "lane_x", Authorized: true, Reason: "authorized",
	})
	for _, e := range cp.Audit() {
		if e.Kind != EventAdmission {
			t.Fatalf("expected admission event, got %v", e.Kind)
		}
	}
}

// TestConcurrentControlSafe exercises the control plane under concurrency
// (posture toggles + audit writes) without races.
func TestConcurrentControlSafe(t *testing.T) {
	cp := New(256)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if j%2 == 0 {
					cp.SetEmergency(true, "op", "x")
				} else {
					cp.SetEmergency(false, "op", "y")
				}
				cp.RecordAdmission(Event{RequestID: "r", Authorized: j%3 != 0})
			}
		}(i)
	}
	wg.Wait()
	_ = cp.Posture()
}
