package anomaly

import (
	"strings"
	"testing"
	"time"
)

// TestDetectorBoundedUnderOneShotSubjects proves P0.31: many one-shot
// subjects cannot grow the detector unbounded — the global subject cap evicts
// cold entries.
func TestDetectorBoundedUnderOneShotSubjects(t *testing.T) {
	base := time.Now()
	th := DefaultThresholds()
	th.MaxSubjects = 128 // small for the test
	d := NewDetector(func() time.Time { return base }, th)

	at := base
	for i := 0; i < 5000; i++ {
		d.Observe("one-shot-src-"+string(rune(i%251))+strings.Repeat("x", 1), "cred-1", "AS-1", at)
		at = at.Add(time.Millisecond)
	}
	d.mu.Lock()
	total := len(d.credAsn) + len(d.srcCred) + len(d.srcInvalid)
	d.mu.Unlock()
	if total > 3*th.MaxSubjects {
		t.Fatalf("P0.31: detector state %d exceeds 3×subject cap %d", total, 3*th.MaxSubjects)
	}
}

// TestPerSubjectCardinalityCap proves P0.31: one subject cannot pin unbounded
// distinct keys inside its window set.
func TestPerSubjectCardinalityCap(t *testing.T) {
	base := time.Now()
	th := DefaultThresholds()
	th.MaxKeysPerSubject = 16
	d := NewDetector(func() time.Time { return base }, th)

	at := base
	for i := 0; i < 500; i++ {
		d.Observe("src-card", "cred-1", "AS-"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26)), at)
		at = at.Add(time.Second)
	}
	d.mu.Lock()
	ws := d.credAsn["cred-1"]
	n := 0
	if ws != nil {
		n = len(ws.keys)
	}
	d.mu.Unlock()
	if n > th.MaxKeysPerSubject {
		t.Fatalf("P0.31: per-subject keys %d exceed cap %d", n, th.MaxKeysPerSubject)
	}
}
