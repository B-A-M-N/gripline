// Package producers implements deterministic signal producers (BETA-07) that
// observe request behavior and emit signals for the policy to resolve into
// scored Evidence.
//
// Architecture (P0.3 fix): producers decide WHAT happened only. They do NOT
// decide the security subject. The compiled policy rule table determines
// scope (LANE/CREDENTIAL/SOURCE/REQUEST), and the terminator resolves the
// actual subject ID from the request context. This prevents the mismatch
// where producers emitted credential-scoped signals that were invisible to
// lane-scoped admission snapshots.
//
// Producers are bounded (P0.31): sliding windows evict stale entries, and
// each producer enforces a global subject cap with oldest-seen eviction under
// overload.
package producers

import (
	"time"

	"github.com/B-A-M-N/gripline/internal/evidence"
)

// Signal is one detected behavior signature. It carries only the evidence
// rule code — the admission engine resolves the actual subject from the
// request context based on the rule's scope (P0.3).
type Signal struct {
	Code string // evidence rule code (e.g. NEW_ASL)
}

// SubjectContext carries the authoritative request subjects that the
// terminator uses to resolve scoped signals into concrete subject IDs.
type SubjectContext struct {
	RequestID    string
	SourceID     string
	LaneID       string
	CredentialID string
	AccountID    string
}

// AdmissionBehavior carries the observable surface of one request at
// admission time (before execution). Producers analyze this to detect
// source novelty, endpoint enumeration, concurrency spikes, etc.
type AdmissionBehavior struct {
	Subjects       SubjectContext
	Features       Features
	EndpointFamily string
	Estimate       UsageEstimate
	Concurrency    int
}

// CompletionBehavior carries the actual resource consumption after the
// backend responds. Producers use this for token/cost velocity signals.
type CompletionBehavior struct {
	Subjects SubjectContext
	Actual   UsageEstimate
	Success  bool
}

// Producer observes request behavior and emits signals. Implementations are
// concurrency-safe; a single instance serves the whole edge.
type Producer interface {
	// ObserveAdmission records one request's admission-time behavior and
	// returns any signals that crossed their threshold.
	ObserveAdmission(behavior AdmissionBehavior) []Signal

	// ObserveCompletion records the actual usage after backend response and
	// returns any signals that crossed their threshold.
	ObserveCompletion(behavior CompletionBehavior) []Signal
}

// Features carries the observable non-secret feature atoms of one request.
type Features struct {
	NetworkASN  string // e.g. "AS1234"
	NetworkType string // residential/hosting/mobile
	RegionClass string // coarse geographic region
	ClientFamily string // claude-code/python-sdk/curl
}

// UsageEstimate carries the per-dimensional resource consumption.
type UsageEstimate struct {
	Input    int64
	Output   int64
	Combined int64
	Cost     int64
}

// ResolveSubject maps a rule scope to the concrete subject ID from the
// request context. Returns false if the required subject is unavailable
// (e.g. no source configured → SOURCE scope signals are skipped).
// P0.3 fix: Uses evidence.Scope enum directly instead of raw integers.
func ResolveSubject(scope evidence.Scope, subjects SubjectContext) (string, bool) {
	switch scope {
	case evidence.ScopeRequest:
		return subjects.RequestID, subjects.RequestID != ""
	case evidence.ScopeSource:
		return subjects.SourceID, subjects.SourceID != ""
	case evidence.ScopeLane:
		return subjects.LaneID, subjects.LaneID != ""
	case evidence.ScopeCredential:
		return subjects.CredentialID, subjects.CredentialID != ""
	case evidence.ScopeAccount:
		return subjects.AccountID, subjects.AccountID != ""
	}
	return "", false
}

// --- Internal helpers ---

// windowKey tracks one subject's sliding-window state for a signal type.
type windowKey struct {
	keys     map[string]time.Time // distinct key -> lastSeen
	lastSeen time.Time            // last observation time
	lastEmit time.Time            // last emission time (cooldown)
}

// evictColdest removes the coldest subject from the map (P0.31 bounded state).
func evictColdest(m map[string]*windowKey) {
	var coldest string
	var coldestTime time.Time
	for k, v := range m {
		if coldest == "" || v.lastSeen.Before(coldestTime) {
			coldest = k
			coldestTime = v.lastSeen
		}
	}
	if coldest != "" {
		delete(m, coldest)
	}
}

// observeWindow updates one subject's window set with a key and returns whether
// the distinct-key threshold has crossed and the cooldown permits emission.
func observeWindow(m map[string]*windowKey, subject, key string, threshold int, window, cooldown time.Duration, now time.Time, maxSubjects int) bool {
	cutoff := now.Add(-window)
	ws := m[subject]
	if ws == nil {
		if len(m) >= maxSubjects {
			evictColdest(m)
		}
		ws = &windowKey{keys: make(map[string]time.Time)}
		m[subject] = ws
	}
	// Evict stale keys.
	for k, t := range ws.keys {
		if t.Before(cutoff) {
			delete(ws.keys, k)
		}
	}
	// Check if this key is new.
	_, existed := ws.keys[key]
	if !existed {
		if len(ws.keys) < threshold {
			ws.keys[key] = now
			ws.lastSeen = now
			return false
		}
		if !ws.lastEmit.IsZero() && now.Sub(ws.lastEmit) < cooldown {
			ws.keys[key] = now
			ws.lastSeen = now
			return false
		}
		ws.keys[key] = now
		ws.lastSeen = now
		ws.lastEmit = now
		return true
	}
	ws.keys[key] = now
	ws.lastSeen = now
	return false
}

// baseline tracks a per-subject exponential moving average for velocity signals.
type baseline struct {
	ema      float64
	count    int
	lastSeen time.Time
	lastEmit time.Time
}



func evictColdestBaseline(m map[string]*baseline) {
	var coldest string
	var coldestTime time.Time
	for k, v := range m {
		if coldest == "" || v.lastSeen.Before(coldestTime) {
			coldest = k
			coldestTime = v.lastSeen
		}
	}
	if coldest != "" {
		delete(m, coldest)
	}
}

// defaultMaxSubjects bounds each producer's per-subject map.
const defaultMaxSubjects = 65536

// defaultCooldown bounds re-emission of the same signal for the same subject.
const defaultCooldown = time.Minute

