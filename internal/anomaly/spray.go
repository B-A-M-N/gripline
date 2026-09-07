// Package anomaly detects the source-spray and velocity signals the risk engine
// consumes as evidence (P0.67). The detector decides WHETHER a signature
// occurred and returns SIGNALS (P0.12); it does NOT mint policy evidence — the
// admission engine resolves each signal against the CURRENT compiled policy's
// evidence rule table and mints with the current revision. The old design
// hardcoded policy revision 1, so after the first policy bump its evidence was
// permanently filtered out of enforcement (or, worse, drove decisions under a
// table it never consulted). One policy authority: the compiled revision.
//
// Emission discipline (P0.32): a signature is emitted when it CROSSES its
// threshold, then the detector enters a cooldown for that subject — repeated
// observations while the signature remains active re-emit only after the
// cooldown elapses. Without this, every request past the threshold mints
// another evidence row: family/correlation bounds hide some score inflation,
// but storage churn and snapshot growth remain.
//
// Bounded state (P0.31): an attacker generating millions of ONE-SHOT subjects
// must not grow the maps forever. The detector enforces (a) window eviction on
// every observation, (b) idle-key removal for cold subjects, (c) a GLOBAL
// subject cap on each map with oldest-seen eviction under overload, and (d) a
// per-subject cardinality cap so one source cannot hold unbounded distinct
// keys. Under overload the detector EVICTS OLDEST state (degrading detection
// for stale subjects) rather than growing unbounded — shared bounded state is
// the production requirement.
package anomaly

import (
	"sync"
	"time"
)

// Spray thresholds align with the evidence table's signatures:
//   - MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN (ScopeCredential): >3 distinct ASNs
//     for one credential inside a 10-minute window.
//   - SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS (ScopeSource): a source
//     presenting many distinct credentials inside the window.
//   - SOURCE_ATTEMPTING_MANY_INVALID_CREDENTIALS (P0.30): a source presenting
//     many distinct INVALID candidate keys (keyed pseudonyms) in the window.
type Thresholds struct {
	MaxASNsPerCredentialInWindow  int // > this many distinct ASNs → credential ASN-spray
	MaxCredentialsPerSourceWindow int // > this many distinct credentials → source spray
	MaxInvalidPerSourceWindow     int // > this many distinct invalid pseudonyms → invalid-key spray
	Window                        time.Duration
	// Cooldown (P0.32): minimum interval between re-emissions of the SAME
	// signal for the SAME subject while the signature stays active.
	Cooldown time.Duration
	// MaxSubjects bounds each top-level map (P0.31); oldest-lastSeen evicted.
	MaxSubjects int
	// MaxKeysPerSubject bounds one subject's inner set (P0.31).
	MaxKeysPerSubject int
}

// DefaultThresholds are conservative, matching the evidence table's intent.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MaxASNsPerCredentialInWindow:  3,
		MaxCredentialsPerSourceWindow: 4,
		MaxInvalidPerSourceWindow:     8,
		Window:                        10 * time.Minute,
		Cooldown:                      time.Minute,
		MaxSubjects:                   65536,
		MaxKeysPerSubject:             256,
	}
}

// Signal is one detected spray signature, awaiting policy resolution. The
// detector owns detection only; it does NOT decide the eventual evidence
// subject (P0.8). The admission engine resolves Signal.Code against the CURRENT
// compiled policy's evidence table (P0.12) — scoring, scope, TTL, and minting
// revision all come from that one authority, and the subject is derived from
// the rule's scope against the request context.
type Signal struct {
	Code string // evidence rule code (e.g. SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS)
}

// winSet is one subject's sliding window of distinct keys.
type winSet struct {
	keys     map[string]time.Time
	lastSeen time.Time
	// lastEmit per signal code (P0.32 cooldown).
	lastEmit map[string]time.Time
}

// Detector is a bounded, sliding-window observer of admission (source,
// credential, ASN, invalid-key pseudonym). Concurrency-safe: a single
// detector may serve the whole edge.
type Detector struct {
	mu  sync.Mutex
	th  Thresholds
	now func() time.Time

	// credAsn: credential -> (asn -> lastSeen); distinct ASNs per credential.
	credAsn map[string]*winSet
	// srcCred: source -> (credential -> lastSeen); distinct credentials per source.
	srcCred map[string]*winSet
	// srcInvalid: source -> (invalid-key pseudonym -> lastSeen) (P0.30).
	srcInvalid map[string]*winSet
}

// NewDetector builds a Detector. now may be nil (defaults time.Now). The
// evidence-table parameter was removed (P0.12): the detector no longer mints.
func NewDetector(now func() time.Time, th Thresholds) *Detector {
	if now == nil {
		now = time.Now
	}
	if th.Window <= 0 || th.MaxSubjects <= 0 || th.MaxKeysPerSubject <= 0 || th.Cooldown <= 0 {
		th = DefaultThresholds()
	}
	return &Detector{
		th:         th,
		now:        now,
		credAsn:    make(map[string]*winSet),
		srcCred:    make(map[string]*winSet),
		srcInvalid: make(map[string]*winSet),
	}
}

// observe updates one subject's window set with a key and returns whether the
// DISTINCT-key threshold for sigCode has (still) crossed and the cooldown
// permits an emission now. Caller holds d.mu.
func (d *Detector) observe(m map[string]*winSet, subject, key string, sigCode string, threshold int, now time.Time) bool {
	cutoff := now.Add(-d.th.Window)
	ws := m[subject]
	if ws == nil {
		// P0.31: global subject cap — evict the coldest subject under overload.
		if len(m) >= d.th.MaxSubjects {
			d.evictColdestLocked(m, now)
		}
		ws = &winSet{keys: make(map[string]time.Time), lastEmit: make(map[string]time.Time)}
		m[subject] = ws
	}
	ws.lastSeen = now
	if key != "" {
		ws.keys[key] = now
	}
	// Window eviction + cardinality cap (P0.31): expired keys leave; if the
	// set is still above the per-subject cap, drop the OLDEST keys — one
	// subject cannot pin unbounded memory.
	for k, at := range ws.keys {
		if at.Before(cutoff) {
			delete(ws.keys, k)
		}
	}
	for len(ws.keys) > d.th.MaxKeysPerSubject {
		oldestK, oldestT := "", now
		for k, at := range ws.keys {
			if at.Before(oldestT) {
				oldestK, oldestT = k, at
			}
		}
		if oldestK == "" {
			break
		}
		delete(ws.keys, oldestK)
	}
	if len(ws.keys) == 0 {
		delete(m, subject)
		return false
	}
	if len(ws.keys) <= threshold {
		return false
	}
	// P0.32: emit on crossing, then cooldown per (subject, code).
	if last, ok := ws.lastEmit[sigCode]; ok && now.Sub(last) < d.th.Cooldown {
		return false
	}
	ws.lastEmit[sigCode] = now
	return true
}

// evictColdestLocked removes the least-recently-seen subject from m (P0.31
// overload behavior: degrade stale subjects' detection, never grow unbounded).
func (d *Detector) evictColdestLocked(m map[string]*winSet, now time.Time) {
	coldestK := ""
	var coldestT time.Time
	for k, ws := range m {
		if coldestK == "" || ws.lastSeen.Before(coldestT) {
			coldestK, coldestT = k, ws.lastSeen
		}
	}
	if coldestK != "" {
		delete(m, coldestK)
	}
}

// Observe records one authenticated admission's (source, credential, ASN) and
// returns the signals for any spray signature whose cooldown permits an
// emission. Empty source/ASN fields are skipped (zeros never score — matches
// lane classification semantics for unknown metadata).
func (d *Detector) Observe(source, credentialID, asn string, now time.Time) []Signal {
	if now.IsZero() {
		now = d.now()
	}
	if credentialID == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []Signal
	if asn != "" && d.observe(d.credAsn, credentialID, asn, "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN", d.th.MaxASNsPerCredentialInWindow, now) {
		out = append(out, Signal{Code: "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN"})
	}
	if source != "" && d.observe(d.srcCred, source, credentialID, "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS", d.th.MaxCredentialsPerSourceWindow, now) {
		out = append(out, Signal{Code: "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS"})
	}
	return out
}

// ObserveInvalidCredential records an INVALID candidate key against its
// source, BEFORE the presented material is destroyed (P0.30). candidate is
// the SprayPseudonym of the presented bytes — a short-lived keyed tag; the
// raw candidate key is never retained anywhere. Returns the invalid-spray
// signal when the source's distinct-invalid-pseudonym count crosses the
// threshold and cooldown permits.
func (d *Detector) ObserveInvalidCredential(source, candidate string, now time.Time) []Signal {
	if now.IsZero() {
		now = d.now()
	}
	if source == "" || candidate == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.observe(d.srcInvalid, source, candidate, "SOURCE_ATTEMPTING_MANY_INVALID_CREDENTIALS", d.th.MaxInvalidPerSourceWindow, now) {
		return []Signal{{Code: "SOURCE_ATTEMPTING_MANY_INVALID_CREDENTIALS"}}
	}
	return nil
}
