// Package anomaly detects the source-spray and velocity signals the risk engine
// consumes as evidence (P0.67). The detector decides WHETHER a signature
// occurred and returns SIGNALS (P0.12); it does NOT mint policy evidence — the
// admission engine resolves each signal against the CURRENT compiled policy's
// evidence rule table and mints with the current revision. The old design
// hardcoded policy revision 1, so after the first policy bump its evidence was
// permanently filtered out of enforcement (or, worse, drove decisions under a
// table it never consulted). One policy authority: the compiled revision.
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
type Thresholds struct {
	MaxASNsPerCredentialInWindow  int // > this many distinct ASNs → credential ASN-spray
	MaxCredentialsPerSourceWindow int // > this many distinct credentials → source spray
	Window                        time.Duration
}

// DefaultThresholds are conservative, matching the evidence table's intent.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MaxASNsPerCredentialInWindow:  3,
		MaxCredentialsPerSourceWindow: 4,
		Window:                        10 * time.Minute,
	}
}

// Signal is one detected spray signature, awaiting policy resolution. The
// detector owns detection only; the admission engine resolves Signal.Code
// against the CURRENT compiled policy's evidence table (P0.12) — scoring,
// scope, TTL, and minting revision all come from that one authority.
type Signal struct {
	Code      string // evidence rule code (e.g. SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS)
	SubjectID string // the credential (ASN spray) or source (credential spray)
}

// Detector is a bounded, sliding-window observer of admission (source,
// credential, ASN). It tracks the DISTINCT keys seen within the window and
// evicts entries older than the window at each observation, so cardinality is
// bounded by real elapsed time, not request volume. A continuous high-volume
// spray keeps its window fresh; a burst that ends decays after the window.
//
// Concurrency-safe: a single detector may serve the whole edge.
type Detector struct {
	mu    sync.Mutex
	th    Thresholds
	now   func() time.Time

	// credAsn: credential -> (asn -> lastSeen); distinct ASNs per credential.
	credAsn map[string]map[string]time.Time
	// srcCred: source -> (credential -> lastSeen); distinct credentials per source.
	srcCred map[string]map[string]time.Time
}

// NewDetector builds a Detector. now may be nil (defaults time.Now). The
// evidence-table parameter was removed (P0.12): the detector no longer mints.
func NewDetector(now func() time.Time, th Thresholds) *Detector {
	if now == nil {
		now = time.Now
	}
	if th.Window <= 0 {
		th = DefaultThresholds()
	}
	return &Detector{
		th:      th,
		now:     now,
		credAsn: make(map[string]map[string]time.Time),
		srcCred: make(map[string]map[string]time.Time),
	}
}

// Observe records one admission's (source, credential, ASN) and returns the
// signals for any spray signature that crossed its threshold within the window.
// Empty source/ASN fields are skipped (zeros never score — matches lane
// classification semantics for unknown metadata).
//
// The signal's subject is the CREDENTIAL (ASN-spray) or the SOURCE
// (credential-spray). The CALLER resolves each signal through the current
// compiled policy's evidence table and mints; a signal with no rule in the
// current table resolves to nothing (fail-closed, no invented parameters).
func (d *Detector) Observe(source, credentialID, asn string, now time.Time) []Signal {
	if now.IsZero() {
		now = d.now()
	}
	if credentialID == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := now.Add(-d.th.Window)
	var out []Signal

	// Credential-side ASN spray.
	if asn != "" {
		m, ok := d.credAsn[credentialID]
		if !ok {
			m = make(map[string]time.Time)
			d.credAsn[credentialID] = m
		}
		m[asn] = now
		// Evict ASNs seen before the window.
		for k, at := range m {
			if at.Before(cutoff) {
				delete(m, k)
			}
		}
		if len(m) > d.th.MaxASNsPerCredentialInWindow {
			out = append(out, Signal{Code: "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN", SubjectID: credentialID})
		}
		// If the set emptied or a credential's ASN set went cold, drop the key to
		// bound memory.
		if len(m) == 0 {
			delete(d.credAsn, credentialID)
		}
	}

	// Source-side credential spray.
	if source != "" {
		m, ok := d.srcCred[source]
		if !ok {
			m = make(map[string]time.Time)
			d.srcCred[source] = m
		}
		m[credentialID] = now
		for k, at := range m {
			if at.Before(cutoff) {
				delete(m, k)
			}
		}
		if len(m) > d.th.MaxCredentialsPerSourceWindow {
			out = append(out, Signal{Code: "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS", SubjectID: source})
		}
		if len(m) == 0 {
			delete(d.srcCred, source)
		}
	}

	return out
}