// Package anomaly detects the source-spray and velocity signals the risk engine
// consumes as evidence (P0.67). It is a RESPONSIBLE MINTER (P0.11): the
// detector decides WHETHER a signature occurred; evidence.Mint fixes its score,
// family, scope, and TTL from the versioned rule table, never hand-built here.
package anomaly

import (
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/evidence"
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
	table evidence.Table

	// credAsn: credential -> (asn -> lastSeen); distinct ASNs per credential.
	credAsn map[string]map[string]time.Time
	// srcCred: source -> (credential -> lastSeen); distinct credentials per source.
	srcCred map[string]map[string]time.Time
}

// NewDetector builds a Detector. now may be nil (defaults time.Now); table may
// be nil (defaults evidence.DefaultTable).
func NewDetector(now func() time.Time, table evidence.Table, th Thresholds) *Detector {
	if now == nil {
		now = time.Now
	}
	if table == nil {
		table = evidence.DefaultTable()
	}
	if th.Window <= 0 {
		th = DefaultThresholds()
	}
	return &Detector{
		th:      th,
		now:     now,
		table:   table,
		credAsn: make(map[string]map[string]time.Time),
		srcCred: make(map[string]map[string]time.Time),
	}
}

// Observe records one admission's (source, credential, ASN) and returns any
// evidence minted when a spray signature crosses its threshold within the
// window. Empty source/ASN fields are skipped (zeros never score — matches lane
// classification semantics for unknown metadata).
//
// The returned evidence's subject is the CREDENTIAL (ASN-spray) or the SOURCE
// (credential-spray), per the rule table scope; it is ready to Append to the
// evidence store.
func (d *Detector) Observe(source, credentialID, asn string, now time.Time) []evidence.Evidence {
	if now.IsZero() {
		now = d.now()
	}
	if credentialID == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := now.Add(-d.th.Window)
	var out []evidence.Evidence

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
			if ev, err := evidence.Mint(d.table, "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN", credentialID, now, 1); err == nil {
				out = append(out, ev)
			}
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
			if ev, err := evidence.Mint(d.table, "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS", source, now, 1); err == nil {
				out = append(out, ev)
			}
		}
		if len(m) == 0 {
			delete(d.srcCred, source)
		}
	}

	return out
}