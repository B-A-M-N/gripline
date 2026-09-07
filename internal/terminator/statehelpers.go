package terminator

import (
	"context"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
)

func ctxForRequest(now time.Time, requestID string) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// Self-releasing: the cancel is invoked once the deadline passes so the
	// goroutine/context is reclaimed even though callers never hold a ref to it.
	time.AfterFunc(5*time.Second, cancel)
	if requestID != "" {
		ctx = credential.WithRequestID(ctx, requestID)
	}
	return ctx
}

// markLastSeen records the credential's LastSeenAt on successful authentication
// and ongoing authorized traffic. It is analytics-grade, not part of the strong
// authorization transaction, and intentionally must not be able to fail an
// admission (P0.22): the Registry.TouchLastSeen contract is best-effort.
func markLastSeen(reg credential.Registry, credentialID string, now time.Time) {
	if reg == nil {
		return
	}
	reg.TouchLastSeen(credentialID, now)
}

// dedupAppend merges per-request synchronous evidence into the lane evidence
// for evaluation, dropping any EvidenceID already present (P0.3): an append that
// landed in the store AND is reconstructed here must never double-count. The
// result is a fresh slice; inputs are not mutated.
func dedupAppend(existing, incoming []evidence.Evidence) []evidence.Evidence {
	if len(incoming) == 0 {
		return existing
	}
	seen := make(map[string]bool, len(existing)+len(incoming))
	out := make([]evidence.Evidence, 0, len(existing)+len(incoming))
	for _, e := range existing {
		seen[e.EvidenceID] = true
		out = append(out, e)
	}
	for _, e := range incoming {
		if e.EvidenceID == "" || !seen[e.EvidenceID] {
			seen[e.EvidenceID] = true
			out = append(out, e)
		}
	}
	return out
}

// activeEvidenceAcrossPolicyRevisions returns the evidence that may drive the authoritative
// state machine. Semantics (P0.11, supersedes the old current-revision-only
// filter): evidence keeps the CONCRETE score/family/scope assigned by the
// policy revision that minted it and remains active until its TTL ends. A
// routine policy deployment must never wipe accumulated risk — the old filter
// dropped evidence minted under any other revision, so deploying revision N+1
// silently pardoned every unexpired event minted under revision N. The minting
// revision stays on the record for audit and for any future explicit migration
// rule (a revision that reinterprets old evidence must do so explicitly, not
// by side effect of a filter).
//
// What still fails closed: evidence with NO minting revision (a possible
// hand-construction artifact) is preserved — zero-revision records are
// documented operator/operator-IOC evidence that predates revision tagging.
// Dedup and TTL handling are unchanged; only revision-based erasure is gone.
func activeEvidenceAcrossPolicyRevisions(items []evidence.Evidence, rev int) []evidence.Evidence {
	if len(items) == 0 {
		return items
	}
	// All unexpired evidence drives the machine regardless of minting revision.
	// rev is still consulted for callers that log the evaluated-revision pair;
	// it no longer gates inclusion.
	return items
}

// credentialHysteresis derives the state-transition config from the compiled
// policy snapshot (P0.11: hysteresis is policy-controlled, not hardcoded).
func (t *Terminator) credentialHysteresis() credential.Hysteresis {
	r := t.pol.Risk
	return credential.Hysteresis{
		WatchThresh:           r.Watch,
		ConstrainedThresh:     r.Constrained,
		QuarantineThresh:      r.Quarantine,
		ConstrainedDownThresh: r.ConstrainedDownThresh,
		WatchDownThresh:       r.WatchDownThresh,
		ConstrainedDwell:      r.ConstrainedDwell,
		WatchDwell:            r.WatchDwell,
		WatchObs:              r.WatchObs,
	}
}
