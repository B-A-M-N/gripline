package terminator

import (
	"context"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
)

const deferredAuthorityTimeout = 5 * time.Second

// boundedRuntimeContext preserves the authority work needed after a client
// disconnects while imposing a finite completion budget. Admission itself
// still uses the caller context; only deferred completion accounting uses this
// detached context.
func boundedRuntimeContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), deferredAuthorityTimeout)
}

func ctxForRequest(parent context.Context, requestID string) (context.Context, context.CancelFunc) {
	return ctxForRequestWithMetadata(parent, credential.TransitionMetadata{RequestID: requestID})
}

func ctxForRequestWithMetadata(parent context.Context, meta credential.TransitionMetadata) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	if meta.RequestID != "" {
		ctx = credential.WithRequestID(ctx, meta.RequestID)
	}
	ctx = credential.WithTransitionMetadata(ctx, meta)
	return ctx, cancel
}

// markLastSeen records the credential's LastSeenAt on successful authentication
// and ongoing authorized traffic. It is analytics-grade, not part of the strong
// authorization transaction, and intentionally must not be able to fail an
// admission (P0.22): the Registry.TouchLastSeen contract is best-effort.
func markLastSeen(reg credential.Registry, credentialID string, now time.Time) {
	if reg == nil {
		return
	}
	if aware, ok := reg.(credential.ContextLastSeenWriter); ok {
		// Last-seen is telemetry, not authorization. Keep it out of the request
		// critical path and bound the detached remote write independently.
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		go func() {
			defer cancel()
			_ = aware.TouchLastSeenContext(ctx, credentialID, now)
		}()
		return
	}
	reg.TouchLastSeen(credentialID, now)
}

func appendEvidenceContext(ctx context.Context, store evidence.Store, items ...evidence.Evidence) error {
	if store == nil {
		return nil
	}
	if aware, ok := store.(evidence.ContextStore); ok {
		return aware.AppendContext(ctx, items...)
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	return store.Append(items...)
}

func snapshotEvidenceContext(ctx context.Context, store evidence.Store, subjects []evidence.SubjectKey, now time.Time) ([]evidence.Evidence, error) {
	if store == nil {
		return nil, nil
	}
	if aware, ok := store.(evidence.ContextStore); ok {
		return aware.SnapshotContext(ctx, subjects, now)
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	return store.Snapshot(subjects, now)
}

func pruneEvidenceContext(ctx context.Context, store evidence.Store, subjects []evidence.SubjectKey, now time.Time) (int, error) {
	if store == nil {
		return 0, nil
	}
	if aware, ok := store.(evidence.ContextStore); ok {
		return aware.PruneContext(ctx, subjects, now)
	}
	if err := contextErr(ctx); err != nil {
		return 0, err
	}
	return store.Prune(subjects, now)
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
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
