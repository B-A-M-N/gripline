package terminator

import (
	"context"
	"errors"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
)

// credentialObservation owns the authoritative credential security-state
// mutation. Admission still decides how the resulting state is enforced, but
// the load/reduce/CAS/re-read protocol is kept together so it cannot be
// accidentally changed in one of the many surrounding gates.
type credentialObservation struct {
	credential *credential.Credential
	status     credential.Status
	adaptive   AdaptiveStateStatus
}

// observeCredentialRisk records one request's credential risk against the
// authoritative registry. On contention it performs the same bounded
// authoritative re-read/retry used by the original admission pipeline. When
// history is unavailable it preserves the persisted state and marks the
// observation degraded; it never synthesizes a lower-risk state.
func (t *Terminator) observeCredentialRisk(ctx context.Context, requestID string, cred *credential.Credential, credentialRisk int, evidenceCodes []string, adaptive AdaptiveStateStatus, adaptivePersistenceFailed bool, out *Outcome, now time.Time) credentialObservation {
	result := credentialObservation{credential: cred, status: cred.Status, adaptive: adaptive}
	if adaptive == AdaptiveAvailable && t.dep.Evidence != nil {
		// Gate H / §102 phase 6: automatic quarantine is disabled until shadow
		// validation. The real score still reaches the authoritative state; only
		// the automatic status ceiling is constrained.
		hy := t.credentialHysteresis()
		if !t.pol.Risk.EnableAutomaticQuarantine {
			hy.MaxAutomaticStatus = credential.StatusConstrained
		}
		transitionMeta := credential.TransitionMetadata{
			RequestID: requestID, PolicyRevision: t.pol.Revision, EvidenceCodes: evidenceCodes,
		}
		transition, err := t.dep.Registry.ObserveAndCommit(
			ctxForRequestWithMetadata(ctx, transitionMeta), cred.CredentialID,
			credentialRisk, hy, now,
		)
		if err != nil {
			// The observation could not be committed authoritatively. Preserve
			// the persisted state; never fuse a local result with stale storage.
			result.adaptive = AdaptiveDegraded
			if record, readErr := t.dep.Registry.LookupAuthoritative(ctxForRequest(ctx, requestID), cred.CredentialID); readErr == nil {
				result.status = record.Status
				result.credential = credFrom(record)
				markLastSeen(t.dep.Registry, cred.CredentialID, now)
			}
			return result
		}
		switch transition.Status {
		case credential.TransitionCommitted, credential.TransitionNoChange:
			result.status = transition.Record.Status
			result.credential = credFrom(transition.Record)
			if transition.Status == credential.TransitionCommitted && !adaptivePersistenceFailed {
				result.adaptive = AdaptiveAvailable
			}
		case credential.TransitionConflict:
			// A concurrent writer advanced the revision. Re-read the
			// authoritative record, then retry the same observation once. If
			// the second write loses again, retain the stricter writer's state.
			record, readErr := t.dep.Registry.LookupAuthoritative(ctxForRequest(ctx, requestID), cred.CredentialID)
			if readErr != nil {
				result.adaptive = AdaptiveDegraded
				return result
			}
			retry, retryErr := t.dep.Registry.ObserveAndCommit(
				ctxForRequestWithMetadata(ctx, transitionMeta), cred.CredentialID,
				credentialRisk, hy, now,
			)
			switch {
			case retryErr == nil:
				result.status = retry.Record.Status
				result.credential = credFrom(retry.Record)
				if retry.Status == credential.TransitionCommitted && !adaptivePersistenceFailed {
					result.adaptive = AdaptiveAvailable
				}
			case errors.Is(retryErr, credential.ErrStaleCAS):
				result.status = record.Status
				result.credential = credFrom(record)
			default:
				result.adaptive = AdaptiveDegraded
				result.status = record.Status
				result.credential = credFrom(record)
			}
		case credential.TransitionUnavailable:
			result.adaptive = AdaptiveDegraded
		}
	} else if t.dep.Evidence != nil {
		// Degraded history preserves persisted restrictions and cannot build
		// clean trust upward.
		out.Degraded = true
		result.adaptive = AdaptiveDegraded
	}
	return result
}
