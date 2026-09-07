// DecisionTrace is the INTERNAL decision record (P0.50): everything an audit
// or replay consumer needs to deterministically reconstruct WHY one admission
// decided what it decided — including for DENIED requests, where the public
// Outcome intentionally carries no principal/context and no assertion (and
// therefore, before P0.51, no policy revision).
//
// It is created inside admission, populated as the pipeline runs, and attached
// to the Outcome as Trace. It carries only safe internal identifiers, enum
// names, scores, evidence ids, and the selected enforcement parameters — never
// a raw credential, header value, or assertion (INV-3). The public
// observability.DecisionRecord remains the external projection; the trace is
// the durable internal source of truth for audit/replay.
package terminator

import (
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
)

type DecisionTrace struct {
	RequestID string `json:"request_id"`
	At        string `json:"at"` // RFC3339; string so the trace is trivially serializable

	// Policy identity — P0.51: stamped DIRECTLY from the compiled policy at
	// decision time, for authorized AND denied requests alike. The assertion
	// (the old revision source) is minted only on authorization, so denied
	// decisions previously reported revision 0 — exactly the decisions audit
	// most needs to attribute to a policy revision.
	PolicyID       string `json:"policy_id"`
	PolicyRevision int    `json:"policy_revision"`

	// Credential state, before → after the observation transaction.
	CredentialID            string `json:"credential_id"`
	AccountID               string `json:"account_id"`
	CredentialStatusBefore  string `json:"credential_status_before"`
	CredentialStatusAfter   string `json:"credential_status_after"`
	CredentialRevBefore     int    `json:"credential_revision_before"`
	CredentialRevAfter      int    `json:"credential_revision_after"`
	CredentialRisk          int    `json:"credential_risk"`
	CredentialSnapshotOK    bool   `json:"credential_snapshot_ok"` // false = evidence outage
	CredentialEvidenceCount int    `json:"credential_evidence_count"`

	// Lane state, before → after the risk observation (trust + security axes,
	// §26/P0.7). For a NEW lane the before-state is the creation state.
	LaneID            string `json:"lane_id"`
	LaneNew           bool   `json:"lane_new"`
	LaneTrustBefore   string `json:"lane_trust_before"`
	LaneTrustAfter    string `json:"lane_trust_after"`
	LaneSecBefore     string `json:"lane_security_before"`
	LaneSecAfter      string `json:"lane_security_after"`
	LaneRevBefore     int    `json:"lane_revision_before"`
	LaneRevAfter      int    `json:"lane_revision_after"`
	LaneRisk          int    `json:"lane_risk"`
	LaneSnapshotOK    bool   `json:"lane_snapshot_ok"`
	LaneEvidenceCount int    `json:"lane_evidence_count"`

	// Source attribution (P0.4): present only when the request carried trusted
	// ingress source identity. SourceRisk is the independently computed
	// source-scoped risk score (BETA-06); source-scoped enforcement rides the
	// SOURCE resource gauge + spray evidence + source-blocked policy gate.
	SourcePseudonym  string `json:"source_pseudonym,omitempty"`
	SourceObserved   bool   `json:"source_observed"`
	SourceRisk       int    `json:"source_risk"`
	SourceBlocked    bool   `json:"source_blocked"`
	SourceSnapshotOK bool   `json:"source_snapshot_ok"`

	// Evidence contributing to the decision: IDs (durable, CSPRNG-derived) and
	// codes. IDs let audit/replay resolve the exact evidence rows — scopes and
	// minting revisions ride the rows themselves.
	EvidenceIDs   []string `json:"evidence_ids"`
	EvidenceCodes []string `json:"evidence_codes"`

	// Enforcement selection + hard-gate result. LimitsClass names the policy
	// limit set selected (normal/constrained/emergency); Reservation reports
	// what the hard gate did with it. Limits echo the selected gauges so replay
	// can recompute the resource decision.
	LimitsClass       string                 `json:"limits_class"`
	Limits            policy.Limits          `json:"limits"`
	ReservationResult string                 `json:"reservation_result"` // granted | denied | none
	ReservationScope  string                 `json:"reservation_scope,omitempty"`
	Estimate          resource.UsageEstimate `json:"usage_estimate"`

	// Adaptive posture + WHY it degraded (P0.1/P0.50): a degraded decision must
	// be explainable as degraded, not silently read as clean.
	Adaptive       AdaptiveStateStatus `json:"adaptive"`
	DegradedReason string              `json:"degraded_reason,omitempty"`

	Authorized bool   `json:"authorized"`
	Reason     string `json:"reason"`
}

// TrimEvidence caps the trace's evidence lists so a pathological snapshot
// (bounded at 2048 rows/subject) cannot bloat every decision record. The cap
// is an audit-sizing bound, not a scoring input; counts above the cap remain
// accurate via the *EvidenceCount fields.
func (dt *DecisionTrace) TrimEvidence(max int) {
	if dt == nil {
		return
	}
	if max <= 0 {
		max = defaultTraceEvidenceCap
	}
	dt.EvidenceIDs = trimStrings(dt.EvidenceIDs, max)
	dt.EvidenceCodes = trimStrings(dt.EvidenceCodes, max)
}

// defaultTraceEvidenceCap keeps one decision's trace comfortably below a
// typical log-line budget while still carrying the full contributor set for
// any realistic admission (thresholds + family caps bound real contributors).
const defaultTraceEvidenceCap = 64

func trimStrings(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	out := make([]string, max)
	copy(out, in[:max])
	return out
}

var (
	_ = credential.StatusWatch
	_ = lane.LaneNormal
	_ = policy.Limits{}
	_ = resource.UsageEstimate{}
)
