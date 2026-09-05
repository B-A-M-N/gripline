// Package observability turns admission outcomes into machine-readable,
// credential-safe decision records (§97, §111 Gate A / INV-2).
//
// A DecisionRecord is the durable, explainable answer to "what changed, why,
// under which policy revision, at what scope" for one admission. It is derived
// ONLY from the terminator's Outcome — which already has zero raw-credential
// surfaces — and is shaped for audit, tracing, and operator investigation.
package observability

import (
	"encoding/json"
	"time"

	"github.com/B-A-M-N/gripline/internal/terminator"
)

// DecisionRecord is one admission's machine-readable explanation (§97). No
// field can hold a raw external credential; identity is via pseudonymous
// internal IDs and credentials are keyed by internal CredentialID only
// (INV-2). Risk scores and evidence codes are safe, non-secret security state.
type DecisionRecord struct {
	// RequestID ties together proxy, resource, security, and audit events; it is
	// globally unique and encodes none of credential/account/IP/prompt (§71).
	RequestID string `json:"request_id"`
	// At is when the decision was made.
	At       time.Time `json:"at"`
	Action   string    `json:"action"`    // "AUTHORIZE" | "AUTHORIZE_DEGRADED" | "DENY"
	Reason   string    `json:"reason"`    // safe, non-secret reason (e.g. "lane_restricted")
	Authorized bool     `json:"authorized"`
	// Degraded records an AdaptiveDegraded posture: some authoritative history or
	// state was unavailable, so the decision preserved persisted restrictions
	// rather than transitioning (P0.1) — a reader must not treat RiskAfter as a
	// freshly-observed score in that case.
	Degraded bool `json:"degraded"`

	Principal     drPrincipal `json:"principal"`
	Scope         string    `json:"authorization_scope"` // LANE / CREDENTIAL / ...
	LaneState     string    `json:"lane_state"`          // NEW / PROBATION / ESTABLISHED / ...
	RiskBefore    int       `json:"risk_before"`
	RiskAfter     int       `json:"risk_after"`
	LaneNew       bool      `json:"lane_new"`
	EvidenceCodes []string  `json:"evidence"` // evidence codes that contributed
	PolicyRevision int      `json:"policy_revision"`
}

// drPrincipal is the minimal, credential-safe principal projection.
type drPrincipal struct {
	AccountID    string `json:"account_id"`
	CredentialID string `json:"credential_id"` // internal, pseudonymous-ish ID
	PolicyID     string `json:"policy_id"`
}

// New builds a DecisionRecord from a terminator admission Outcome. It is a pure
// projection: it reads only exported, already-safe Outcome fields and never
// touches the raw credential or assertion. It never fails on its own.
//
// RiskBefore isn't carried on Outcome for denied/unauthorized admissions (risk
// is computed in the authorization path); callers that want a precise before
// value must capture the credential's prior persisted risk separately. New
// records the Outcome.RiskAfter as RiskAfter and leaves RiskBefore at the
// caller-provided value (0 default) for the degraded/denied short path.
func New(out *terminator.Outcome) *DecisionRecord {
	if out == nil {
		return &DecisionRecord{Action: "DENY", Reason: "nil_outcome"}
	}
	dr := &DecisionRecord{
		RequestID:    out.RequestID,
		At:           time.Now().UTC(),
		Reason:       out.Reason,
		Authorized:   out.Authorized,
		Degraded:     out.Degraded,
		RiskAfter:    out.RiskAfter,
		EvidenceCodes: out.Evidence,
		LaneNew:      out.LaneNew,
		Action:       "AUTHORIZE",
	}
	if !out.Authorized {
		dr.Action = "DENY"
	} else if out.Degraded {
		dr.Action = "AUTHORIZE_DEGRADED"
	}
	dr.Principal = drPrincipal{
		AccountID:    out.Principal.AccountID,
		CredentialID: out.Principal.CredentialID,
		PolicyID:     out.Principal.PolicyID,
	}
	dr.Scope = string(out.Context.AuthorizationScope)
	dr.LaneState = out.Context.LaneState
	dr.PolicyRevision = policyRevisionOf(out)
	return dr
}

// policyRevisionOf returns the compiled policy revision when the context or an
// assertion carries it, else 0. The assertion (issued only on authorization)
// embeds PolicyRev in its claims; it is the authoritative compiled-revision
// stamp.
func policyRevisionOf(out *terminator.Outcome) int {
	if out.Assertion != nil {
		return out.Assertion.Claims().PolicyRev
	}
	return 0
}

// JSON marshals the record. It is the canonical credential-safe serialization
// used by audit/trace sinks (§97).
func (d *DecisionRecord) JSON() ([]byte, error) {
	return json.Marshal(d)
}