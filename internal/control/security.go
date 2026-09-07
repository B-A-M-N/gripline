package control

import "time"

// SecurityTransitionRecord is the append-only durable record for automatic
// credential and lane security changes. It is separate from operator audit so
// an incident review can distinguish machine transitions from human actions.
// All fields are credential-safe; request ids correlate to ingress decisions,
// never to raw secrets.
type SecurityTransitionRecord struct {
	Sequence       uint64    `json:"sequence"`
	At             time.Time `json:"at"`
	Kind           string    `json:"kind"` // credential_status | lane_security | lane_trust
	RequestID      string    `json:"request_id,omitempty"`
	CredentialID   string    `json:"credential_id,omitempty"`
	LaneID         string    `json:"lane_id,omitempty"`
	Before         string    `json:"before"`
	After          string    `json:"after"`
	RiskScore      int       `json:"risk_score,omitempty"`
	Revision       int       `json:"revision"`
	PolicyRevision int       `json:"policy_revision,omitempty"`
	EvidenceCodes  []string  `json:"evidence_codes,omitempty"`
}

// SecurityTransitionReader is the authenticated read surface for automatic
// security-transition history.
type SecurityTransitionReader interface {
	ListSecurityTransitions(after uint64, limit int) ([]SecurityTransitionRecord, error)
}
