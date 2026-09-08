package terminator

import (
	"context"
	"errors"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/principal"
	"github.com/B-A-M-N/gripline/internal/resource"
)

// resourceAdmission owns the hard multi-scope gate independently from the
// credential/evidence/lane pipeline. Keeping this state in a small operation
// object makes the reservation contract explicit and keeps Terminator's main
// admission method focused on sequencing security decisions.
type resourceAdmission struct {
	term           *Terminator
	requestCtx     context.Context
	cred           *credential.Credential
	laneID         string
	limits         policy.Limits
	authCtx        principal.AuthorizedContext
	requestID      string
	out            *Outcome
	adaptive       AdaptiveStateStatus
	laneRisk       int
	credentialRisk int
	effectiveRisk  int
	evidenceCodes  []string
	source         TrustedSource
	estimate       resource.UsageEstimate
	trace          *DecisionTrace
}

// run provisions SOURCE/LANE/CREDENTIAL/ACCOUNT capacity all-or-nothing,
// issues the internal assertion while the reservation is held, and attaches
// the backend-neutral lifecycle handle to the outcome. A non-nil outcome
// short-circuits admission; nil means the gate passed.
func (a resourceAdmission) run() *Outcome {
	t := a.term
	// P0.35: the selected limits' per-dimension gauges (requests/tokens/cost)
	// ride EVERY scope's spec. Zero-capacity gauges are inert at every scope.
	gauges := resourceSpec(a.limits)
	// Precedence order is the resource.Scope enum: SOURCE → ACCOUNT →
	// CREDENTIAL → LANE, GLOBAL last as the whole-plane gauge. The SOURCE scope
	// keys on this request's pseudonym; an unknown source is not collapsed into
	// a shared process-global bucket.
	specs := []resource.ScopeSpec{}
	if a.source.sourceID() != "" {
		specs = append(specs, resource.ScopeSpec{Scope: resource.ScopeSource, ID: a.source.sourceID(), Buckets: gauges})
	}
	specs = append(specs,
		resource.ScopeSpec{Scope: resource.ScopeAccount, ID: a.cred.AccountID, Buckets: gauges},
		resource.ScopeSpec{Scope: resource.ScopeCredential, ID: a.cred.CredentialID, Buckets: gauges},
	)
	if a.laneID != "" {
		specs = append(specs, resource.ScopeSpec{Scope: resource.ScopeLane, ID: a.laneID, Buckets: gauges})
	}
	global := resourceSpec(t.pol.Global)
	if resourceSpecEnabled(global) {
		specs = append(specs, resource.ScopeSpec{Scope: resource.ScopeGlobal, ID: "fleet", Buckets: global})
	}

	deny := func(reason string, err error) *Outcome {
		a.out.Authorized = false
		a.out.Reason = reason
		a.out.DenialErr = err
		a.out.CredentialRisk = a.credentialRisk
		a.out.LaneRisk = a.laneRisk
		a.out.RiskAfter = a.effectiveRisk
		a.out.Evidence = a.evidenceCodes
		a.out.Adaptive = a.adaptive
		a.out.Degraded = a.adaptive == AdaptiveDegraded
		return a.out
	}

	reservation, err := t.dep.Resource.Reserve(a.requestCtx, resource.ReserveRequest{
		RequestID: a.requestID,
		Scopes:    specs,
		Estimate:  a.estimate,
	})
	if err != nil {
		a.trace.ReservationResult = "denied"
		if errors.Is(err, resource.ErrSourceScopeSaturated) {
			return deny("resource_unavailable", err)
		}
		var sle *resource.ScopeLimitError
		if errors.As(err, &sle) {
			a.trace.ReservationScope = sle.Scope.String()
			a.trace.ReservationDimension = sle.Dimension.String()
			return deny("rate_limit", err)
		}
		return deny("resource_unavailable", err)
	}
	if reservation == nil {
		a.trace.ReservationResult = "unavailable"
		return deny("resource_unavailable", errors.New("terminator: resource authority returned no reservation"))
	}
	a.trace.ReservationResult = "granted"
	assertion, assertionErr := t.issueAssertion(a.authCtx, a.requestID, a.cred)
	if assertionErr != nil {
		reservation.Release()
		return deny("internal_identity_failure", assertionErr)
	}
	a.out.Assertion = assertion
	a.out.ResourceReservation = reservation
	if local, ok := reservation.(*resource.MultiReservation); ok {
		// Compatibility fields for legacy in-process callers. New code uses the
		// backend-neutral ResourceReservation handle above.
		a.out.ResourceRes = local
		a.out.UsageRes = local
	}
	return nil
}
