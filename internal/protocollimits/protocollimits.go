// Package protocollimits contains security protocol bounds shared by the
// issuer, verifier, and authority rotation code.
package protocollimits

import "time"

const (
	MaxAssertionTTL         = 30 * time.Second
	AssertionClockSkew      = 5 * time.Second
	SignerRetirementHorizon = MaxAssertionTTL + AssertionClockSkew
)
