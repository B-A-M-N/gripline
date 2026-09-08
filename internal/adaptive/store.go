// Package adaptive contains the backend-neutral contracts for cross-node
// adaptive observations. It deliberately exposes atomic observations rather
// than whole detector snapshots: a shared authority can merge traffic from
// several nodes without last-writer-wins state loss.
package adaptive

import (
	"context"
	"time"
)

// WindowObservation records one distinct key in a subject's sliding window.
// The authority owns the clock, expiry, cardinality and cooldown decisions.
type WindowObservation struct {
	Detector    string
	Subject     string
	Key         string
	Threshold   int
	Window      time.Duration
	Cooldown    time.Duration
	MaxSubjects int
	MaxKeys     int
}

// BaselineObservation records one value against a subject/metric EMA. A
// non-empty returned string is the producer signal that crossed a threshold.
type BaselineObservation struct {
	Detector        string
	Subject         string
	Metric          string
	Value           float64
	Alpha           float64
	Cooldown        time.Duration
	Threshold4      float64
	Threshold10     float64
	Code4           string
	Code10          string
	AbsoluteFloor   float64
	ConcurrencyRamp bool
}

// Store atomically aggregates bounded adaptive observations across nodes.
type Store interface {
	ObserveWindow(context.Context, WindowObservation) (bool, error)
	ObserveBaseline(context.Context, BaselineObservation) (string, error)
}
