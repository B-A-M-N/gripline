package main

import (
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/observability"
	"github.com/B-A-M-N/gripline/internal/proxy"
)

type demoEvent struct {
	At                  time.Time `json:"at"`
	RequestID           string    `json:"request_id"`
	Actor               string    `json:"actor"`
	SourcePseudonym     string    `json:"source_pseudonym,omitempty"`
	LaneID              string    `json:"lane_id,omitempty"`
	Evidence            []string  `json:"evidence"`
	CredentialRisk      int       `json:"credential_risk"`
	LaneRisk            int       `json:"lane_risk"`
	ObservedConcurrency int       `json:"observed_concurrency"`
	Transition          string    `json:"transition"`
	LimitClass          string    `json:"limit_class"`
	Decision            string    `json:"decision"`
	BackendReached      bool      `json:"backend_reached"`
	AssertionVerified   bool      `json:"assertion_verified"`
}

type demoObserver struct {
	mu     sync.Mutex
	events []*demoEvent
}

func newDemoObserver() *demoObserver { return &demoObserver{} }

func (o *demoObserver) ObserveAdmission(record *observability.DecisionRecord) {
	if record == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	var transitions []string
	if record.CredentialStatusBefore != "" || record.CredentialStatusAfter != "" {
		transitions = append(transitions, "credential:"+record.CredentialStatusBefore+"→"+record.CredentialStatusAfter)
	}
	if record.LaneSecurityBefore != "" || record.LaneSecurityAfter != "" {
		transitions = append(transitions, "lane-security:"+record.LaneSecurityBefore+"→"+record.LaneSecurityAfter)
	}
	limit := record.LimitsClass
	if limit == "" && record.Action == "DENY" {
		limit = "security-deny"
	}
	o.events = append(o.events, &demoEvent{At: record.At, RequestID: record.RequestID,
		SourcePseudonym: record.SourcePseudonym, LaneID: record.LaneID,
		Evidence: append([]string(nil), record.EvidenceCodes...), CredentialRisk: record.CredentialRisk,
		LaneRisk: record.LaneRisk, ObservedConcurrency: record.ObservedConcurrency,
		Transition: strings.Join(transitions, "; "), LimitClass: limit,
		Decision: record.Action + ":" + record.Reason})
}
func (o *demoObserver) ObserveCompletion(proxy.CompletionEvent) {}
func (o *demoObserver) MarkResponse(requestID, actor string, reached, verified bool) {
	if requestID == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := len(o.events) - 1; i >= 0; i-- {
		if o.events[i].RequestID == requestID {
			o.events[i].Actor, o.events[i].BackendReached, o.events[i].AssertionVerified = actor, reached && verified, verified
			return
		}
	}
}
func (o *demoObserver) snapshot() []*demoEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	rows := make([]*demoEvent, len(o.events))
	for i, e := range o.events {
		c := *e
		c.Evidence = append([]string(nil), e.Evidence...)
		rows[i] = &c
	}
	return rows
}
