package main

import (
	"embed"
	"encoding/json"
	"net/http"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

type demoSnapshot struct {
	CredentialFingerprint string            `json:"credential_fingerprint"`
	Baseline              baselineSnapshot  `json:"baseline"`
	Protected             protectedSnapshot `json:"protected"`
	Timeline              []*demoEvent      `json:"timeline"`
	Proof                 demoProof         `json:"proof"`
}
type protectedSnapshot struct {
	LegitimateReached int `json:"legitimate_reached"`
	AttackerReached   int `json:"attacker_reached"`
	AttackerBlocked   int `json:"attacker_blocked"`
	RawAuthorization  int `json:"raw_authorization"`
	RawAPIKey         int `json:"raw_api_key"`
	ValidAssertions   int `json:"valid_assertions"`
	InvalidOrForged   int `json:"invalid_or_forged_assertions"`
	DirectRawRejected int `json:"direct_raw_rejected"`
}
type demoProof struct {
	RealEvidence       bool `json:"real_evidence"`
	SecurityTransition bool `json:"security_transition"`
}

type baselineSnapshot struct {
	LegitimateAccepted int `json:"legitimate_accepted"`
	AttackerAccepted   int `json:"attacker_accepted"`
}

func (s *Scenario) Snapshot() demoSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := demoSnapshot{CredentialFingerprint: s.fingerprint}
	if s.baseStats != nil {
		s.baseStats.mu.Lock()
		out.Baseline.LegitimateAccepted, out.Baseline.AttackerAccepted = s.baseStats.LegitimateAccepted, s.baseStats.AttackerAccepted
		s.baseStats.mu.Unlock()
	}
	if s.backendStats != nil {
		s.backendStats.mu.Lock()
		out.Protected.RawAuthorization, out.Protected.RawAPIKey = s.backendStats.RawAuthorization, s.backendStats.RawAPIKey
		out.Protected.ValidAssertions, out.Protected.InvalidOrForged = s.backendStats.ValidAssertions, s.backendStats.InvalidOrForged
		out.Protected.DirectRawRejected = s.backendStats.DirectRawRejected
		s.backendStats.mu.Unlock()
	}
	if s.obs != nil {
		out.Timeline = s.obs.snapshot()
		for _, e := range out.Timeline {
			if e.Actor == "legit" && e.BackendReached {
				out.Protected.LegitimateReached++
			}
			if e.Actor == "attacker" && e.BackendReached {
				out.Protected.AttackerReached++
			}
			if e.Actor == "attacker" && !e.BackendReached {
				out.Protected.AttackerBlocked++
			}
			for _, code := range e.Evidence {
				if code == "DEMO_ATTACK_SPIKE" || code == "NEW_HOSTING_ASN" {
					out.Proof.RealEvidence = true
				}
			}
			if strings.Contains(e.Transition, "lane-security:") {
				out.Proof.SecurityTransition = true
			}
		}
	}
	return out
}

func (s *Scenario) WebHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, _ := staticFiles.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		name := "static/" + strings.TrimPrefix(r.URL.Path, "/static/")
		data, err := staticFiles.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasSuffix(name, ".js"):
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case strings.HasSuffix(name, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		}
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Snapshot()) })
	mux.HandleFunc("/api/reset", s.control(func() error { return s.Reset() }))
	mux.HandleFunc("/api/run-normal", s.control(func() error { return s.RunNormal() }))
	mux.HandleFunc("/api/steal-key", s.control(func() error { return s.StealKeyAndAttack() }))
	mux.HandleFunc("/api/legit-after-containment", s.control(func() error { return s.LegitAfterContainment() }))
	mux.HandleFunc("/api/run-full", s.control(func() error { return s.RunFullDemo() }))
	mux.HandleFunc("/api/direct-raw", s.control(func() error { return s.DirectRawBackendAttempt() }))
	return mux
}

func (s *Scenario) control(fn func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := fn(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, s.Snapshot())
	}
}
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
