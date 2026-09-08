package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type adminPolicySnapshot struct {
	ID              string `json:"id"`
	Revision        int    `json:"revision"`
	Digest          string `json:"digest"`
	ActivationEpoch uint64 `json:"activation_epoch,omitempty"`
}

func adminPolicySnapshotOf(compiled *policy.CompiledPolicy) *adminPolicySnapshot {
	return adminPolicySnapshotOfWithEpoch(compiled, 0)
}

func adminPolicySnapshotOfWithEpoch(compiled *policy.CompiledPolicy, epoch uint64) *adminPolicySnapshot {
	if compiled == nil {
		return nil
	}
	digest, err := policy.Digest(&compiled.Policy)
	if err != nil {
		return nil
	}
	return &adminPolicySnapshot{ID: compiled.ID, Revision: compiled.Revision, Digest: digest, ActivationEpoch: epoch}
}

// adminPolicyStatus exposes only immutable policy identity metadata. The
// artifact itself is not echoed back through the control plane.
func adminPolicyStatus(svc *control.Service, manager *policy.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapPolicyInstall); err != nil {
			writeAdminError(w, err)
			return
		}
		if err := manager.Reconcile(r.Context()); err != nil {
			writePolicyAdminError(w, err)
			return
		}
		active := manager.Snapshot()
		var activeView *adminPolicySnapshot
		if active != nil {
			activeView = adminPolicySnapshotOfWithEpoch(active.Policy, active.ActivationEpoch)
		}
		writeAdminJSON(w, map[string]any{
			"active":    activeView,
			"candidate": adminPolicySnapshotOf(manager.Candidate()),
		})
	}
}

func adminPolicyPrepare(svc *control.Service, manager *policy.Manager, verifier ed25519.PublicKey) http.HandlerFunc {
	type request struct {
		Artifact json.RawMessage `json:"artifact"`
		Reason   string          `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		id, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapPolicyInstall)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		var body request
		if err := decodeAdminJSONLimit(w, r, &body, 4<<20); err != nil {
			return
		}
		if strings.TrimSpace(body.Reason) == "" {
			writeAdminError(w, control.ErrReasonRequired)
			return
		}
		if len(verifier) != ed25519.PublicKeySize {
			http.Error(w, "policy verifier unavailable", http.StatusServiceUnavailable)
			return
		}
		compiled, err := policy.LoadAuthenticated(body.Artifact, verifier)
		if err != nil {
			writePolicyAdminError(w, err)
			return
		}
		prepared, err := manager.PrepareByContext(r.Context(), &compiled.Policy, id.Name, body.Reason)
		if err != nil {
			writePolicyAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]any{"prepared": adminPolicySnapshotOf(prepared)})
	}
}

func adminPolicyActivate(svc *control.Service, manager *policy.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		id, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapPolicyInstall)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeAdminJSON(w, r, &body); err != nil {
			return
		}
		if strings.TrimSpace(body.Reason) == "" {
			writeAdminError(w, control.ErrReasonRequired)
			return
		}
		if err := manager.ActivateByContext(r.Context(), body.Reason, id.Name); err != nil {
			writePolicyAdminError(w, err)
			return
		}
		active := manager.Snapshot()
		if active == nil {
			writeAdminJSON(w, map[string]any{"active": nil})
			return
		}
		writeAdminJSON(w, map[string]any{"active": adminPolicySnapshotOfWithEpoch(active.Policy, active.ActivationEpoch)})
	}
}

func adminPolicyRollback(svc *control.Service, manager *policy.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		id, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapPolicyInstall)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		var body struct {
			Revision int    `json:"revision"`
			Reason   string `json:"reason"`
		}
		if err := decodeAdminJSON(w, r, &body); err != nil {
			return
		}
		if body.Revision < 1 || strings.TrimSpace(body.Reason) == "" {
			writePolicyAdminError(w, errors.New("policy rollback requires a positive revision and reason"))
			return
		}
		if err := manager.RollbackByContext(r.Context(), body.Revision, body.Reason, id.Name); err != nil {
			writePolicyAdminError(w, err)
			return
		}
		active := manager.Snapshot()
		if active == nil {
			writeAdminJSON(w, map[string]any{"active": nil})
			return
		}
		writeAdminJSON(w, map[string]any{"active": adminPolicySnapshotOfWithEpoch(active.Policy, active.ActivationEpoch)})
	}
}

func writePolicyAdminError(w http.ResponseWriter, err error) {
	if errors.Is(err, control.ErrUnauthenticated) || errors.Is(err, control.ErrUnauthorized) || errors.Is(err, control.ErrReasonRequired) {
		writeAdminError(w, err)
		return
	}
	http.Error(w, "policy action rejected", http.StatusBadRequest)
}

func adminPosture(svc *control.Service) http.HandlerFunc {
	type body struct {
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var b body
		if err := decodeAdminJSON(w, r, &b); err != nil {
			return
		}
		token := bearer(r.Header.Get("Authorization"))
		posture, err := svc.SetEmergencyWithOperationID(r.Context(), token, b.On, b.Reason, adminOperationID(r))
		if err != nil {
			writeAdminError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"posture": posture.String()})
	}
}

func adminCredentials(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapCredentialLifecycle); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		rows, err := state.ListCredentials()
		if err != nil {
			http.Error(w, "credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		writeAdminJSON(w, rows)
	}
}

func adminCredentialRevoke(svc *control.Service) http.HandlerFunc {
	type request struct {
		CredentialID string `json:"credential_id"`
		Reason       string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		var req request
		if err := decodeAdminJSON(w, r, &req); err != nil {
			return
		}
		if req.CredentialID == "" || req.Reason == "" {
			http.Error(w, "credential_id and reason are required", http.StatusBadRequest)
			return
		}
		if err := svc.RevokeCredentialWithOperationID(r.Context(), bearer(r.Header.Get("Authorization")), req.CredentialID, req.Reason, adminOperationID(r)); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "status": "REVOKED"})
	}
}

func adminCredentialAdd(svc *control.Service, state adminStateAuthority, peppers *credential.PepperRing, policyManager *policy.Manager, cryptoAuthority *statepg.Store) http.HandlerFunc {
	type request struct {
		CredentialID    string `json:"credential_id"`
		AccountID       string `json:"account_id"`
		PolicyID        string `json:"policy_id"`
		PlanID          string `json:"plan_id"`
		VerifierB64     string `json:"verifier_b64"`
		VerifierVersion int    `json:"verifier_version"`
		PepperVersion   int    `json:"pepper_version"`
		Reason          string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		var req request
		if err := decodeAdminJSON(w, r, &req); err != nil {
			return
		}
		if state == nil {
			http.Error(w, "persistent credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		if req.CredentialID == "" || req.AccountID == "" || req.PlanID == "" || req.VerifierB64 == "" || req.Reason == "" {
			http.Error(w, "credential_id, account_id, plan_id, verifier_b64, and reason are required", http.StatusBadRequest)
			return
		}
		if policyManager == nil {
			http.Error(w, "policy authority unavailable", http.StatusServiceUnavailable)
			return
		}
		// Provisioning is a control-plane mutation, but its policy binding is
		// still security authority. Reconcile before accepting a caller-supplied
		// id so a stale operator config cannot create a credential that
		// immediately fails admission.
		activePolicy, err := activeCredentialPolicy(r.Context(), policyManager, req.PolicyID)
		if err != nil {
			if errors.Is(err, errCredentialPolicyInactive) {
				http.Error(w, err.Error(), http.StatusBadRequest)
			} else {
				http.Error(w, "policy authority unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		req.PolicyID = activePolicy
		verifier, err := base64.StdEncoding.DecodeString(req.VerifierB64)
		if err != nil || len(verifier) == 0 {
			http.Error(w, "verifier_b64 must be valid base64", http.StatusBadRequest)
			return
		}
		defer func() {
			for i := range verifier {
				verifier[i] = 0
			}
		}()
		if req.VerifierVersion == 0 {
			req.VerifierVersion = 1
		}
		activePepperVersion, err := activeCredentialPepperVersion(r.Context(), peppers, cryptoAuthority)
		if err != nil {
			http.Error(w, "verifier pepper authority unavailable", http.StatusServiceUnavailable)
			return
		}
		if req.PepperVersion == 0 {
			req.PepperVersion = activePepperVersion
		} else if req.PepperVersion != activePepperVersion {
			http.Error(w, "pepper_version must match the active cluster generation", http.StatusBadRequest)
			return
		}
		rec := credential.CredentialRecord{
			CredentialID: req.CredentialID, AccountID: req.AccountID, Verifier: verifier,
			VerifierVersion: req.VerifierVersion, PepperVersion: req.PepperVersion,
			Status: credential.StatusNormal, PolicyID: req.PolicyID, PlanID: req.PlanID,
			CreatedAt: time.Now().UTC(), Revision: 1,
		}
		if err := svc.ProvisionCredentialWithOperationID(r.Context(), bearer(r.Header.Get("Authorization")), rec, req.Reason, adminOperationID(r)); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "status": "ACTIVE"})
	}
}

func adminCredentialPepperStatus(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapCredentialLifecycle); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		counts, err := state.CountCredentialsByPepperVersion()
		if err != nil {
			http.Error(w, "credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		writeAdminJSON(w, counts)
	}
}

func adminLanes(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapLaneLifecycle); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent lane authority unavailable", http.StatusServiceUnavailable)
			return
		}
		credentialID := r.URL.Query().Get("credential")
		if credentialID == "" {
			http.Error(w, "credential query parameter is required", http.StatusBadRequest)
			return
		}
		rows, err := state.ListLaneRecords(credentialID)
		if err != nil {
			http.Error(w, "lane authority unavailable", http.StatusServiceUnavailable)
			return
		}
		type summary struct {
			LaneID       string    `json:"lane_id"`
			CredentialID string    `json:"credential_id"`
			State        string    `json:"state"`
			Security     string    `json:"security_state"`
			RiskScore    int       `json:"risk_score"`
			RequestCount int64     `json:"request_count"`
			LastSeenAt   time.Time `json:"last_seen_at"`
			Revision     int       `json:"revision"`
		}
		out := make([]summary, 0, len(rows))
		for _, row := range rows {
			out = append(out, summary{
				LaneID: row.LaneID, CredentialID: row.CredentialID, State: row.State.String(),
				Security: row.Security.Status.String(), RiskScore: row.RiskScore,
				RequestCount: row.RequestCount, LastSeenAt: row.LastSeenAt.UTC(), Revision: row.Revision,
			})
		}
		writeAdminJSON(w, out)
	}
}

func adminLaneUnblock(svc *control.Service) http.HandlerFunc {
	type request struct {
		CredentialID string `json:"credential_id"`
		LaneID       string `json:"lane_id"`
		Reason       string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		var req request
		if err := decodeAdminJSON(w, r, &req); err != nil {
			return
		}
		if req.CredentialID == "" || req.LaneID == "" || req.Reason == "" {
			http.Error(w, "credential_id, lane_id, and reason are required", http.StatusBadRequest)
			return
		}
		if err := svc.UnblockLaneWithOperationID(r.Context(), bearer(r.Header.Get("Authorization")), req.CredentialID, req.LaneID, req.Reason, adminOperationID(r)); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "lane_id": req.LaneID, "status": "NORMAL"})
	}
}

func adminAudit(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapAuditRead); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent audit authority unavailable", http.StatusServiceUnavailable)
			return
		}
		after := uint64(0)
		if raw := r.URL.Query().Get("after"); raw != "" {
			var err error
			after, err = strconv.ParseUint(raw, 10, 64)
			if err != nil {
				http.Error(w, "invalid after cursor", http.StatusBadRequest)
				return
			}
		}
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var err error
			limit, err = strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 1000 {
				http.Error(w, "invalid limit", http.StatusBadRequest)
				return
			}
		}
		rows, err := state.ListOperatorAudit(after, limit)
		if err != nil {
			http.Error(w, "audit authority unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(rows) > 0 {
			w.Header().Set("X-Gripline-Next-Audit-After", strconv.FormatUint(rows[len(rows)-1].Sequence, 10))
		}
		w.Header().Set("X-Gripline-Audit-Has-More", strconv.FormatBool(len(rows) == limit))
		writeAdminJSON(w, rows)
	}
}

func adminSecurityEvents(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapAuditRead); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent security audit authority unavailable", http.StatusServiceUnavailable)
			return
		}
		after, limit, err := auditCursor(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rows, err := state.ListSecurityTransitions(after, limit)
		if err != nil {
			http.Error(w, "security audit authority unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(rows) > 0 {
			w.Header().Set("X-Gripline-Next-Audit-After", strconv.FormatUint(rows[len(rows)-1].Sequence, 10))
		}
		w.Header().Set("X-Gripline-Audit-Has-More", strconv.FormatBool(len(rows) == limit))
		writeAdminJSON(w, rows)
	}
}

func adminMetrics(svc *control.Service, dp *proxy.DataPlane, governor resource.Authority, state *statebolt.Store, postgres *statepg.Store, spray *anomaly.Detector, observer *jsonlObserver, policyManager *policy.Manager, signer *terminator.Keyring, adaptiveHealth []terminator.AdaptivePersistenceHealth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapAuditRead); err != nil {
			writeAdminError(w, err)
			return
		}
		var b strings.Builder
		writeMetric := func(name string, value any) { fmt.Fprintf(&b, "gripline_%s %v\n", name, value) }
		if dp != nil {
			m := dp.Metrics()
			writeMetric("admissions_total", m.Admissions)
			writeMetric("authorizations_total", m.Authorizations)
			writeMetric("denials_total", m.Denials)
			writeMetric("authentication_failures_total", m.AuthenticationFail)
			writeMetric("degraded_decisions_total", m.Degraded)
			writeMetric("resource_denials_total", m.ResourceDenials)
			writeMetric("policy_denials_total", m.PolicyDenials)
			writeMetric("payload_too_large_total", m.PayloadTooLarge)
			writeMetric("spool_rejects_total", m.SpoolRejects)
			writeMetric("completion_failures_total", m.CompletionFailures)
			writeMetric("backend_failures_total", m.BackendFailures)
			writeMetric("backend_4xx_total", m.Backend4xx)
			writeMetric("backend_5xx_total", m.Backend5xx)
			writeMetric("active_streams", m.ActiveStreams)
			writeMetric("evidence_events_total", m.EvidenceEvents)
			for i, count := range m.ResourceDenialsByScope {
				writeMetric("resource_denials_scope_"+strings.ToLower(resource.Scope(i).String())+"_total", count)
			}
			for i, count := range m.ResourceDenialsByDimension {
				writeMetric("resource_denials_dimension_"+resource.Dimension(i).String()+"_total", count)
			}
			writeMetric("spool_bytes", m.Spool.Bytes)
			writeMetric("spool_files", m.Spool.Files)
			writeMetric("spool_max_bytes", m.Spool.MaxBytes)
			writeMetric("spool_max_files", m.Spool.MaxFiles)
		}
		if stats, ok := governor.(interface{ Stats() resource.GovernorStats }); ok {
			m := stats.Stats()
			writeMetric("source_scopes", m.SourceScopes)
			writeMetric("source_scope_saturations_total", m.SourceSaturations)
			writeMetric("source_scope_overflows_total", m.SourceOverflows)
			writeMetric("source_scope_evictions_total", m.SourceEvictions)
		}
		if statsAuthority, ok := governor.(resource.ContextStatsAuthority); ok {
			if m, err := statsAuthority.StatsContext(r.Context()); err == nil {
				writeMetric("resource_stats_available", 1)
				writeMetric("resource_active_concurrency", m.ActiveConcurrency)
				writeMetric("resource_active_leases", m.ActiveLeases)
				writeMetric("resource_forwarded_leases", m.ForwardedLeases)
				writeMetric("resource_settled_leases", m.SettledLeases)
				writeMetric("resource_released_leases", m.ReleasedLeases)
				writeMetric("resource_active_holds", m.ActiveHolds)
				writeMetric("resource_source_scopes", m.SourceScopes)
				writeMetric("resource_source_overflows", m.SourceOverflows)
			} else {
				writeMetric("resource_stats_available", 0)
			}
		}
		if policyManager != nil {
			if current := policyManager.Current(); current != nil {
				writeMetric("active_policy_revision", current.Revision)
			}
		}
		if signer != nil {
			writeMetric("active_signer_kid", signer.ActiveKid())
		}
		if state != nil {
			m := state.EvidenceSweepStats()
			writeMetric("evidence_sweep_scanned_total", m.Scanned)
			writeMetric("evidence_sweep_deleted_total", m.Deleted)
			tx := state.TransactionStats()
			writeMetric("bbolt_transactions_total", tx.Transactions)
			writeMetric("bbolt_transaction_errors_total", tx.TransactionErrors)
			writeMetric("bbolt_transaction_nanos_total", tx.TransactionNanos)
		}
		if postgres != nil {
			m := postgres.PoolStats()
			writeMetric("postgres_pool_total_conns", m.TotalConns)
			writeMetric("postgres_pool_idle_conns", m.IdleConns)
			writeMetric("postgres_pool_acquired_conns", m.AcquiredConns)
			writeMetric("postgres_pool_constructing_conns", m.ConstructingConns)
			writeMetric("postgres_pool_max_conns", m.MaxConns)
			writeMetric("postgres_pool_acquires_total", m.AcquireCount)
			writeMetric("postgres_pool_acquire_duration_seconds", m.AcquireDuration.Seconds())
			writeMetric("postgres_pool_empty_acquires_total", m.EmptyAcquireCount)
			writeMetric("postgres_pool_empty_acquire_wait_seconds", m.EmptyAcquireWait.Seconds())
			writeMetric("postgres_pool_canceled_acquires_total", m.CanceledAcquireCount)
			a := postgres.Metrics()
			writeMetric("postgres_transaction_attempts_total", a.TransactionAttempts)
			writeMetric("postgres_transaction_errors_total", a.TransactionErrors)
			writeMetric("postgres_transaction_latency_seconds_total", a.TransactionLatency.Seconds())
			writeMetric("postgres_serialization_retries_total", a.SerializationRetries)
			writeMetric("postgres_deadlock_retries_total", a.DeadlockRetries)
			writeMetric("postgres_reservation_attempts_total", a.ReservationAttempts)
			writeMetric("postgres_reservations_granted_total", a.ReservationsGranted)
			writeMetric("postgres_reservation_failures_total", a.ReservationFailures)
			writeMetric("postgres_reservation_latency_seconds_total", a.ReservationLatency.Seconds())
			writeMetric("postgres_forward_attempts_total", a.ForwardAttempts)
			writeMetric("postgres_forwarded_total", a.Forwarded)
			writeMetric("postgres_forward_failures_total", a.ForwardFailures)
			writeMetric("postgres_lease_renewal_attempts_total", a.LeaseRenewalAttempts)
			writeMetric("postgres_leases_renewed_total", a.LeasesRenewed)
			writeMetric("postgres_lease_renewal_failures_total", a.LeaseRenewalFailures)
			writeMetric("postgres_settlement_attempts_total", a.SettlementAttempts)
			writeMetric("postgres_settlements_total", a.Settlements)
			writeMetric("postgres_settlement_failures_total", a.SettlementFailures)
			writeMetric("postgres_expired_leases_total", a.ExpiredLeases)
			writeMetric("postgres_forwarded_unsettled_consumed_total", a.ForwardedUnsettledConsumed)
			writeMetric("postgres_release_failures_total", a.ReleaseFailures)
		}
		if spray != nil {
			writeMetric("detector_drops_total", spray.Stats().Dropped)
		}
		adaptiveHealthy := 1
		for _, health := range adaptiveHealth {
			if health != nil && health.PersistenceError() != nil {
				adaptiveHealthy = 0
				break
			}
		}
		writeMetric("adaptive_persistence_healthy", adaptiveHealthy)
		if observer != nil {
			m := observer.Stats()
			writeMetric("telemetry_drops_total", m.Dropped)
			writeMetric("telemetry_sink_failures_total", m.SinkFailures)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	}
}

func auditCursor(r *http.Request) (uint64, int, error) {
	after := uint64(0)
	if raw := r.URL.Query().Get("after"); raw != "" {
		var err error
		after, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid after cursor")
		}
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 1000 {
			return 0, 0, fmt.Errorf("invalid limit")
		}
	}
	return after, limit, nil
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return decodeAdminJSONLimit(w, r, dst, 4096)
}

func decodeAdminJSONLimit(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		http.Error(w, "bad request", http.StatusBadRequest)
		if err == nil {
			err = errors.New("admin JSON must be one object")
		}
		return err
	}
	obj := json.NewDecoder(bytes.NewReader(raw))
	obj.DisallowUnknownFields()
	if err := obj.Decode(dst); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return err
	}
	return nil
}

func writeAdminJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func adminMethodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func writeAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, control.ErrUnauthenticated):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, control.ErrUnauthorized):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, control.ErrReasonRequired):
		http.Error(w, "reason required", http.StatusBadRequest)
	case errors.Is(err, control.ErrOperationIDRequired), errors.Is(err, control.ErrOperationIDInvalid):
		http.Error(w, "valid Idempotency-Key required", http.StatusBadRequest)
	case errors.Is(err, control.ErrOperationConflict):
		http.Error(w, "Idempotency-Key was already used for another operation", http.StatusConflict)
	case errors.Is(err, control.ErrOperationIDUnsupported):
		http.Error(w, "idempotency authority unavailable", http.StatusServiceUnavailable)
	case errors.Is(err, credential.ErrNotFound), errors.Is(err, lane.ErrLaneNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		http.Error(w, "operator action failed", http.StatusInternalServerError)
	}
}

func bearer(h string) string {
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(rest)
}

// adminOperationID returns the client-owned replay key for a mutating admin
// request. PostgreSQL-backed services require this header before making a
// state change; standalone services keep legacy behavior when it is absent.
func adminOperationID(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("Idempotency-Key"))
}

func parseSpec(spec string) (string, []string, error) {
	name, caps, ok := strings.Cut(spec, ":")
	if !ok {
		return "", nil, fmt.Errorf("spec must be \"name:cap1,cap2\"")
	}
	var out []string
	for _, c := range strings.Split(caps, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return strings.TrimSpace(name), out, nil
}
