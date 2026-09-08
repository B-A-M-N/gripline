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

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/statepg"
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
