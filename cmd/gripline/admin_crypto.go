package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/ingress"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type cryptoActivationAuthority interface {
	ActivateCryptoGeneration(context.Context, statepg.CryptoActivationRequest) (statepg.CryptoIdentity, error)
}

type cryptoRetirementAuthority interface {
	RetireCryptoGeneration(context.Context, statepg.CryptoRetirementRequest) (statepg.CryptoIdentity, error)
}

type cryptoLifecycleAuthority interface {
	cryptoActivationAuthority
	cryptoRetirementAuthority
	cryptoSynchronizer
}

// adminCryptoActivate is the shared-authority activation half of the crypto
// lifecycle. Secret rings are applied locally only after PostgreSQL commits
// the selected generation. Signer activation is intentionally withheld until
// the deployment supplies a backend verifier-acceptance protocol; activating
// it from an operator-supplied boolean would create a split-brain outage.
func adminCryptoActivate(svc *control.Service, authority cryptoLifecycleAuthority, signer *terminator.Keyring, peppers *credential.PepperRing, pseudonyms ingress.PseudonymRing, signerPath string, acceptor preparedSignerAcceptor) http.HandlerFunc {
	type request struct {
		Kind        string `json:"kind"`
		Generation  int    `json:"generation"`
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		id, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapCryptoLifecycle)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		var req request
		if err := decodeAdminJSON(w, r, &req); err != nil {
			return
		}
		req.Kind = strings.TrimSpace(req.Kind)
		req.Fingerprint = strings.TrimSpace(req.Fingerprint)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.Generation < 1 || req.Fingerprint == "" || req.Reason == "" {
			http.Error(w, "crypto activation requires kind, positive generation, fingerprint, and reason", http.StatusBadRequest)
			return
		}
		operationID := adminOperationID(r)
		if operationID == "" {
			writeAdminError(w, control.ErrOperationIDRequired)
			return
		}
		if authority == nil {
			http.Error(w, "cluster crypto authority unavailable", http.StatusServiceUnavailable)
			return
		}
		local, err := localCryptoIdentity(signer, peppers, pseudonyms)
		if err != nil {
			http.Error(w, "local crypto capability unavailable", http.StatusServiceUnavailable)
			return
		}
		switch req.Kind {
		case statepg.CryptoKindSigner:
			prepared, ok := signer.PreparedKid()
			if !ok || prepared != req.Generation {
				http.Error(w, "requested signer generation is not locally prepared", http.StatusBadRequest)
				return
			}
			if !matchesCryptoGeneration(local, req.Kind, req.Generation, req.Fingerprint) {
				http.Error(w, "requested crypto generation is not loaded with the supplied fingerprint", http.StatusBadRequest)
				return
			}
			if signerPath == "" || acceptor == nil {
				http.Error(w, "signer activation requires backend verifier acceptance and is not configured", http.StatusServiceUnavailable)
				return
			}
			public, ok := signer.Public(req.Generation)
			if !ok {
				http.Error(w, "requested signer generation is not loaded", http.StatusBadRequest)
				return
			}
			if err := acceptor.AcceptPrepared(r.Context(), signer, req.Generation, public); err != nil {
				http.Error(w, "backend verifier rejected signer generation", http.StatusBadGateway)
				return
			}
		case statepg.CryptoKindPepper, statepg.CryptoKindPseudonym:
			// Secret-ring activation is checked against the exact loaded
			// fingerprint below, then committed through the shared authority.
		default:
			http.Error(w, fmt.Sprintf("unknown crypto activation kind %q", req.Kind), http.StatusBadRequest)
			return
		}
		if !matchesCryptoGeneration(local, req.Kind, req.Generation, req.Fingerprint) {
			http.Error(w, "requested crypto generation is not loaded with the supplied fingerprint", http.StatusBadRequest)
			return
		}
		shared, err := authority.ActivateCryptoGeneration(r.Context(), statepg.CryptoActivationRequest{
			Kind: req.Kind, Generation: req.Generation, Fingerprint: req.Fingerprint,
			OperationID: operationID, Actor: id.Name, Reason: req.Reason,
		})
		if err != nil {
			writeAdminError(w, err)
			return
		}
		if err := reconcileClusterCryptoWithSigner(r.Context(), shared, authority, signer, peppers, pseudonyms, signerPath, acceptor); err != nil {
			http.Error(w, "crypto generation activated; local reconciliation pending", http.StatusServiceUnavailable)
			return
		}
		writeAdminJSON(w, map[string]any{
			"kind": req.Kind, "generation": req.Generation, "fingerprint": req.Fingerprint,
			"generation_epoch": shared.GenerationEpoch, "status": "active",
		})
	}
}

// adminCryptoRetire removes a generation only after the authority-owned
// overlap horizon. The shared authority commits first, preventing a
// concurrent activation from selecting the generation while its verifier is
// being retired. Local key material is removed only after the authority
// records retirement.
func adminCryptoRetire(svc *control.Service, authority cryptoLifecycleAuthority, signer *terminator.Keyring, peppers *credential.PepperRing, pseudonyms ingress.PseudonymRing, signerPath string, acceptor preparedSignerAcceptor) http.HandlerFunc {
	type request struct {
		Kind        string    `json:"kind"`
		Generation  int       `json:"generation"`
		Fingerprint string    `json:"fingerprint"`
		NotBefore   time.Time `json:"not_before"`
		Reason      string    `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		id, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapCryptoLifecycle)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		var req request
		if err := decodeAdminJSON(w, r, &req); err != nil {
			return
		}
		req.Kind = strings.TrimSpace(req.Kind)
		req.Fingerprint = strings.TrimSpace(req.Fingerprint)
		req.Reason = strings.TrimSpace(req.Reason)
		operationID := adminOperationID(r)
		if operationID == "" {
			writeAdminError(w, control.ErrOperationIDRequired)
			return
		}
		if req.Generation < 1 || req.Fingerprint == "" || req.Reason == "" {
			http.Error(w, "crypto retirement requires kind, positive generation, fingerprint, and reason", http.StatusBadRequest)
			return
		}
		if req.Kind != statepg.CryptoKindSigner && req.Kind != statepg.CryptoKindPepper && req.Kind != statepg.CryptoKindPseudonym {
			http.Error(w, fmt.Sprintf("unknown crypto retirement kind %q", req.Kind), http.StatusBadRequest)
			return
		}
		if authority == nil {
			http.Error(w, "cluster crypto authority unavailable", http.StatusServiceUnavailable)
			return
		}
		if req.Kind == statepg.CryptoKindSigner {
			if signer.ActiveKid() == req.Generation {
				http.Error(w, "the active signer generation cannot be retired", http.StatusBadRequest)
				return
			}
			if _, ok := acceptor.(signerVerifierRetirer); !ok || signerPath == "" {
				http.Error(w, "signer retirement requires backend verifier control", http.StatusServiceUnavailable)
				return
			}
		}
		shared, err := authority.RetireCryptoGeneration(r.Context(), statepg.CryptoRetirementRequest{
			Kind: req.Kind, Generation: req.Generation, Fingerprint: req.Fingerprint,
			NotBefore: req.NotBefore, OperationID: operationID, Actor: id.Name, Reason: req.Reason,
		})
		if err != nil {
			writeAdminError(w, err)
			return
		}
		if req.Kind == statepg.CryptoKindSigner {
			retirer := acceptor.(signerVerifierRetirer)
			if err := retirer.RetireKey(r.Context(), req.Generation, req.Fingerprint); err != nil {
				http.Error(w, "crypto generation retired; backend verifier retirement pending", http.StatusBadGateway)
				return
			}
		}
		if err := reconcileClusterCryptoWithSigner(r.Context(), shared, authority, signer, peppers, pseudonyms, signerPath, acceptor); err != nil {
			http.Error(w, "crypto generation retired; local reconciliation pending", http.StatusServiceUnavailable)
			return
		}
		writeAdminJSON(w, map[string]any{
			"kind": req.Kind, "generation": req.Generation, "fingerprint": req.Fingerprint,
			"generation_epoch": shared.GenerationEpoch, "status": "retired",
		})
	}
}

func matchesCryptoGeneration(identity statepg.CryptoIdentity, kind string, generation int, fingerprint string) bool {
	for _, loaded := range identity.Loaded {
		if loaded.Kind == kind && loaded.Generation == generation {
			return loaded.Fingerprint == fingerprint
		}
	}
	return false
}
