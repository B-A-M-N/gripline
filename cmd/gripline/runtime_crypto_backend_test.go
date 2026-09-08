package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

func TestHTTPVerifierControlPublishesAndVerifiesPreparedSigner(t *testing.T) {
	signer, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := signer.Save(path); err != nil {
		t.Fatal(err)
	}
	candidate, err := signer.PrepareRotation(path)
	if err != nil {
		t.Fatal(err)
	}
	const audience = "verifier-control-test"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body verifierControlRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if body.Action != "publish" || body.Protocol != verifierControlProtocol || body.KID != candidate.KID {
			http.Error(w, "bad protocol", http.StatusBadRequest)
			return
		}
		public, err := base64.StdEncoding.DecodeString(body.PublicKey)
		if err != nil || string(public) != string(candidate.PublicKey) {
			http.Error(w, "bad public key", http.StatusBadRequest)
			return
		}
		r.Header.Set("X-Gripline-Assertion", body.CanaryAssertion)
		if _, err := signer.Verify(body.CanaryAssertion, audience, time.Now()); err != nil {
			http.Error(w, "bad canary", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	control, err := newHTTPVerifierControl(&config.Config{
		Identity: config.IdentitySection{Audience: audience},
		Backend:  config.BackendSection{URL: server.URL, VerifierControlURL: server.URL},
	}, server.Client().Transport, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.AcceptPrepared(context.Background(), signer, candidate.KID, candidate.PublicKey); err != nil {
		t.Fatal(err)
	}
}
