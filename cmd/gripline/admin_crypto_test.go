package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type cryptoAdminAuth struct{ identity *control.Identity }

func (a cryptoAdminAuth) Authenticate(context.Context, string) (*control.Identity, error) {
	return a.identity, nil
}

type cryptoAdminAudit struct{}

func (cryptoAdminAudit) AppendOperator(context.Context, control.OperatorRecord) error { return nil }

type cryptoAdminAuthority struct {
	shared       statepg.CryptoIdentity
	activation   statepg.CryptoActivationRequest
	retirement   statepg.CryptoRetirementRequest
	acknowledged statepg.CryptoIdentity
}

type cryptoBackendLifecycle struct {
	accepted int
	retired  []int
}

func (b *cryptoBackendLifecycle) AcceptPrepared(context.Context, *terminator.Keyring, int, []byte) error {
	b.accepted++
	return nil
}

func (b *cryptoBackendLifecycle) RetireKey(_ context.Context, kid int, _ string) error {
	b.retired = append(b.retired, kid)
	return nil
}

func (a *cryptoAdminAuthority) ActivateCryptoGeneration(_ context.Context, req statepg.CryptoActivationRequest) (statepg.CryptoIdentity, error) {
	a.activation = req
	return a.shared, nil
}

func (a *cryptoAdminAuthority) RetireCryptoGeneration(_ context.Context, req statepg.CryptoRetirementRequest) (statepg.CryptoIdentity, error) {
	a.retirement = req
	return a.shared, nil
}

func (a *cryptoAdminAuthority) SynchronizeCrypto(_ context.Context, identity statepg.CryptoIdentity) (statepg.CryptoIdentity, error) {
	a.acknowledged = identity
	return a.shared, nil
}

func TestAdminCryptoActivateRequiresAuthorityAndReplayKey(t *testing.T) {
	service, err := control.NewService(control.New(16), cryptoAdminAuth{identity: &control.Identity{
		Name: "operator", Capabilities: []control.Capability{control.CapCryptoLifecycle},
	}}, cryptoAdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	peppers := credential.MustPepperRing(
		&credential.PepperKey{Version: 1, Key: []byte("pepper-generation-one-0123456789")},
		&credential.PepperKey{Version: 2, Key: []byte("pepper-generation-two-0123456789")},
	)
	fingerprint, _ := peppers.VersionFingerprint(2)
	signerFingerprint, _ := signer.PublicKeyFingerprint(signer.ActiveKid())
	authority := &cryptoAdminAuthority{shared: statepg.CryptoIdentity{
		SignerActiveKID: signer.ActiveKid(), SignerActiveFingerprint: signerFingerprint,
		PepperActiveVersion: 2, PepperActiveFingerprint: fingerprint,
		PseudonymVersion: 0,
	}}
	handler := adminCryptoActivate(service, authority, signer, peppers, nil, "", nil)

	withoutKey := httptest.NewRequest(http.MethodPost, "/admin/crypto/activate", strings.NewReader(`{"kind":"pepper","generation":2,"fingerprint":"`+fingerprint+`","reason":"rotate"}`))
	withoutKey.Header.Set("Authorization", "Bearer operator-token")
	withoutKey.Header.Set("Content-Type", "application/json")
	withoutKeyResponse := httptest.NewRecorder()
	handler.ServeHTTP(withoutKeyResponse, withoutKey)
	if withoutKeyResponse.Code != http.StatusBadRequest {
		t.Fatalf("missing replay key status=%d, want %d", withoutKeyResponse.Code, http.StatusBadRequest)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/crypto/activate", strings.NewReader(`{"kind":"pepper","generation":2,"fingerprint":"`+fingerprint+`","reason":"rotate"}`))
	req.Header.Set("Authorization", "Bearer operator-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "crypto-activation-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("activation status=%d body=%s", response.Code, response.Body.String())
	}
	if authority.activation.OperationID != "crypto-activation-1" || peppers.ActiveVersion() != 2 {
		t.Fatalf("activation operation=%+v active pepper=%d", authority.activation, peppers.ActiveVersion())
	}
}

func TestAdminCryptoActivateSignerFailsClosedWithoutVerifierProtocol(t *testing.T) {
	service, err := control.NewService(control.New(16), cryptoAdminAuth{identity: &control.Identity{
		Name: "operator", Capabilities: []control.Capability{control.CapCryptoLifecycle},
	}}, cryptoAdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	signerPath := filepath.Join(t.TempDir(), "keyring.json")
	if err := signer.Save(signerPath); err != nil {
		t.Fatal(err)
	}
	candidate, err := signer.PrepareRotation(signerPath)
	if err != nil {
		t.Fatal(err)
	}
	candidateFingerprint, ok := signer.PublicKeyFingerprint(candidate.KID)
	if !ok {
		t.Fatal("candidate fingerprint unavailable")
	}
	peppers := credential.MustPepperRing(&credential.PepperKey{Version: 1, Key: []byte("pepper-generation-one-0123456789")})
	authority := &cryptoAdminAuthority{}
	handler := adminCryptoActivate(service, authority, signer, peppers, nil, signerPath, nil)
	req := httptest.NewRequest(http.MethodPost, "/admin/crypto/activate", strings.NewReader(`{"kind":"signer","generation":`+strconv.Itoa(candidate.KID)+`,"fingerprint":"`+candidateFingerprint+`","reason":"rotate"}`))
	req.Header.Set("Authorization", "Bearer operator-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "crypto-signer-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("signer activation status=%d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if authority.activation.OperationID != "" {
		t.Fatal("signer rejection must not mutate shared authority")
	}
}

func TestAdminCryptoRetireSignerWaitsForAuthorityAndRemovesLocalKey(t *testing.T) {
	service, err := control.NewService(control.New(16), cryptoAdminAuth{identity: &control.Identity{
		Name: "operator", Capabilities: []control.Capability{control.CapCryptoLifecycle},
	}}, cryptoAdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	signerPath := filepath.Join(t.TempDir(), "keyring.json")
	if err := signer.Save(signerPath); err != nil {
		t.Fatal(err)
	}
	oldKid := signer.ActiveKid()
	newKid, err := signer.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Save(signerPath); err != nil {
		t.Fatal(err)
	}
	oldFingerprint, _ := signer.PublicKeyFingerprint(oldKid)
	newFingerprint, _ := signer.PublicKeyFingerprint(newKid)
	pepper := credential.MustPepperRing(&credential.PepperKey{Version: 1, Key: []byte("pepper-generation-one-0123456789")})
	authority := &cryptoAdminAuthority{shared: statepg.CryptoIdentity{
		SignerActiveKID: newKid, SignerActiveFingerprint: newFingerprint,
		PepperActiveVersion: 1, PepperActiveFingerprint: mustPepperFingerprint(t, pepper, 1),
		PseudonymVersion: 0,
		Retired:          []statepg.CryptoGeneration{{Kind: statepg.CryptoKindSigner, Generation: oldKid, Fingerprint: oldFingerprint}},
	}}
	backend := &cryptoBackendLifecycle{}
	handler := adminCryptoRetire(service, authority, signer, pepper, nil, signerPath, backend)
	req := httptest.NewRequest(http.MethodPost, "/admin/crypto/retire", strings.NewReader(`{"kind":"signer","generation":1,"fingerprint":"`+oldFingerprint+`","not_before":"`+time.Now().Add(-time.Second).UTC().Format(time.RFC3339)+`","reason":"overlap expired"}`))
	req.Header.Set("Authorization", "Bearer operator-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "crypto-signer-retire-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("retirement status=%d body=%s", response.Code, response.Body.String())
	}
	if len(backend.retired) != 2 || signer.ActiveKid() != newKid {
		t.Fatalf("backend retirement calls=%v active kid=%d", backend.retired, signer.ActiveKid())
	}
	if _, ok := signer.Public(oldKid); ok {
		t.Fatal("local retired signer public key remains loaded")
	}
}

func mustPepperFingerprint(t *testing.T, peppers *credential.PepperRing, version int) string {
	t.Helper()
	fingerprint, ok := peppers.VersionFingerprint(version)
	if !ok {
		t.Fatalf("pepper generation %d fingerprint unavailable", version)
	}
	return fingerprint
}
