package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

const verifierControlProtocol = "gripline.verifier-control/v1"

// httpVerifierControl implements the protected-backend contract required for
// live signer activation. The backend endpoint must durably publish the public
// candidate, verify the supplied candidate assertion, and return success only
// after both operations complete.
type httpVerifierControl struct {
	client   *http.Client
	endpoint *url.URL
	audience string
	token    string
}

func newHTTPVerifierControl(cfg *config.Config, transport http.RoundTripper, timeout time.Duration) (*httpVerifierControl, error) {
	if cfg == nil || strings.TrimSpace(cfg.Backend.VerifierControl.URL) == "" {
		return nil, nil
	}
	endpoint, err := url.Parse(cfg.Backend.VerifierControl.URL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, fmt.Errorf("gripline: verifier control URL is invalid")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("gripline: verifier control URL must not contain userinfo, query, or fragment")
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &httpVerifierControl{
		client: &http.Client{Transport: transport, Timeout: timeout}, endpoint: endpoint,
		audience: cfg.Identity.Audience, token: cfg.Backend.VerifierControl.Token,
	}, nil
}

func (c *httpVerifierControl) authenticate(req *http.Request) {
	if c == nil || req == nil || c.token == "" {
		return
	}
	req.Header.Set("X-Gripline-Verifier-Control", c.token)
}

type verifierControlRequest struct {
	Action          string `json:"action"`
	Protocol        string `json:"protocol"`
	KID             int    `json:"kid"`
	PublicKey       string `json:"public_key"`
	Fingerprint     string `json:"fingerprint"`
	CanaryAssertion string `json:"canary_assertion"`
}

func (c *httpVerifierControl) AcceptPrepared(ctx context.Context, signer *terminator.Keyring, kid int, public []byte) error {
	if c == nil || c.client == nil || c.endpoint == nil {
		return fmt.Errorf("backend verifier control is not configured")
	}
	if signer == nil || kid < 1 || len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid prepared signer generation")
	}
	loaded, ok := signer.Public(kid)
	if !ok || !bytes.Equal(loaded, public) {
		return fmt.Errorf("prepared signer public key is not loaded")
	}
	fingerprint, ok := signer.PublicKeyFingerprint(kid)
	if !ok {
		return fmt.Errorf("prepared signer fingerprint is unavailable")
	}
	canary, err := signer.IssuePrepared(terminator.Claims{
		Subject: "gripline-rotation", CredID: "gripline-rotation", Audience: c.audience,
		JTI: terminator.NewRequestID(), PolicyRev: 1, CredRev: 1, Scope: []string{"inference"},
	}, 10*time.Second)
	if err != nil {
		return fmt.Errorf("issue signer canary: %w", err)
	}
	payload := verifierControlRequest{
		Action: "publish", Protocol: verifierControlProtocol, KID: kid,
		PublicKey: base64.StdEncoding.EncodeToString(public), Fingerprint: fingerprint,
		CanaryAssertion: canary.Encode(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal verifier control request: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build verifier control request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.authenticate(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("backend verifier control request: %w", err)
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		return fmt.Errorf("read backend verifier control response: %w", readErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("backend verifier rejected candidate kid %d: status %d: %s", kid, resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

// RetireKey asks the backend verifier to remove a generation after the
// cluster authority has enforced its overlap and migration safety horizon.
// The endpoint must treat an already-removed key as an idempotent success.
func (c *httpVerifierControl) RetireKey(ctx context.Context, kid int, fingerprint string) error {
	if c == nil || c.client == nil || c.endpoint == nil {
		return fmt.Errorf("backend verifier control is not configured")
	}
	if kid < 1 || strings.TrimSpace(fingerprint) == "" {
		return fmt.Errorf("invalid signer retirement request")
	}
	payload, err := json.Marshal(verifierControlRequest{
		Action: "retire", Protocol: verifierControlProtocol, KID: kid, Fingerprint: fingerprint,
	})
	if err != nil {
		return fmt.Errorf("marshal verifier retirement request: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build verifier retirement request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.authenticate(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("backend verifier retirement request: %w", err)
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		return fmt.Errorf("read backend verifier retirement response: %w", readErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("backend verifier rejected retirement kid %d: status %d: %s", kid, resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}
