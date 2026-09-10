package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
)

func operatorTokenFromFile(flagValue, path string) (string, error) {
	if flagValue != "" {
		return strings.TrimSpace(flagValue), nil
	}
	if path == "" {
		if token := strings.TrimSpace(os.Getenv("GRIPLINE_OPERATOR_TOKEN")); token != "" {
			return token, nil
		}
		path = strings.TrimSpace(os.Getenv("GRIPLINE_OPERATOR_TOKEN_FILE"))
	}
	if path != "" {
		b, err := os.ReadFile(path) // #nosec G304 -- token file path is an explicit operator input.
		if err != nil {
			return "", fmt.Errorf("read operator token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv("GRIPLINE_OPERATOR_TOKEN")), nil
}

type adminClient struct {
	base   string
	client *http.Client
}

type adminHTTPError struct {
	StatusCode int
	Method     string
	Path       string
	Body       string
}

func (e adminHTTPError) Error() string {
	return fmt.Sprintf("admin request %s %s: %s", e.Method, e.Path, e.Body)
}

type cryptoRetirementTooEarlyCLIError struct {
	Kind       string
	Generation int
	SafeAfter  time.Time
}

func (e cryptoRetirementTooEarlyCLIError) Error() string {
	remaining := time.Until(e.SafeAfter)
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("%s generation %d is not safe to retire yet\nSafe after: %s\nRemaining: %s", e.Kind, e.Generation, e.SafeAfter.UTC().Format(time.RFC3339), remaining.Round(time.Second))
}

type cryptoRetirementBlockedCLIError struct {
	Kind       string
	Generation int
	References int
	Detail     string
}

func (e cryptoRetirementBlockedCLIError) Error() string {
	return fmt.Sprintf("%s generation %d cannot be retired: %d reference(s) remain (%s)", e.Kind, e.Generation, e.References, e.Detail)
}

func newAdminClientWithTimeout(cfgPath string, timeout time.Duration) (*adminClient, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	if cfg.Admin == nil || cfg.Admin.Listen == "" {
		return nil, fmt.Errorf("deployment has no private admin listener configured")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("admin request timeout must be positive")
	}
	return &adminClient{base: "http://" + cfg.Admin.Listen, client: &http.Client{Timeout: timeout}}, nil
}

func (c *adminClient) request(method, path, token string, body any, out any) error {
	return c.requestContext(context.Background(), method, path, token, body, out)
}

func (c *adminClient) requestWithOperationID(method, path, token, operationID string, body any, out any) error {
	return c.requestWithOperationIDContext(context.Background(), method, path, token, operationID, body, out)
}

func (c *adminClient) requestContext(ctx context.Context, method, path, token string, body any, out any) error {
	return c.requestWithOperationIDContext(ctx, method, path, token, "", body, out)
}

func (c *adminClient) requestWithOperationIDContext(ctx context.Context, method, path, token, operationID string, body any, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	attempts := 1
	if operationID != "" {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(data)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if operationID != "" {
			req.Header.Set("Idempotency-Key", operationID)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			if attempt+1 < attempts {
				continue
			}
			if operationID != "" {
				return fmt.Errorf("request outcome is uncertain; operation ID: %s; re-run with --operation-id %s: %w", operationID, operationID, err)
			}
			return fmt.Errorf("admin request: %w", err)
		}
		responseData, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			if attempt+1 < attempts {
				continue
			}
			if operationID != "" {
				return fmt.Errorf("request outcome is uncertain; operation ID: %s; re-run with --operation-id %s: %w", operationID, operationID, readErr)
			}
			return fmt.Errorf("admin response: %w", readErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if resp.StatusCode == http.StatusConflict {
				var conflict struct {
					Kind       string `json:"kind"`
					Generation int    `json:"generation"`
					SafeAfter  string `json:"safe_after"`
					References int    `json:"references"`
					Detail     string `json:"detail"`
				}
				if json.Unmarshal(responseData, &conflict) == nil && conflict.Kind != "" && conflict.Generation > 0 && conflict.SafeAfter != "" {
					if safeAfter, parseErr := time.Parse(time.RFC3339, conflict.SafeAfter); parseErr == nil {
						return cryptoRetirementTooEarlyCLIError{Kind: conflict.Kind, Generation: conflict.Generation, SafeAfter: safeAfter}
					}
				}
				if json.Unmarshal(responseData, &conflict) == nil && conflict.Kind != "" && conflict.Generation > 0 && conflict.References > 0 {
					return cryptoRetirementBlockedCLIError{Kind: conflict.Kind, Generation: conflict.Generation, References: conflict.References, Detail: conflict.Detail}
				}
			}
			return adminHTTPError{StatusCode: resp.StatusCode, Method: method, Path: path, Body: strings.TrimSpace(string(responseData))}
		}
		if out != nil && len(responseData) > 0 {
			if err := json.Unmarshal(responseData, out); err != nil {
				return fmt.Errorf("admin response: decode: %w", err)
			}
		}
		return nil
	}
	return fmt.Errorf("admin request failed")
}
