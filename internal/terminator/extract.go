package terminator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/B-A-M-N/gripline/internal/secret"
)

// CredentialCarrier names the header that carried the credential.
type CredentialCarrier int

const (
	carrierNone CredentialCarrier = iota
	carrierAuthorization
	carrierAPIKey
	carrierProvider
)



// maxCredentialLen bounds the accepted raw credential size (§15 oversized).
const maxCredentialLen = 1024

// extractionError is returned for ambiguous or malformed auth (§15: ambiguity
// must fail).
type extractionError struct{ msg string }

func (e *extractionError) Error() string { return "terminator: extraction: " + e.msg }

// isExtractionError reports whether err is an authentication-extraction failure.
func isExtractionError(err error) bool {
	var e *extractionError
	return errors.As(err, &e)
}

// ExtractExternalCredential pulls a credential from a normalized view of the
// request secret headers (carrier presence), enforcing: only one carrier;
// exactly one credential; valid syntax; bounded size. On success it returns
// the sealed credential; the caller (Admit) is responsible for stripping the
// secret headers (§18) — extraction does not mutate the map itself. On
// ambiguity it fails closed.
//
// headers is treated as owned by the caller; the sealed copy is independent.
func ExtractExternalCredential(headers map[string][]string) (*secret.SealedSecret, CredentialCarrier, error) {
	var (
		authCandidates []string
		keyCandidates  []string
	)
	for name, vals := range headers {
		ln := strings.ToLower(name)
		switch ln {
		case "authorization", "proxy-authorization":
			authCandidates = append(authCandidates, vals...)
		case "x-api-key", "api-key":
			keyCandidates = append(keyCandidates, vals...)
		}
		// provider-specific secret headers handled by adapters; the default
		// config only honors bearer + api-key.
	}

	// Ambiguity: more than one of either kind of carrier.
	carriers := 0
	if len(authCandidates) > 0 {
		carriers++
	}
	if len(keyCandidates) > 0 {
		carriers++
	}
	if carriers > 1 {
		return nil, carrierNone, &extractionError{msg: "conflicting credential carriers (Authorization + api-key)"}
	}

	switch {
	case len(authCandidates) > 0:
		if len(authCandidates) > 1 {
			return nil, carrierNone, &extractionError{msg: "duplicate Authorization headers"}
		}
		s, err := parseBearer(authCandidates[0])
		if err != nil {
			return nil, carrierNone, err
		}
		return s, carrierAuthorization, nil
	case len(keyCandidates) > 0:
		if len(keyCandidates) > 1 {
			return nil, carrierNone, &extractionError{msg: "duplicate api-key headers"}
		}
		raw := keyCandidates[0]
		raw = strings.TrimSpace(raw)
		if len(raw) == 0 || len(raw) > maxCredentialLen {
			return nil, carrierNone, &extractionError{msg: "invalid api-key length"}
		}
		if strings.ContainsAny(raw, " \t\r\n") {
			return nil, carrierNone, &extractionError{msg: "api-key must not contain whitespace"}
		}
		return secret.NewFromBytes([]byte(raw)), carrierAPIKey, nil
	default:
		return nil, carrierNone, &extractionError{msg: "no credential supplied"}
	}
}

// parseBearer validates and extracts an `Authorization: Bearer <key>` value.
func parseBearer(v string) (*secret.SealedSecret, error) {
	v = strings.TrimSpace(v)
	parts := strings.Fields(v)
	if len(parts) != 2 {
		return nil, &extractionError{msg: fmt.Sprintf("malformed bearer syntax (%d fields)", len(parts))}
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return nil, &extractionError{msg: "unsupported authorization scheme"}
	}
	raw := parts[1]
	if len(raw) == 0 || len(raw) > maxCredentialLen {
		return nil, &extractionError{msg: "invalid bearer credential length"}
	}
	return secret.NewFromBytes([]byte(raw)), nil
}

// StripSecretHeaders removes every header an external caller must never
// inject past the terminator: the external-secret carriers (§18) AND the
// reserved internal-identity namespace (INV-12 — a forged "Gripline-*" header
// arriving from the public side could otherwise impersonate an admitted
// request at the protected backend). Internal headers are minted by the
// terminator after admission; anything presenting them at ingress is forgery
// and is deleted before authentication.
func StripSecretHeaders(headers map[string][]string) {
	for name := range headers {
		ln := strings.ToLower(name)
		switch {
		case ln == "authorization" || ln == "proxy-authorization" ||
			ln == "x-api-key" || ln == "api-key":
			delete(headers, name)
		case strings.HasPrefix(ln, "gripline-") || strings.HasPrefix(ln, "x-gripline-"):
			// Reserved internal namespace, any capitalization or suffix
			// (Gripline-Principal, X-Gripline-Assertion, ...).
			delete(headers, name)
		}
	}
}
