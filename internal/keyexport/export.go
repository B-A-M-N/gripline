// Package keyexport provides public key material for backend verification.
// This is the boundary the deployment hands to private backends — never the
// signer/private key, only public verification material (P0.15).
package keyexport

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"time"
)

// KeyMaterial is one verification key entry for backend consumption.
type KeyMaterial struct {
	KID         int    `json:"kid"`         // key ID for selection
	Algorithm   string `json:"algorithm"`   // always "Ed25519"
	PublicKey   string `json:"public"`      // base64-encoded Ed25519 public key
	Fingerprint string `json:"fingerprint"` // SHA-256 of the public key
}

// Export is the full verification material a backend needs.
type Export struct {
	Keys        []KeyMaterial `json:"keys"`         // all retained generations
	ActiveKID   int           `json:"active_kid"`   // current signing generation
	GeneratedAt string        `json:"generated_at"` // RFC3339 timestamp
}

// GenerateExport builds the export from a keyring's public keys.
// Keys are sorted by KID for deterministic output. GeneratedAt is populated
// from the current UTC time.
func GenerateExport(activeKid int, verifiers map[int][]byte) (*Export, error) {
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("keyexport: no verifier keys available")
	}

	// Sort keys by KID for deterministic output.
	kids := make([]int, 0, len(verifiers))
	for kid := range verifiers {
		kids = append(kids, kid)
	}
	sort.Ints(kids)

	keys := make([]KeyMaterial, 0, len(verifiers))
	for _, kid := range kids {
		pub := verifiers[kid]
		if len(pub) != ed25519.PublicKeySize {
			continue
		}
		fingerprint := sha256.Sum256(pub)
		keys = append(keys, KeyMaterial{
			KID:         kid,
			Algorithm:   "Ed25519",
			PublicKey:   base64.StdEncoding.EncodeToString(pub),
			Fingerprint: base64.StdEncoding.EncodeToString(fingerprint[:8]),
		})
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("keyexport: no valid Ed25519 public keys")
	}

	return &Export{
		Keys:        keys,
		ActiveKID:   activeKid,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}
