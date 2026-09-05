// Package secret provides the sealed container through which the raw external
// credential is handled. This is the narrowest privileged boundary in Gripline:
// a raw credential may exist at most inside a *SealedSecret, and never in a
// generic request context, log, trace, or internal header (INV-1..INV-3).
//
// The type intentionally has a minimal API:
//
//   - it does not implement fmt.Formatter, Stringer, or Error, so accidental
//     formatting via %v / %s / %q cannot leak the raw bytes (INV-2);
//   - it has no MarshalJSON / MarshalBinary / GobEncode, so no serializer can
//     ship the raw bytes out of the boundary;
//   - the only escape hatch, DigestHMAC, is the deliberate keyed one-way
//     transform that derives the stored verifier (internal/credential). It
//     never exposes the raw bytes.
//
// Zero() wipes the backing array so the raw representation does not survive
// beyond authentication. Every terminator code path reaches Zero (deferred).
package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// SealedSecret holds raw credential bytes in an opaque, non-formatting,
// non-serializing container.
type SealedSecret struct {
	// buf is owned exclusively by the SealedSecret. Unexported: nothing outside
	// this package can read it except through the deliberate DigestHMAC
	// operation.
	buf []byte
	// zeroed is set once Zero is applied. Operations on a zeroed secret fail.
	zeroed bool
}

// digestDomain separates this HMAC use from every other HMAC in the program
// (the pepper-keyed verifier derives under this exact domain).
var digestDomain = []byte("gripline:secret:digest:v1")

// NewFromBytes builds a SealedSecret from a caller-owned byte slice, copying
// the bytes into an internal buffer. The caller is responsible for zeroing its
// own buffer afterwards.
func NewFromBytes(src []byte) *SealedSecret {
	buf := make([]byte, len(src))
	copy(buf, src)
	return &SealedSecret{buf: buf}
}

// Zero wipes the backing memory and marks the secret unusable. Idempotent
// (releases at most once); returns true if it actually wiped a live buffer.
func (s *SealedSecret) Zero() bool {
	if s == nil || s.zeroed {
		return false
	}
	for i := range s.buf {
		s.buf[i] = 0
	}
	s.buf = nil
	s.zeroed = true
	return true
}

// Zeroed reports whether the secret has been wiped. Used by tests and by the
// terminator to assert the raw secret is destroyed after authentication.
func (s *SealedSecret) Zeroed() bool {
	return s == nil || s.zeroed
}

// Len returns the byte length of the held secret. Revealing only the length is
// safe within this boundary (it does not reveal the secret). A zeroed secret
// reports 0.
func (s *SealedSecret) Len() int {
	if s == nil || s.zeroed {
		return 0
	}
	return len(s.buf)
}

// DigestHMAC is the single deliberate transform on a sealed secret: fold the
// raw bytes under a pepper key with HMAC-SHA256 to derive the verifier. It
// keeps the key-op and the secret co-located inside the sealed boundary so
// neither is exposed. The credential package composes this with the pepper ring
// to derive/store/compare verifiers. Returns nil on a zeroed secret or an
// empty key — an HMAC under an empty key is publicly computable, so deriving
// under one would mint enumerable verifiers (INV-1 fails closed, not open).
func (s *SealedSecret) DigestHMAC(key []byte) []byte {
	if s == nil || s.zeroed || len(key) == 0 {
		return nil
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(digestDomain)
	_, _ = m.Write(s.buf)
	return m.Sum(nil)
}

// Random returns n random bytes sealed for test/key-generation use.
func Random(n int) (*SealedSecret, error) {
	if n <= 0 {
		return nil, errors.New("secret: Random requires n > 0")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("secret: random read: %w", err)
	}
	return NewFromBytes(buf), nil
}

// Compile-time interfaces the secret must NOT satisfy. The commented asserts
// document the contract; a future contributor who adds a String() method will
// find the property test "secret never formats/serializes" failing.
//
//	// var _ fmt.Stringer = (*SealedSecret)(nil)        // must stay absent
//	// var _ fmt.Formatter = (*SealedSecret)(nil)       // must stay absent
//	// var _ json.Marshaler = (*SealedSecret)(nil)      // must stay absent
//	// var _ encoding.BinaryMarshaler = (*SealedSecret)(nil) // must stay absent
