// Package secret provides the sealed container through which the raw external
// credential is handled. This is the narrowest privileged boundary in Gripline:
// a raw credential may exist at most inside a *SealedSecret, and never in a
// generic request context, log, trace, or internal header (INV-1..INV-3).
//
// Redaction here is an ACTIVE property, not the absence of an interface. Go's
// fmt package formats unexported fields by default (%v on a naive struct
// prints its byte values), so a type that merely lacks String() leaks through
// every generic format call. SealedSecret therefore implements the full
// formatting surface as deliberate redaction:
//
//   - Format handles every verb: output is always "<redacted>", never the
//     bytes, for %v %+v %#v %s %q %x %d and everything else;
//   - String and GoString cover implicit conversion and %#v;
//   - errors created from a secret (or an error carrying one) never render it;
//   - json/gob/text marshaling is absent by design (marshalers would ship the
//     raw bytes out of the boundary), and the redacting Format intercepts the
//     reflection fallback that serializers use.
//
// The exported struct holds ONLY an opaque pointer to unexported state. A
// struct copy (copy := *s) carries no bytes and no copyable flag — copies
// share the same zeroization state, so a stale copy cannot resurrect data or
// out-live a wipe.
//
// Memory-lifetime honesty (threat-model boundary): Go strings and header maps
// handed to ExtractExternalCredential already contain the credential as
// immutable memory this package cannot reach. Zero() wipes every buffer this
// package OWNS (best effort — the runtime may still have moved or copied
// them). The guarantee Gripline makes is architectural: the credential never
// propagates past the terminator into storage, telemetry, queues, or
// downstream services, and every owned mutable copy is wiped on exit. It is
// NOT a claim that zero copies exist in process memory. See
// docs/design/01-containment.md.
package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// redacted is the only thing any formatter ever emits.
const redacted = "<redacted>"

// SealedSecret holds raw credential bytes in an opaque, actively-redacting
// container. The zero value is not usable; construct with NewFromBytes or
// Random.
type SealedSecret struct {
	// state is unexported and pointer-typed on purpose:
	//   - fmt cannot reach the bytes through the struct (Format redacts first);
	//   - a struct copy shares the same state (no independent stale copy).
	state *secretState
}

// secretState is the owned backing buffer plus the zeroization flag. All
// copies of a SealedSecret alias one state, so Zero affects every alias.
type secretState struct {
	buf    []byte
	zeroed bool
}

// digestDomain separates this HMAC use from every other HMAC in the program
// (the pepper-keyed verifier derives under this exact domain).
var digestDomain = []byte("gripline:secret:digest:v1")

// sprayDomain separates the P0.30 spray-pseudonym transform from verifier
// derivation: a value that collides across the two would let spray tracking
// impersonate authentication state.
var sprayDomain = []byte("gripline:secret:spray-pseudonym:v1")

// NewFromBytes builds a SealedSecret from a caller-owned byte slice, copying
// the bytes into an internal buffer. The caller is responsible for zeroing its
// own buffer afterwards.
func NewFromBytes(src []byte) *SealedSecret {
	buf := make([]byte, len(src))
	copy(buf, src)
	return &SealedSecret{state: &secretState{buf: buf}}
}

// Zero wipes the owned backing memory and marks the secret unusable. Every
// copy of the SealedSecret (they alias the same state) becomes unusable too.
// Idempotent; returns true if it actually wiped a live buffer. Best effort at
// the memory layer: the Go runtime may have moved or duplicated the buffer
// internally; see the package comment for the honest boundary.
func (s *SealedSecret) Zero() bool {
	if s == nil || s.state == nil || s.state.zeroed {
		return false
	}
	st := s.state
	for i := range st.buf {
		st.buf[i] = 0
	}
	st.buf = nil
	st.zeroed = true
	return true
}

// Zeroed reports whether the secret has been wiped (or was never constructed).
func (s *SealedSecret) Zeroed() bool {
	return s == nil || s.state == nil || s.state.zeroed
}

// Len returns the byte length of the held secret. Revealing only the length is
// safe within this boundary (it does not reveal the secret). A zeroed secret
// reports 0.
func (s *SealedSecret) Len() int {
	if s.Zeroed() {
		return 0
	}
	return len(s.state.buf)
}

// DigestHMAC is the single deliberate transform on a sealed secret: fold the
// raw bytes under a pepper key with HMAC-SHA256 to derive the verifier. It
// keeps the key-op and the secret co-located inside the sealed boundary so
// neither is exposed. Returns nil on a zeroed secret or an empty key — an HMAC
// under an empty key is publicly computable, so deriving under one would mint
// enumerable verifiers (INV-1 fails closed, not open).
func (s *SealedSecret) DigestHMAC(key []byte) []byte {
	if s == nil || s.state == nil || s.state.zeroed || len(key) == 0 {
		return nil
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(digestDomain)
	_, _ = m.Write(s.state.buf)
	return m.Sum(nil)
}

// SprayPseudonym is the second (and only other) deliberate transform (P0.30):
// a SHORT-LIVED, domain-separated keyed pseudonym over the presented bytes,
// used to track INVALID-credential spray. Before an unknown credential is
// destroyed, source state can count DISTINCT presented keys per source —
// without retaining any raw candidate key bytes and without adding a generic
// Bytes() accessor (the transform stays inside the sealed boundary). The
// output is a base64 tag suitable as a detector key; it is NOT a verifier and
// MUST NOT be persisted as one.
func (s *SealedSecret) SprayPseudonym(key []byte) string {
	if s == nil || s.state == nil || s.state.zeroed || len(key) == 0 {
		return ""
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(sprayDomain) // domain separation: never DigestHMAC-compatible
	_, _ = m.Write(s.state.buf)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

// Random returns n random bytes sealed for test/key-generation use. The
// temporary staging buffer is wiped after the sealed copy is made (P0.2: the
// staging copy must not outlive the call unowned).
func Random(n int) (*SealedSecret, error) {
	if n <= 0 {
		return nil, errors.New("secret: Random requires n > 0")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		for i := range buf { // don't leak entropy-sized garbage on failure either
			buf[i] = 0
		}
		return nil, fmt.Errorf("secret: random read: %w", err)
	}
	s := NewFromBytes(buf)
	for i := range buf { // wipe the staging copy
		buf[i] = 0
	}
	return s, nil
}

// --- active redaction surface ------------------------------------------------
//
// Every method below REPLACES a reflection fallback fmt would otherwise use.
// They use VALUE receivers deliberately: pointer-receiver methods are not in
// the method set of a struct copy, so `copy := *s` formatted with %v would
// fall back to raw-field reflection. With value receivers both SealedSecret
// and *SealedSecret carry the redaction surface. No verb, flag, width, or
// precision combination reaches the bytes. (Formatting a nil *SealedSecret
// derefs nil before the body runs; fmt recovers panics from these specific
// methods and prints a panic notice — still no bytes.)

// Format implements fmt.Formatter for every verb. It always emits the
// redaction marker: even %x/%d/%q/%s must not reveal or encode the bytes.
func (s SealedSecret) Format(f fmt.State, verb rune) {
	// Ignore all flags — any flag-sensitive rendering would be a side channel
	// on the content.
	fmt.Fprint(f, redacted)
}

// String implements fmt.Stringer (implicit %s/%v paths).
func (s SealedSecret) String() string { return redacted }

// GoString implements fmt.GoStringer (%#v).
func (s SealedSecret) GoString() string { return redacted }

// MarshalJSON is deliberately ABSENT. Serializers must not be able to ship the
// raw bytes; with no Marshaler defined, encoding/json falls back to reflection
// — which fmt.Formatter-style redaction cannot intercept. The compile-time
// contract is enforced by TestSealedSecretHasNoFormattingOrSerializationSurface
// asserting both that redaction methods EXIST and marshalers DO NOT.
//
// Compile-time proof that the redaction surface is present:
var (
	_ fmt.Formatter  = (*SealedSecret)(nil)
	_ fmt.Stringer   = (*SealedSecret)(nil)
	_ fmt.GoStringer = (*SealedSecret)(nil)
)
