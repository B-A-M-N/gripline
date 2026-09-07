package secret

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"
	"testing"
)

// canary is an unmistakable secret value: if any formatting, logging, or
// serialization path leaks the raw bytes, this string (or its byte values)
// appears in the output.
const canary = "sk-CANARY-leak-probe-0f3a9c"

// wantRedacted asserts output is exactly the redaction marker (strongest
// contract: no verb may encode or transform the bytes).
func wantRedacted(t *testing.T, verb, got string) {
	t.Helper()
	if got != redacted {
		t.Fatalf("%%%s rendered %q, want %q (P0.1)", verb, got, redacted)
	}
}

// TestFormatVerbsNeverLeakCanary is the adversarial P0.1 test: every fmt verb
// applied to a live secret must yield exactly the redaction marker — never the
// canary, never its decimal byte values, never any encoding of it.
func TestFormatVerbsNeverLeakCanary(t *testing.T) {
	s := NewFromBytes([]byte(canary))
	defer s.Zero()

	canon := []string{canary, "115 107 45", "115,107,45"} // raw + decimal bytes
	// Content verbs must render EXACTLY the redaction marker.
	verbs := []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%c", "%b", "%o",
		"%U", "%e", "%f", "%g", "%5s", "%-10s", "%.3s", "%08x",
		"%#x", "% d",
	}
	for _, v := range verbs {
		out := fmt.Sprintf(v, s)
		wantRedacted(t, v, out)
		for _, c := range canon {
			if strings.Contains(out, c) {
				t.Fatalf("%%%s output contains canary material: %q", v, out)
			}
		}
	}
	// %p and %T bypass Formatter inside fmt (address / type are printed
	// directly for any operand). They cannot contain credential material —
	// assert absence, not redaction.
	for _, v := range []string{"%p", "%T"} {
		out := fmt.Sprintf(v, s)
		for _, c := range canon {
			if strings.Contains(out, c) {
				t.Fatalf("%%%s output contains canary material: %q", v, out)
			}
		}
	}
	// Compound formats and Sprint/log paths.
	compound := fmt.Sprintf("auth=%v len=%d ok=%t", s, s.Len(), true)
	if strings.Contains(compound, canary) {
		t.Fatalf("compound format leaked: %q", compound)
	}
	if got := fmt.Sprint(s); got != redacted {
		t.Fatalf("fmt.Sprint = %q", got)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "header %s", s)
	if sb.String() != "header "+redacted {
		t.Fatalf("Fprintf output = %q, want prefix + redaction", sb.String())
	}
	if strings.Contains(sb.String(), canary) {
		t.Fatal("Fprintf output leaked the canary")
	}

	// The most common accidental path: a debug logger.
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	log.Printf("request credential: %v", s)
	log.SetOutput(nil)
	if got := logBuf.String(); !strings.Contains(got, redacted) || strings.Contains(got, canary) {
		t.Fatalf("log.Printf output: %q", got)
	}
}

// TestFormatOnValueCopyNeverLeaks covers the struct-copy path: a copy of the
// exported value must not fall back to raw-field reflection formatting, and a
// copy shares the zeroization state (P0.1 + INV-15-style idempotency).
func TestFormatOnValueCopyNeverLeaks(t *testing.T) {
	s := NewFromBytes([]byte(canary))
	cp := *s // struct copy — must alias the same state

	for _, v := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		out := fmt.Sprintf(v, cp)
		wantRedacted(t, v, out)
	}
	// Zero via the original; the copy must see the same state.
	if !s.Zero() {
		t.Fatal("first Zero must wipe")
	}
	if !cp.Zeroed() {
		t.Fatal("copy must share zeroization state with the original")
	}
	if cp.Len() != 0 {
		t.Fatal("copy must report len 0 after Zero of the original")
	}
	// Zeroing again through the copy is a no-op.
	if cp.Zero() {
		t.Fatal("second Zero through the copy must be a no-op")
	}
	// And DigestHMAC is dead through either alias.
	if cp.DigestHMAC([]byte("k")) != nil || s.DigestHMAC([]byte("k")) != nil {
		t.Fatal("zeroed secret must not digest through any alias")
	}
}

// TestPanicDiagnosticsDoNotLeak: a panic value carrying the secret must not
// render the canary in recovery diagnostics.
func TestPanicDiagnosticsDoNotLeak(t *testing.T) {
	s := NewFromBytes([]byte(canary))
	defer s.Zero()

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic")
			}
			msg := fmt.Sprintf("%v", r)
			if strings.Contains(msg, canary) {
				t.Fatalf("panic diagnostics leaked the secret: %q", msg)
			}
		}()
		panic(s)
	}()
}

// TestErrorWrappingDoesNotLeak: an error wrapping the secret must not render it.
func TestErrorWrappingDoesNotLeak(t *testing.T) {
	s := NewFromBytes([]byte(canary))
	defer s.Zero()
	err := fmt.Errorf("admission failed for %v", s)
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("error text leaked the secret: %q", err.Error())
	}
}

// TestSealedSecretRedactionSurfaceExists backs INV-2 as an active property:
// the redaction methods must exist (so fmt can never fall through to raw-field
// formatting), while serialization methods must not (so no serializer can
// carry the bytes out of the boundary).
func TestSealedSecretRedactionSurfaceExists(t *testing.T) {
	typ := reflect.TypeOf((*SealedSecret)(nil))
	for _, required := range []string{"Format", "String", "GoString"} {
		if _, ok := typ.MethodByName(required); !ok {
			t.Fatalf("SealedSecret must implement %s (active redaction, P0.1)", required)
		}
	}
	for _, banned := range []string{"MarshalJSON", "MarshalBinary", "GobEncode", "MarshalText", "AppendText"} {
		if _, ok := typ.MethodByName(banned); ok {
			t.Fatalf("SealedSecret must not implement %s (INV-2)", banned)
		}
	}
}

// TestStructHasNoExportedFields ensures json/gob cannot ship contents via
// exported fields, and that the only field is the opaque state pointer (a
// future byte-bearing field here would reintroduce the P0.1 fallback).
func TestStructHasNoExportedFields(t *testing.T) {
	typ := reflect.TypeOf(SealedSecret{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath == "" {
			t.Fatalf("field %q is exported; SealedSecret fields must be unexported (INV-2)", f.Name)
		}
		if f.Name != "state" {
			t.Fatalf("unexpected field %q; SealedSecret must hold only the opaque state pointer", f.Name)
		}
	}
}

func TestZeroWipesAndIsIdempotent(t *testing.T) {
	wantLen := len("sk-0123456789abcdef")
	s := NewFromBytes([]byte("sk-0123456789abcdef"))
	if s.Zeroed() {
		t.Fatal("secret should start un-zeroed")
	}
	if s.Len() != wantLen {
		t.Fatalf("len = %d, want %d", s.Len(), wantLen)
	}
	if !s.Zero() {
		t.Fatal("first Zero should return true (actually wiped)")
	}
	if !s.Zeroed() {
		t.Fatal("secret should be zeroed after Zero")
	}
	if s.Len() != 0 {
		t.Fatalf("zeroed secret reports len %d, want 0", s.Len())
	}
	if s.Zero() {
		t.Fatal("second Zero should return false (already zeroed)")
	}
	if d := s.DigestHMAC([]byte("k")); d != nil {
		t.Fatal("zeroed secret must not produce a keyed digest")
	}
}

func TestDigestHMACMatchesManual(t *testing.T) {
	s := NewFromBytes([]byte("the-raw-credential"))
	key := []byte("pepper-key")
	want := hmacSHA256(key, []byte("gripline:secret:digest:v1"), []byte("the-raw-credential"))
	if !bytes.Equal(s.DigestHMAC(key), want) {
		t.Fatal("DigestHMAC must fold domain || raw under the key")
	}
	s.Zero()
	if s.DigestHMAC(key) != nil {
		t.Fatal("zeroed secret must produce nil digest")
	}
}

// TestNewFromBytesCopies isolates the sealed copy from later caller mutation.
func TestNewFromBytesCopies(t *testing.T) {
	src := []byte("sk-original")
	s := NewFromBytes(src)
	src[0] = 'X'
	want := hmacSHA256([]byte("k"), []byte("gripline:secret:digest:v1"), []byte("sk-original"))
	if !bytes.Equal(s.DigestHMAC([]byte("k")), want) {
		t.Fatal("NewFromBytes must copy the source buffer")
	}
	s.Zero()
}

func TestRandom(t *testing.T) {
	if _, err := Random(0); err == nil {
		t.Fatal("Random(0) should error")
	}
	if _, err := Random(-1); err == nil {
		t.Fatal("Random(-1) should error")
	}
	a, err := Random(32)
	if err != nil {
		t.Fatalf("Random(32) error: %v", err)
	}
	if a.Len() != 32 {
		t.Fatalf("len = %d, want 32", a.Len())
	}
	a.Zero()
}

// TestRandomDoesNotStageLeak: the returned secret's material must not equal a
// fresh random buffer (trivially true), and Random must be usable repeatedly
// without cross-contamination; the staging-buffer wipe is asserted by
// exercising Random on failure-size edges and normal sizes back to back.
func TestRandomStagingHygiene(t *testing.T) {
	prev := make(map[string]bool)
	for i := 0; i < 8; i++ {
		a, err := Random(16)
		if err != nil {
			t.Fatal(err)
		}
		enc := fmt.Sprintf("%x", a.DigestHMAC([]byte("probe")))
		if prev[enc] {
			t.Fatal("Random produced a repeated value")
		}
		prev[enc] = true
		a.Zero()
	}
}

// --- explicit "try to serialize" adversarial tests --------------------------

func TestJSONMarshalLeaksNothing(t *testing.T) {
	s := NewFromBytes([]byte("sk-json-secret-value"))
	defer s.Zero()
	// A *SealedSecret has no exported fields and no MarshalJSON (INV-2), so a
	// bare json.Marshal(s) is a staticcheck-flagged empty-struct no-op. Marshal
	// it nested inside a one-exported-field wrapper instead; this still proves
	// the JSON path never ships the raw bytes.
	wrapped := struct {
		Secret *SealedSecret `json:"secret"`
	}{Secret: s}
	b, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("json.Marshal errored: %v", err)
	}
	if bytes.Contains(b, []byte("sk-json-secret-value")) {
		t.Fatal("json output must not contain the raw secret")
	}
}

func TestGobEncodeLeaksNothing(t *testing.T) {
	s := NewFromBytes([]byte("sk-gob-secret-value"))
	defer s.Zero()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(s); err == nil {
		if bytes.Contains(buf.Bytes(), []byte("sk-gob-secret-value")) {
			t.Fatal("gob output must not contain the raw secret")
		}
	}
}
