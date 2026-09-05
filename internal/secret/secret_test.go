package secret

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"reflect"
	"testing"
)

// TestSealedSecretHasNoFormattingOrSerializationSurface backs INV-2: a
// SealedSecret must have no String/Format/Marshal surface, so no logger,
// serializer, or formatter can render the raw bytes. Asserts on the reflected
// method set so a future contributor who adds String() or a Marshaler fails
// here.
func TestSealedSecretHasNoFormattingOrSerializationSurface(t *testing.T) {
	typ := reflect.TypeOf((*SealedSecret)(nil))
	for _, banned := range []string{"Format", "String", "MarshalJSON", "MarshalBinary", "GobEncode", "MarshalText", "AppendText"} {
		if _, ok := typ.MethodByName(banned); ok {
			t.Fatalf("SealedSecret must not implement %s (INV-2)", banned)
		}
	}
}

// TestStructHasNoExportedFields ensures json/gob cannot ship contents via
// exported fields.
func TestStructHasNoExportedFields(t *testing.T) {
	typ := reflect.TypeOf(SealedSecret{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath == "" {
			t.Fatalf("field %q is exported; SealedSecret fields must be unexported (INV-2)", f.Name)
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

// --- explicit "try to serialize" adversarial tests --------------------------

func TestJSONMarshalLeaksNothing(t *testing.T) {
	s := NewFromBytes([]byte("sk-json-secret-value"))
	defer s.Zero()
	b, err := json.Marshal(s)
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
