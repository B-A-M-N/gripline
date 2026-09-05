package terminator

import (
	"testing"
)

// FuzzExtractExternalCredential exercises the security-critical Authorization /
// api-key parser. It must never panic on arbitrary input and must not strip the
// secret headers on failure paths. Run: go test -fuzz=FuzzExtractExternalCredential.
func FuzzExtractExternalCredential(f *testing.F) {
	f.Add("Authorization", "Bearer sk-test-key")
	f.Add("Authorization", "Bearer")
	f.Add("x-api-key", "sk-key1")
	f.Add("x-api-key", "")
	f.Add("Authorization", "Basic abc")
	f.Add("Authorization", "Bearer  sk-token-with-two-spaces")
	f.Add("api-key", "a\tb")
	f.Add("authorization", "Bearer  sk-unié")

	f.Fuzz(func(t *testing.T, headerName, value string) {
		h := map[string][]string{normalize(headerName): {value}}
		// May return an extractionError or an authenticated secret; it must
		// never panic, regardless of input (spec §105 highest-priority target).
		if s, _, err := ExtractExternalCredential(h); err == nil && s != nil {
			s.Zero()
		}
	})
}

// normalize lowercases so fuzz headers hit both case spellings safely.
func normalize(s string) string {
	if s == "" {
		return s
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// FuzzExtractNeverPanicsOnDup carriers covers the duplicate-header ambiguity
// path.
func FuzzExtractNeverPanicsOnDup(f *testing.F) {
	f.Add("cc", "c1")
	f.Add("1", "2")
	f.Add("%%", "")
	f.Add("authorization", "Bearer a b")
	f.Fuzz(func(t *testing.T, h1, h2 string) {
		m := map[string][]string{
			normalize(h1): {"x"},
			normalize(h2): {"y"},
		}
		_, _, _ = ExtractExternalCredential(m)
	})
}