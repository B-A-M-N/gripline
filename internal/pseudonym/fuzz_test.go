package pseudonym

import "testing"

func FuzzVersionedPseudonym(f *testing.F) {
	ring, err := NewRing(&Key{Version: 1, Secret: []byte("pseudonym-fuzz-key")})
	if err != nil {
		f.Fatal(err)
	}
	f.Add("source", "198.51.100.7")
	f.Fuzz(func(t *testing.T, family, raw string) {
		value, err := ring.Derive(Family(family), []byte(raw))
		if err == nil {
			_ = ring.Verify(Family(family), []byte(raw), value)
		}
	})
}
