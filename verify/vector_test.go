package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestImmutableWireVector(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Version   string `json:"version"`
		Audience  string `json:"audience"`
		Now       int64  `json:"now"`
		PublicKey string `json:"public_key"`
		Payload   string `json:"payload"`
		Token     string `json:"token"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Version != AssertionWireVersion || vector.Payload == "" {
		t.Fatalf("invalid vector metadata: %+v", vector)
	}
	pub, err := base64.StdEncoding.DecodeString(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewKeySet(map[int]ed25519.PublicKey{3: pub}, 3)
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(set, vector.Audience)
	if err != nil {
		t.Fatal(err)
	}
	v.WithClock(func() time.Time { return time.Unix(vector.Now, 0) })
	r := httptest.NewRequest("POST", "http://backend/v1/messages", nil)
	r.Header.Set(AssertionHeader, vector.Token)
	claims, err := v.Verify(r)
	if err != nil {
		t.Fatalf("immutable vector rejected: %v", err)
	}
	if claims.CredID != "cred-vector" || claims.PolicyRev != 7 || claims.CredRev != 11 {
		t.Fatalf("unexpected vector claims: %+v", claims)
	}
}
