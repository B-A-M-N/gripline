// Command gripline-test-assertion creates negative-path assertions for the
// compiled release harness. It is a test fixture only; it reads the private
// keyring from a temporary harness directory and is never part of a release.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/terminator"
)

func main() {
	keyringPath := flag.String("keyring", "", "private test keyring")
	audience := flag.String("audience", "", "assertion audience")
	mode := flag.String("mode", "valid", "valid|wrong-audience|wrong-issuer|wrong-kid|forged|wrong-revision")
	flag.Parse()
	if *keyringPath == "" || *audience == "" {
		fmt.Fprintln(os.Stderr, "-keyring and -audience are required")
		os.Exit(2)
	}
	keyring, err := terminator.LoadExistingKeyring(*keyringPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	claims := terminator.Claims{Subject: "harness-account", CredID: "harness-credential", LaneID: "harness-lane", Audience: *audience, JTI: "harness-test-jti", PolicyRev: 1, CredRev: 1, Scope: []string{"inference"}}
	if *mode == "wrong-audience" {
		claims.Audience = "wrong-audience"
	}
	if *mode == "wrong-kid" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		claims.KeyID = 999999
		claims.Issuer = "gripline"
		claims.IssuedAt = time.Now().Unix()
		claims.ExpiresAt = time.Now().Add(10 * time.Second).Unix()
		payload, _ := json.Marshal(claims)
		fmt.Printf("v1.%s.%s\n", base64.RawURLEncoding.EncodeToString(payload), base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload)))
		return
	}
	assertion, err := keyring.Issue(claims, 10*time.Second)
	if err != nil {
		panic(err)
	}
	token := assertion.Encode()
	parts := strings.Split(token, ".")
	if *mode == "forged" {
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sig[0] ^= 0xff
		parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	} else if *mode == "wrong-issuer" {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var altered map[string]any
		_ = json.Unmarshal(payload, &altered)
		altered["iss"] = "wrong-issuer"
		payload, _ = json.Marshal(altered)
		parts[1] = base64.RawURLEncoding.EncodeToString(payload)
		// The modified payload intentionally keeps the old signature. The public
		// verifier must reject it before any altered issuer can authorize.
	}
	fmt.Println(strings.Join(parts, "."))
}
