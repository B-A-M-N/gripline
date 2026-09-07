package main

import (
	"strings"
	"testing"
)

// validPepper is a base64-encoded 40-byte key (>= 32 decoded bytes of entropy).
const validPepper = testPepperEnv

// TestAcceptancePepperEntropyRequired (P0-17) proves the runtime refuses to
// boot on weak or mis-encoded pepper material: raw ASCII passphrases, short
// decoded keys, and invalid base64 are all boot ERRORS — never silently
// accepted as low-entropy verifier pepper.
func TestAcceptancePepperEntropyRequired(t *testing.T) {
	cases := map[string]string{
		"raw ascii passphrase":  "a-simple-passphrase-not-encoded",
		"base64 but too short":  "c2hvcnQ=",                 // decodes to 5 bytes
		"base64 16 bytes":       "MDEyMzQ1Njc4OWFiY2RlZg==", // 16 bytes — below the 32-byte floor
		"invalid base64":        "not!!valid@base64!!",
		"empty after expansion": "",
	}
	for name, pepper := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := ephemeralConfigForPepperTest(t)
			t.Setenv("GRIPLINE_PEPPER_V1", pepper)
			if _, err := BuildRuntime(cfg); err == nil {
				t.Fatalf("pepper %q (%s) must be a boot error", pepper, name)
			} else if !strings.Contains(err.Error(), "GRIPLINE_PEPPER_V1") {
				t.Fatalf("error must name the offending variable, got %v", err)
			}
		})
	}

	// The valid pepper boots.
	cfg := ephemeralConfigForPepperTest(t)
	t.Setenv("GRIPLINE_PEPPER_V1", validPepper)
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("valid pepper must boot, got %v", err)
	}
	_ = rt.Close()
}

// TestAcceptancePseudonymKeySeparation (P0-17) proves the ingress pseudonym
// key must (a) meet the same entropy floor and (b) DIFFER from the credential
// pepper — one secret across two cryptographic domains lets a value in either
// domain be replayed into the other.
func TestAcceptancePseudonymKeySeparation(t *testing.T) {
	t.Run("same key as pepper rejected", func(t *testing.T) {
		cfg := ephemeralConfigForPepperTest(t)
		cfg.Ingress = ingressConfig(t, validPepper)
		t.Setenv("GRIPLINE_PEPPER_V1", validPepper)
		if _, err := BuildRuntime(cfg); err == nil {
			t.Fatal("pseudonym key equal to the pepper must be a boot error")
		} else if !strings.Contains(err.Error(), "key separation") {
			t.Fatalf("error must name key separation, got %v", err)
		}
	})
	t.Run("weak pseudonym key rejected", func(t *testing.T) {
		cfg := ephemeralConfigForPepperTest(t)
		cfg.Ingress = ingressConfig(t, "c2hvcnQ=") // 5 decoded bytes
		t.Setenv("GRIPLINE_PEPPER_V1", validPepper)
		if _, err := BuildRuntime(cfg); err == nil {
			t.Fatal("weak pseudonym key must be a boot error")
		}
	})
	t.Run("distinct strong key accepted", func(t *testing.T) {
		cfg := ephemeralConfigForPepperTest(t)
		cfg.Ingress = ingressConfig(t, "Z3JpcGxpbmUtcHNldWRvbnltLWtleS0wMTIzNDU2Nzg5YWJjZGVmZ2hp")
		t.Setenv("GRIPLINE_PEPPER_V1", validPepper)
		rt, err := BuildRuntime(cfg)
		if err != nil {
			t.Fatalf("distinct strong pseudonym key must boot, got %v", err)
		}
		_ = rt.Close()
	})
}
