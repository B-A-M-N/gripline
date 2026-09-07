package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-A-M-N/gripline/internal/keyexport"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// validPepper is a base64-encoded 40-byte key (>= 32 decoded bytes of entropy).
const validPepper = testPepperEnv

func TestAcceptanceKeysExportIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "keyring.json")
	configPath := filepath.Join(dir, "config.json")
	configBody := `{"listen":"127.0.0.1:8080","backend":{"url":"http://backend.invalid:80","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"tls":{"terminate_tls_upstream":true},"paths":{"signer_keyring":"` + keyringPath + `"}}`
	if err := os.WriteFile(configPath, []byte(configBody), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := runKeysExport(configPath); err == nil || errors.Is(err, errSubcommand) {
		t.Fatal("missing keyring must fail without creating a signing identity")
	}
	if _, err := os.Stat(keyringPath); !os.IsNotExist(err) {
		t.Fatalf("read-only export created keyring: stat err=%v", err)
	}

	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runKeysExport(configPath); !errors.Is(err, errSubcommand) {
			t.Fatalf("successful export returned %v", err)
		}
	})
	var exported keyexport.Export
	if err := json.Unmarshal([]byte(out), &exported); err != nil {
		t.Fatalf("export JSON: %v", err)
	}
	if exported.ActiveKID != kr.ActiveKid() || len(exported.Keys) == 0 {
		t.Fatalf("unexpected public export: %+v", exported)
	}
	if strings.Contains(out, "private") || strings.Contains(out, "active") && strings.Contains(out, "seed") {
		t.Fatalf("export contains private-key material: %s", out)
	}
}

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
