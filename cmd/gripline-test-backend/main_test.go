package main

import (
	"net/http"
	"testing"
)

func TestValidVerifierControlTokenRejectsDuplicateValues(t *testing.T) {
	const expected = "control-secret"

	valid := make(http.Header)
	valid.Set("X-Gripline-Verifier-Control", expected)
	if !validVerifierControlToken(valid, expected) {
		t.Fatal("one exact control-token value should be accepted")
	}

	duplicate := make(http.Header)
	duplicate.Add("X-Gripline-Verifier-Control", expected)
	duplicate.Add("X-Gripline-Verifier-Control", "attacker-value")
	if validVerifierControlToken(duplicate, expected) {
		t.Fatal("duplicate control-token values must be rejected")
	}

	commaFolded := make(http.Header)
	commaFolded.Set("X-Gripline-Verifier-Control", expected+", attacker-value")
	if validVerifierControlToken(commaFolded, expected) {
		t.Fatal("comma-folded control-token values must be rejected")
	}

	caseVariant := http.Header{"x-gripline-verifier-control": {expected}}
	if !validVerifierControlToken(caseVariant, expected) {
		t.Fatal("control-token matching must be case-insensitive")
	}
}
