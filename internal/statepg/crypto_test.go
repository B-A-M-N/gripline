package statepg

import "testing"

func TestCryptoIdentityValidation(t *testing.T) {
	valid := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "signer",
		PepperActiveVersion: 1, PepperFingerprint: "pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if err := validateCryptoIdentity(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.PepperActiveVersion = 0
	if err := validateCryptoIdentity(invalid); err == nil {
		t.Fatal("zero pepper generation must be rejected")
	}
	if sameCryptoIdentity(valid, invalid) {
		t.Fatal("different active generations must not compare equal")
	}
}

func TestCryptoIdentitySeparatesActiveAndLoadedGenerations(t *testing.T) {
	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "signer-1",
		PepperActiveVersion: 1, PepperFingerprint: "pepper-1",
		PseudonymVersion: 1, PseudonymFingerprint: "pseudonym-1",
		Loaded: []CryptoGeneration{
			{Kind: CryptoKindSigner, Generation: 1, Fingerprint: "signer-1"},
			{Kind: CryptoKindSigner, Generation: 2, Fingerprint: "signer-2"},
			{Kind: CryptoKindPepper, Generation: 1, Fingerprint: "pepper-1"},
			{Kind: CryptoKindPepper, Generation: 2, Fingerprint: "pepper-2"},
			{Kind: CryptoKindPseudonym, Generation: 1, Fingerprint: "pseudonym-1"},
			{Kind: CryptoKindPseudonym, Generation: 2, Fingerprint: "pseudonym-2"},
		},
	}
	if err := validateCryptoIdentity(identity); err != nil {
		t.Fatalf("staged generations should be valid: %v", err)
	}
	if err := validateCryptoIdentity(CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "signer-1",
		PepperActiveVersion: 1, PepperFingerprint: "pepper-1",
		PseudonymVersion: 1, PseudonymFingerprint: "pseudonym-1",
		Loaded: []CryptoGeneration{{Kind: CryptoKindSigner, Generation: 2, Fingerprint: "signer-2"}},
	}); err == nil {
		t.Fatal("an active generation absent from loaded capabilities must be rejected")
	}
}
