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
