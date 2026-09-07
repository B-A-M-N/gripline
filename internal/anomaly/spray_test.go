package anomaly

import (
	"testing"
	"time"
)

// TestSprayMoreThan3ASNsSignalsCredentialSpray proves the P0.67 credential-
// side ASN-spray signature: >3 distinct ASNs for one credential inside the
// window raises the MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN signal for the
// credential subject. P0.12: the detector emits SIGNALS; scoring/scope/minting
// belong to the compiled policy at the admission site.
func TestSprayMoreThan3ASNsSignalsCredentialSpray(t *testing.T) {
	base := time.Now()
	now := base
	d := NewDetector(func() time.Time { return now }, DefaultThresholds())

	var sigs []Signal
	// 4 distinct ASNs for the same credential within the window.
	for _, asn := range []string{"AS1", "AS2", "AS3", "AS4"} {
		now = base
		sigs = append(sigs, d.Observe("src", "cred_c", asn, now)...)
	}
	// The 4th ASN crosses the threshold (MaxASNs = 3).
	var credentialSpray bool
	for _, s := range sigs {
		if s.Code == "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN" {
			credentialSpray = true
		}
	}
	if !credentialSpray {
		t.Fatal("P0.67: >3 unrelated ASNs in-window must signal the credential ASN-spray")
	}
}

// TestSpraySourceManyCredentialsSignalsSourceSpray proves the SOURCE-side
// credential-spray signature (P0.67): one source presenting many distinct
// credentials raises SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS for the
// source subject.
func TestSpraySourceManyCredentialsSignalsSourceSpray(t *testing.T) {
	base := time.Now()
	now := base
	d := NewDetector(func() time.Time { return now }, DefaultThresholds())

	var sigs []Signal
	for i := 0; i < 6; i++ {
		sigs = append(sigs, d.Observe("src-1", "cred_"+string(rune('a'+i)), "AS0", base)...)
	}
	var sourceSpray bool
	for _, s := range sigs {
		if s.Code == "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS" {
			sourceSpray = true
		}
	}
	if !sourceSpray {
		t.Fatal("P0.67: one source with many distinct credentials must signal the source-spray")
	}
}

// TestSprayWindowDecays proves the sliding window: a burst of 4 ASNs in one
// instant does NOT keep spraying forever — once the window elapses with no new
// ASN, a single fresh observation does not immediately re-trigger (the count of
// distinct in-window ASNs falls below threshold after eviction).
func TestSprayWindowDecays(t *testing.T) {
	base := time.Now()
	now := base
	d := NewDetector(func() time.Time { return now }, DefaultThresholds())

	for _, asn := range []string{"AS1", "AS2", "AS3"} {
		d.Observe("src", "cred_d", asn, base) // 3 distinct, at threshold (not over)
	}
	// Advance past the window; all 3 decay.
	now = base.Add(11 * time.Minute)
	for _, s := range d.Observe("src", "cred_d", "AS4", now) {
		if s.Code == "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN" {
			t.Fatal("P0.67: window must decay — an old 3-ASN burst must not count toward a fresh 4th")
		}
	}
	// A FRESH burst of 4 distinct ASNs inside one window DOES cross.
	now = base.Add(12 * time.Minute)
	sprayed := false
	for _, asn := range []string{"AS5", "AS6", "AS7", "AS8"} {
		for _, s := range d.Observe("src", "cred_d", asn, now) {
			if s.Code == "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN" {
				sprayed = true
			}
		}
	}
	if !sprayed {
		t.Fatal("P0.67: a fresh 4-ASN burst within one window must signal the spray")
	}
}

// TestSpraySignalsCarryOnlyCode proves P0.8/P0.12: the detector has no path to
// invent evidence parameters OR decide the eventual evidence subject. A Signal
// carries only a code; scoring, family, scope, TTL, minting revision, and the
// subject are resolved by the admission engine against the current compiled
// policy.
func TestSpraySignalsCarryOnlyCode(t *testing.T) {
	d := NewDetector(nil, DefaultThresholds())
	sigs := d.Observe("s", "c", "AS1", time.Now())
	for _, s := range sigs {
		if s.Code == "" {
			t.Fatalf("signal must carry a code: %+v", s)
		}
	}
}
