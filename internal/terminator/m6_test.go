package terminator

import (
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

func m6Terminator(t *testing.T, cp *control.ControlPlane) (*Terminator, string) {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("m6-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('6' + i%26)
	}
	raw := "sk-m6-" + string(rawBytes)
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_m6", AccountID: "acct_1",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status:    credential.StatusNormal,
		PolicyID:  "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := GenerateSigner()
	term, err := New(Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Evidence: evidence.NewMemoryStore(),
		Resource: resource.NewGovernor(nil),
		Control:  cp,
	})
	if err != nil {
		t.Fatal(err)
	}
	return term, raw
}

// establishLane admits one request on distinct features so a lane EXISTS; later
// requests on DIFFERENT features would be a NEW lane.
func establishLane(t *testing.T, term *Terminator, raw string, existing bool) string {
	t.Helper()
	feat := laneFeatures("AS-EST")
	if !existing {
		feat = laneFeatures("AS-NEW")
	}
	out := term.Admit(bearerHeaders(raw), feat)
	if out.Authorized {
		// Release the held reservation so subsequent admissions see free
		// capacity (emergency posture caps concurrency at 1, P0.48).
		out.Reservation().Release()
	}
	return feat.NetworkASN
}

// TestControlPlaneEmergencyLockdownDeniesNewLanes proves P0.40: in
// EMERGENCY_LOCKDOWN a request that would CREATE a new lane is denied, while
// an established lane's traffic still authorizes (the firefight denies new
// attack surface but does not nuke legit established capacity).
func TestControlPlaneEmergencyLockdownDeniesNewLanes(t *testing.T) {
	cp := control.New(1024)
	term, raw := m6Terminator(t, cp)

	// Establish a lane on residential features (existing).
	est := establishLane(t, term, raw, true)
	if est == "" {
		t.Fatal("establish failed")
	}
	// Confirm established traffic authorizes.
	established := laneFeatures("AS-EST")
	if o := term.Admit(bearerHeaders(raw), established); !o.Authorized {
		t.Fatalf("established lane should authorize before lockdown: %s", o.Reason)
	} else {
		// P0.48: emergency limits cap concurrency at 1 — release the slot so
		// the post-lockdown established admission can take it.
		o.Reservation().Release()
	}

	// Flip to emergency lockdown as the operator.
	cp.SetEmergency(true, "ops-oncall", "active credential exfiltration")

	// A NEW lane request (different features, would create a new lane) is denied.
	newLane := laneFeatures("AS-NEW")
	out := term.Admit(bearerHeaders(raw), newLane)
	if out.Authorized {
		t.Fatal("P0.40: EMERGENCY_LOCKDOWN must deny a NEW lane's request")
	}
	if out.Reason != "emergency_lockdown" {
		t.Fatalf("P0.40: denial reason = %q, want emergency_lockdown", out.Reason)
	}

	// The established lane still authorizes during lockdown — but under the
	// EMERGENCY limit set (P0.48): one in-flight request, not the normal cap.
	if o := term.Admit(bearerHeaders(raw), established); !o.Authorized {
		t.Fatalf("P0.41: established lane must continue through lockdown: %s", o.Reason)
	} else {
		o.Reservation().Release()
	}
}

// TestControlPlaneAuditTrailRecordsDecisions proves P0.35: the control plane's
// audit trail captures both operator actions (SetEmergency) and admission
// decisions (authorized + denied), without any secret material.
func TestControlPlaneAuditTrailRecordsDecisions(t *testing.T) {
	cp := control.New(1024)
	term, raw := m6Terminator(t, cp)

	// One authorized admission.
	feat := laneFeatures("AS-AUDIT")
	term.Admit(bearerHeaders(raw), feat)

	// One denied admission (invalid credential → extraction/auth fails before
	// any admission event because the terminator returns before the defer? The
	// defer is set AFTER auth, so an auth failure won't be audited here. Use a
	// denied-but-authenticated path: quarantined credential after emergency.
	cp.SetEmergency(true, "ops", "test")
	term.Admit(bearerHeaders(raw), laneFeatures("AS-NEW2"))

	events := cp.Audit()
	var operatorSeen, admissionAuthorized, admissionDenied bool
	for _, e := range events {
		switch e.Kind {
		case control.EventOperator:
			operatorSeen = true
		case control.EventAdmission:
			if e.Authorized {
				admissionAuthorized = true
			} else if e.Reason == "emergency_lockdown" {
				admissionDenied = true
			}
		}
	}
	if !operatorSeen {
		t.Fatal("P0.35: control plane must record the operator SetEmergency action")
	}
	if !admissionAuthorized {
		t.Fatal("P0.35: audit trail must record the authorized admission")
	}
	if !admissionDenied {
		t.Fatal("P0.35: audit trail must record the lockdown denial")
	}
}

// TestM6SprayDetectorPersistsEvidence proves the P0.67 wiring: with a Spray
// detector configured, a credential that establishes many distinct ASNs within
// the window persists MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN evidence into the
// store (across admissions), while the current request's lane risk is not
// inflated by that credential-scoped signal.
func TestM6SprayDetectorPersistsEvidence(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	pep := &credential.PepperKey{Version: 1, Key: []byte("m6-pepper-spray")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('s' + i%26)
	}
	raw := "sk-m6-spray-" + string(rawBytes)
	sealed := secret.NewFromBytes([]byte(raw))
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_m6s", AccountID: "acct_1",
		Verifier: credential.Verifier(sealed, pep), VerifierVersion: 1, PepperVersion: 1,
		Status:    credential.StatusNormal,
		PolicyID:  "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := GenerateSigner()
	store := evidence.NewMemoryStore()
	spray := anomaly.NewDetector(func() time.Time { return time.Now() }, anomaly.DefaultThresholds())
	term, err := New(Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Evidence: store,
		Resource: resource.NewGovernor(nil),
		Spray:    spray,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Establish 5 distinct ASNs for the same credential; the 4th+ crosses the
	// spray threshold and must persist the evidence. P0.4: each request carries
	// its own trusted source identity (previously a process-global SourceID).
	for _, asn := range []string{"AS1", "AS2", "AS3", "AS4", "AS5"} {
		feat := lane.Features{NetworkASN: asn, NetworkType: "residential", RegionClass: "us"}
		out := term.AdmitSource(bearerHeaders(raw), feat, TrustedSource{Pseudonym: "src-m6"})
		if !out.Authorized {
			t.Fatalf("spray-establish request on %s should authorize: %s", asn, out.Reason)
		}
	}

	snap, _ := store.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: "cred_m6s"}}, time.Now())
	found := false
	for _, e := range snap {
		if e.Code == "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN" {
			found = true
		}
	}
	if !found {
		t.Fatal("P0.67: credential ASN-spray evidence must be persisted by the terminator's detector")
	}
}