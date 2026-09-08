package terminator

import (
	"context"
	"testing"

	"github.com/B-A-M-N/gripline/internal/control"
)

type fixedPostureAuthority struct {
	posture control.Posture
	err     error
}

func (a fixedPostureAuthority) PostureContext(context.Context) (control.Posture, error) {
	return a.posture, a.err
}

func TestExplicitPostureAuthorityOverridesLocalControlCache(t *testing.T) {
	local := control.New(32)
	term, raw := m6Terminator(t, local)
	term.dep.Posture = fixedPostureAuthority{posture: control.EmergencyLockdown}

	out := term.Admit(bearerHeaders(raw), laneFeatures("AS-REMOTE-POSTURE"))
	if out.Authorized {
		t.Fatal("admission used the local NORMAL cache instead of the explicit posture authority")
	}
	if out.Reason != "emergency_lockdown" {
		t.Fatalf("denial reason=%q, want emergency_lockdown", out.Reason)
	}
}

func TestPostureAuthorityErrorFailsClosed(t *testing.T) {
	local := control.New(32)
	term, raw := m6Terminator(t, local)
	term.dep.Posture = fixedPostureAuthority{err: context.DeadlineExceeded}

	out := term.Admit(bearerHeaders(raw), laneFeatures("AS-POSTURE-TIMEOUT"))
	if out.Authorized {
		t.Fatal("admission succeeded while the posture authority was unavailable")
	}
	if out.Reason != "control_unavailable" {
		t.Fatalf("denial reason=%q, want control_unavailable", out.Reason)
	}
}
