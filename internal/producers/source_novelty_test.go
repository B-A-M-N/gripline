package producers

import "testing"

func TestSourceNoveltyEmitsSourceContinuitySignalWithoutASN(t *testing.T) {
	p := NewSourceNoveltyProducer(nil)
	base := AdmissionBehavior{Subjects: SubjectContext{CredentialID: "cred", SourceID: "source-a"}}
	if got := p.ObserveAdmission(base); len(got) != 0 {
		t.Fatalf("first source established a signal: %v", got)
	}
	base.Subjects.SourceID = "source-b"
	got := p.ObserveAdmission(base)
	if len(got) != 1 || got[0].Code != "NEW_SOURCE" {
		t.Fatalf("second source signal=%v", got)
	}
}
