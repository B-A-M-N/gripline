package main

import (
	"strings"
	"testing"
)

func TestVersionStringIncludesBuildMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, buildCommit, buildDate
	version, buildCommit, buildDate = "v1.2.3", "abc123", "2026-09-07T00:00:00Z"
	t.Cleanup(func() { version, buildCommit, buildDate = oldVersion, oldCommit, oldDate })
	got := versionString()
	for _, want := range []string{"gripline v1.2.3", "commit abc123", "built 2026-09-07T00:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Fatalf("version output %q missing %q", got, want)
		}
	}
}
