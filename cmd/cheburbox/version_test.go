package main

import (
	"bytes"
	"testing"

	"github.com/Arsolitt/cheburbox/internal/buildinfo"
)

func TestVersionCommandOutput(t *testing.T) {
	tests := []struct {
		name    string
		version string
		commit  string
		want    string
	}{
		{
			name:    "default build",
			version: "dev",
			commit:  "none",
			want:    "cheburbox dev (none)\n",
		},
		{
			name:    "release build",
			version: "v0.1.0",
			commit:  "abc1234",
			want:    "cheburbox v0.1.0 (abc1234)\n",
		},
		{
			name:    "snapshot build",
			version: "v0.1.1-snapshot.deadbee",
			commit:  "deadbee",
			want:    "cheburbox v0.1.1-snapshot.deadbee (deadbee)\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setBuildinfo(t, tt.version, tt.commit)

			var stdout, stderr bytes.Buffer

			cmd := NewRootCommand()
			cmd.SetArgs([]string{"version"})
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)

			if err := cmd.Execute(); err != nil {
				t.Fatalf("version failed: %v\nstderr=%s", err, stderr.String())
			}
			if got := stdout.String(); got != tt.want {
				t.Errorf("output = %q, want %q", got, tt.want)
			}
		})
	}
}

// setBuildinfo overrides the build stamps for one test and restores the
// previous values when the test finishes.
func setBuildinfo(t *testing.T, version, commit string) {
	t.Helper()

	origVersion, origCommit := buildinfo.Version, buildinfo.Commit
	t.Cleanup(func() {
		buildinfo.Version = origVersion
		buildinfo.Commit = origCommit
	})

	buildinfo.Version = version
	buildinfo.Commit = commit
}
