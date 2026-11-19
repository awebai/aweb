package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestStdoutCaptureHelpersLargeOutput(t *testing.T) {
	for _, helper := range []struct {
		name    string
		capture func(*testing.T, func()) string
	}{
		{name: "terminal", capture: captureStdout},
		{name: "identity_command", capture: captureIDCommandStdout},
		{name: "identity_address", capture: captureIDAddressStdout},
		{name: "team_members", capture: captureTeamMembersStdout},
	} {
		t.Run(helper.name, func(t *testing.T) {
			want := strings.Repeat("captured stdout\n", 1<<19)
			got := helper.capture(t, func() {
				written, err := io.WriteString(os.Stdout, want)
				if err != nil {
					t.Fatal(err)
				}
				if written != len(want) {
					t.Fatalf("wrote %d stdout bytes, want %d", written, len(want))
				}
			})
			if got != want {
				t.Fatalf("captured stdout differs: got %d bytes, want %d", len(got), len(want))
			}
		})
	}
}
