package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestInviteInspectionReportsAClosedOutputAndPreservesItsRefusal(t *testing.T) {
	for _, format := range []struct {
		Name string
		JSON bool
	}{{Name: "json", JSON: true}, {Name: "text"}} {
		t.Run(format.Name, func(t *testing.T) {
			previousJSON := jsonFlag
			jsonFlag = format.JSON
			t.Cleanup(func() { jsonFlag = previousJSON })
			file, err := os.Create(filepath.Join(t.TempDir(), "inspection"))
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetOut(file)
			refusal := &inviteInspectError{Code: "malformed_token", Message: "Pass the invite token on stdin, not as an argument.", exit: 2}
			result := &inviteInspection{Kind: "controller", CanonicalTeamID: "one:example.test", IdentityScope: "unknown", Status: "unverified"}
			err = reportInviteInspectError(cmd, result, refusal)
			if !errors.Is(err, os.ErrClosed) || exitCode(err) != 2 || !strings.Contains(err.Error(), "check the output destination and retry") {
				t.Fatalf("output failure or original exit code lost: %v", err)
			}
			var retained *inviteInspectError
			if !errors.As(err, &retained) || retained != refusal {
				t.Fatalf("lost the original refusal: %v", err)
			}
			var good strings.Builder
			cmd.SetOut(&good)
			if err := reportInviteInspectError(cmd, result, refusal); err != refusal {
				t.Fatalf("valid output changed the refusal: %v", err)
			}
			if good.Len() == 0 {
				t.Fatal("valid output produced no inspection")
			}
		})
	}
}
