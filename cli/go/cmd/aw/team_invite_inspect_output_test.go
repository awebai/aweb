package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIErrorResultReportsClosedOutputForPartialInviteInspection(t *testing.T) {
	for _, format := range []struct {
		Name string
		JSON bool
	}{{Name: "json", JSON: true}, {Name: "text"}} {
		t.Run(format.Name, func(t *testing.T) {
			file, err := os.Create(filepath.Join(t.TempDir(), "inspection"))
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			refusal := &inviteInspectError{Code: "malformed_token", Message: "Pass the invite token on stdin, not as an argument.", exit: 2}
			result := &inviteInspection{Kind: "controller", CanonicalTeamID: "one:example.test", IdentityScope: "unknown", Status: "unverified"}
			failure := &inviteInspectionFailure{inviteInspectError: refusal, invite: result}
			output := cliErrorResult{Refusal: failure, Message: failure.Error(), JSON: format.JSON}
			err = writeCLIErrorResult(file, output)
			if !errors.Is(err, os.ErrClosed) || !strings.Contains(err.Error(), "check the output destination and retry") {
				t.Fatalf("output failure lost: %v", err)
			}
			var good strings.Builder
			if err := writeCLIErrorResult(&good, output); err != nil {
				t.Fatalf("valid output failed: %v", err)
			}
			if good.Len() == 0 {
				t.Fatal("valid output produced no inspection")
			}
		})
	}
}
