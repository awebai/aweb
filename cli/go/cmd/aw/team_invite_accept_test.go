package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// The invitation selection follows the submission history. The acceptance-minted
// key marker remains in every refusal case (docs/identity.md, Acceptance-minted key recovery).
func TestHostedInviteRefusalPreservesSubmissionHistoryAndRetainedAnswers(t *testing.T) {
	mismatch := &awid.IDCertificateError{Code: "human_mismatch"}
	unavailable := errors.New("registry unavailable")
	cases := []struct {
		name     string
		history  hostedInviteSubmissionHistory
		response string
		cause    error
		keep     bool
	}{
		{"unsubmitted condition refusal releases selection", hostedSubmissionNotAttempted, "", mismatch, false},
		{"condition refusal without submission record releases selection", hostedSubmissionUnknown, "", mismatch, false},
		{"earlier submission keeps selection", hostedSubmissionAttempted, "", mismatch, true},
		{"unknown evidence keeps selection", hostedSubmissionNotAttempted, "", unavailable, true},
		{"retained answer keeps selection", hostedSubmissionNotAttempted, "retained-success", mismatch, true},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			root := t.TempDir()
			home := awconfig.IdentityHome{Root: filepath.Join(root, "identity")}
			if err := os.MkdirAll(home.Root, 0o700); err != nil {
				t.Fatal(err)
			}
			recovery := filepath.Join(home.Root, hostedInviteRecoveryFile)
			marker := filepath.Join(home.Root, acceptanceKeyMarkerName)
			if err := os.WriteFile(recovery, []byte("selection"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marker, []byte("acceptance minted this key"), 0o600); err != nil {
				t.Fatal(err)
			}
			request := hostedInviteAcceptanceRequest{WorkingDir: root, Home: home, RecoveryPath: recovery, Creation: &hostedInviteCreation{ResponseJSON: scenario.response}}
			err := finishHostedInviteRefusal(request, scenario.history, scenario.cause)
			if !errors.Is(err, scenario.cause) {
				t.Fatalf("lost original refusal: %v", err)
			}
			keptMarker, err := os.ReadFile(marker)
			if err != nil || string(keptMarker) != "acceptance minted this key" {
				t.Fatalf("acceptance key marker changed: %q, %v", keptMarker, err)
			}
			selection, err := os.ReadFile(recovery)
			if scenario.keep {
				if err != nil || string(selection) != "selection" {
					t.Fatalf("retained selection changed: %q, %v", selection, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("selection was not released %s: %v", recovery, err)
			}
		})
	}
}
