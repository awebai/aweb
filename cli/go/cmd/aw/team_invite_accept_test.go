package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// docs/identity.md:237-245 keeps uncertain submissions and successful answers
// available for resumption, while a definitive unsubmitted refusal releases only selection.
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
			for _, path := range []string{recovery, marker} {
				if err := os.WriteFile(path, []byte("selection"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			request := hostedInviteAcceptanceRequest{WorkingDir: root, Home: home, RecoveryPath: recovery, Creation: &hostedInviteCreation{ResponseJSON: scenario.response}}
			err := finishHostedInviteRefusal(request, scenario.history, scenario.cause)
			if !errors.Is(err, scenario.cause) {
				t.Fatalf("lost original refusal: %v", err)
			}
			for _, path := range []string{recovery, marker} {
				_, err := os.Stat(path)
				if scenario.keep {
					if err != nil {
						t.Fatalf("lost retained selection %s: %v", path, err)
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("selection was not released %s: %v", path, err)
				}
			}
		})
	}
}
