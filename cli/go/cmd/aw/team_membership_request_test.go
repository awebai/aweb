package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestAcceptedMembershipValidatesDestinationAndModesBeforeWriting(t *testing.T) {
	for _, kind := range []string{"destination", "activation", "binding"} {
		t.Run(kind, func(t *testing.T) {
			wd := t.TempDir()
			t.Chdir(wd)
			request := acceptedTeamMembershipRequest{WorkingDir: wd, IdentityHome: currentEncryptionKeyIdentityHome(), Output: &teamAcceptInviteOutput{TeamID: "default:example.test", Alias: "child", CertPath: "team-certs/default.cert"}, Certificate: &awid.TeamCertificate{Team: "default:example.test", Alias: "child"}}
			want := ""
			switch kind {
			case "destination":
				request.WorkingDir = ""
				want = "membership recording requires a working directory or identity home"
			case "activation":
				request.Activation = membershipActivation(255)
				want = "membership activation is unknown"
			case "binding":
				request.Binding = membershipWorkspaceBinding(255)
				want = "membership workspace binding is unknown"
			}
			if err := recordAcceptedTeamMembership(request); err == nil || err.Error() != want {
				t.Fatalf("error=%v want=%q", err, want)
			}
			if _, err := os.Stat(filepath.Join(wd, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("invalid request wrote credential state: %v", err)
			}
		})
	}
}
