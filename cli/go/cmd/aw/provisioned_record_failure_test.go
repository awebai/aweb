package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestProvisionedMembershipRecordFailureKeepsTheAdmittedIdentity(t *testing.T) {
	directory := t.TempDir()
	output, certificate := writeSelfCustodyIdentityForTest(t, directory, "default:record.example")
	home := awconfig.WorktreeIdentityHome(directory)
	// An actual filesystem obstruction makes the retained membership unreadable.
	if err := os.Mkdir(filepath.Join(home, "teams.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: directory, IdentityHome: explicitEncryptionKeyIdentityHome(home), Output: output, Certificate: certificate, AwebURL: "https://service.example", RegistryURL: "https://registry.example", Binding: membershipWriteWorkspaceBinding})
	if err == nil || !retainUnfinishedProvisioningIdentity(err) {
		t.Fatalf("local record failure would discard an accepted identity: %v", err)
	}
	for _, next := range []string{"id team install-cert --certificate", "workspace connect --service", "Repair that local file error"} {
		if !strings.Contains(err.Error(), next) {
			t.Fatalf("missing recording recovery %q: %v", next, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "signing.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(awconfig.TeamCertificatePath(directory, certificate.Team)); err != nil {
		t.Fatal(err)
	}
}
