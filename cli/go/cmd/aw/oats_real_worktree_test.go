package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestOATSRealWorktreeAdmissionFailureRetainsIssuedMember(t *testing.T) {
	input := newRecoveryWorktree(t)
	world := newRealCommandWorld(t)
	source := world.addLocalMember(t, "parent")
	t.Setenv("HOME", world.UserHome)
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerMeta(world.Domain, &awconfig.ControllerMeta{RegistryURL: world.Stack.RegistryURL}); err != nil {
		t.Fatal(err)
	}
	input.WorkingDir, input.CreatorHome = filepath.Dir(source.Home), awconfig.IdentityHome{Root: source.Home, Source: awconfig.IdentityHomeFlag}
	input.TeamID, input.ServerURL = world.TeamID, closedWorktreeEndpoint(t)
	_, connectErr := addWorktreeViaLocalTeamKey(input)
	if connectErr == nil || !retainUnfinishedProvisioningIdentity(connectErr) || !strings.Contains(connectErr.Error(), workspaceConnectCommandForIdentityHome(input.ServerURL, awconfig.WorktreeIdentityHome(input.WorktreePath))) {
		t.Fatalf("issued member lacks its exact connect recovery: %v", connectErr)
	}
	home := awconfig.WorktreeIdentityHome(input.WorktreePath)
	key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	if err != nil {
		t.Fatalf("admission failure removed its recipient: %v", err)
	}
	requireRegisteredRecoveryWorktree(t, input)
	invitesDir, err := awconfig.DefaultTeamInvitesDir()
	if err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(invitesDir)
	if err != nil {
		t.Fatal(err)
	}
	var issued *awconfig.TeamInviteIssuance
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		invite, err := awconfig.LoadTeamInvite(strings.TrimSuffix(file.Name(), ".json"))
		if err != nil {
			t.Fatal(err)
		}
		fence, err := awconfig.InspectTeamInviteIssuance(invite)
		if err != nil {
			t.Fatal(err)
		}
		if fence != nil && fence.Context.IdentityHome == home {
			if issued != nil {
				t.Fatal("worktree issued more than one enrollment")
			}
			issued = fence
		}
	}
	if issued == nil || issued.State != awconfig.RecoveryConfirmed || issued.PreparedEffect.MemberDIDKey != didOf(key) {
		t.Fatal("admission failure did not retain the exact confirmed certificate and key")
	}
	status, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", issued.PreparedEffect.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "active" {
		t.Fatalf("admission failure revoked the member without ordered retirement: %s", status.Status)
	}
}
