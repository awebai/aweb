package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestOATSRealProvisioningCommandsRetainKeyAfterCertificateWriteFailure(t *testing.T) {
	for _, mode := range []string{"workspace add-worktree", "team admin add"} {
		t.Run(mode, func(t *testing.T) {
			world := newRealCommandWorld(t)
			source := world.addLocalMember(t, "issuer")
			t.Setenv("HOME", world.UserHome)
			if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
				t.Fatal(err)
			}
			if err := awconfig.SaveControllerMeta(world.Domain, &awconfig.ControllerMeta{RegistryURL: world.Stack.RegistryURL}); err != nil {
				t.Fatal(err)
			}
			const alias = "recipient"
			workDir := filepath.Dir(source.Home)
			target := filepath.Join(t.TempDir(), alias)
			args := []string{"team", "admin", "add", alias + ":local", "--home", target}
			if mode == "workspace add-worktree" {
				workDir = filepath.Join(t.TempDir(), "repo")
				if err := os.MkdirAll(workDir, 0o700); err != nil {
					t.Fatal(err)
				}
				initGitRepoWithOriginAndCommit(t, workDir, "https://example.invalid/receipt.git")
				var err error
				target, err = deriveWorkspaceAddWorktreePath(workDir, alias)
				if err != nil {
					t.Fatal(err)
				}
				args = []string{"workspace", "add-worktree", "--name", alias}
			}
			home := awconfig.WorktreeIdentityHome(target)
			certPath, err := awconfig.TeamCertificatePathFromIdentityHome(home, world.TeamID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "workspace add-worktree" {
				// Git creates the worktree before the command mints its member.
				// A checkout hook injects an actual directory at the future file.
				hook := filepath.Join(workDir, ".git", "hooks", "post-checkout")
				if err := os.WriteFile(hook, []byte("#!/bin/sh\n"+formatShellCommand([]string{"mkdir", "-p", certPath})+"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.MkdirAll(certPath, 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(world.Context, world.Binary, append([]string{"--identity-home", source.Home, "--json"}, args...)...)
			cmd.Dir = workDir
			cmd.Env = append(idCreateCommandEnv(world.UserHome), "AWID_REGISTRY_URL="+world.Stack.RegistryURL, "AW_NO_UPDATE_CHECK=1")
			var stderr strings.Builder
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err == nil {
				t.Fatalf("certificate write unexpectedly succeeded: %s", out)
			}
			member, lookupErr := world.Registry.ResolveTeamMember(world.Context, world.Stack.RegistryURL, world.Domain, "backend", alias, world.TeamKey)
			if lookupErr != nil || member.CertificateID == "" {
				t.Fatalf("failure did not follow confirmed issuance: %v / %#v\n%s\n%s", lookupErr, member, out, stderr.String())
			}
			if mode == "workspace add-worktree" {
				var refusal cliErrorEnvelope
				if json.Unmarshal(out, &refusal) != nil || refusal.Error.Code != "certificate_persistence_incomplete" {
					t.Fatalf("worktree lost its certificate recovery code: %s", out)
				}
				requireRegisteredRecoveryWorktree(t, worktreeAgentCreation{RepoRoot: workDir, BranchName: alias})
			}
			if !strings.Contains(stderr.String(), "run `aw id team fetch-cert") || !strings.Contains(stderr.String(), member.CertificateID) {
				t.Fatalf("recover the exact certificate from the retained home: %s", stderr.String())
			}
			key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
			if err != nil {
				t.Fatalf("rollback removed the recipient signing key: %v", err)
			}
			if err := os.Remove(certPath); err != nil {
				t.Fatal(err)
			}
			world.requireCommand(t, home, "id", "team", "fetch-cert", "--namespace", world.Domain, "--team", "backend", "--cert-id", member.CertificateID, "--registry", world.Stack.RegistryURL)
			if restored, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home, world.TeamID); err != nil || restored.CertificateID != member.CertificateID || restored.MemberDIDKey != didOf(key) {
				t.Fatalf("retained home could not recover its exact issued certificate: %#v; %v", restored, err)
			}
		})
	}
}

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
