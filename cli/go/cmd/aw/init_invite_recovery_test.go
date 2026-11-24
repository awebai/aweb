package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestInitJoinFromUnreadableMembershipKeepsRecovery(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	oldName, oldGlobal := initName, initGlobal
	t.Cleanup(func() { initName, initGlobal = oldName, oldGlobal })
	initName, initGlobal = "child", false
	t.Setenv("HOME", t.TempDir())
	wd := t.TempDir()
	home := filepath.Join(wd, ".aw")
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	writeWorkspaceBindingForTest(t, source, workspaceBinding("https://fixture.invalid", "backend:example.com", "source", "workspace-source"))
	path := filepath.Join(home, initInviteRecoveryFile)
	state := &initInviteRecovery{MintedKey: true, ParentFromSource: true, Source: source, TeamID: "backend:example.com", Alias: "child", Scope: "local", Token: "aw_inv_DO_NOT_PRINT", Origin: "https://fixture.invalid", ExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), DIDKey: awid.ComputeDIDKey(pub)}
	if err := state.save(path); err != nil {
		t.Fatal(err)
	}
	certPath := awconfig.TeamCertificatePath(wd, state.TeamID)
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte("broken certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	before := snapshotJoinFiles(t, home)
	var out bytes.Buffer
	err = runRecoverableJoinFrom(authTestCmd(&out), wd, state.Source, state.TeamID)
	if err == nil || !strings.Contains(err.Error(), "load init retry membership") || strings.Contains(err.Error()+out.String(), state.Token) {
		t.Fatalf("unreadable membership was treated as absent: %v", err)
	}
	after := snapshotJoinFiles(t, home)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("unreadable membership released recovery: before=%v after=%v", before, after)
	}
}

func TestInitJoinFromExpiredRecovery(t *testing.T) {
	for _, submitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsubmitted", true: "uncertain"}[submitted], func(t *testing.T) {
			resetTeamHumanCreateGlobals(t)
			oldName, oldGlobal := initName, initGlobal
			t.Cleanup(func() { initName, initGlobal = oldName, oldGlobal })
			initName, initGlobal = "child", false
			t.Setenv("HOME", t.TempDir())
			wd := t.TempDir()
			home := filepath.Join(wd, ".aw")
			pub, key, _ := awid.GenerateKeypair()
			if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
				t.Fatal(err)
			}
			source := t.TempDir()
			writeWorkspaceBindingForTest(t, source, workspaceBinding("https://fixture.invalid", "backend:example.com", "source", "workspace-source"))
			path := filepath.Join(home, initInviteRecoveryFile)
			state := &initInviteRecovery{MintedKey: true, Source: source, TeamID: "backend:example.com", Alias: "child", Scope: "local", Token: "aw_inv_DO_NOT_PRINT", Origin: "https://fixture.invalid", ExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), DIDKey: awid.ComputeDIDKey(pub)}
			if err := state.save(path); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("private record mode: %v %v", info, err)
			}
			if submitted {
				tree, _ := newHostedIDTreeRecovery(hostedIdentityContext{})
				prior := &hostedInviteCreation{AcceptAttempted: &submitted, Tree: tree, TokenHash: "retained", DIDKey: state.DIDKey}
				if err := prior.save(filepath.Join(home, hostedInviteRecoveryFile)); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			err = runRecoverableJoinFrom(authTestCmd(&out), wd, state.Source, state.TeamID)
			if err == nil || !strings.Contains(err.Error(), "expired") {
				t.Fatalf("expiry allowed: %v", err)
			}
			if strings.Contains(err.Error()+out.String(), state.Token) {
				t.Fatal("bearer token leaked")
			}
			_, statErr := os.Stat(path)
			if submitted {
				if statErr != nil {
					t.Fatalf("uncertain record removed: %v", statErr)
				}
				for _, text := range []string{"may have succeeded", hostedInviteRecoveryFile, initInviteRecoveryFile, "fetch-cert", "--identity-home"} {
					if !strings.Contains(err.Error(), text) {
						t.Fatalf("no reconciliation exit %q: %v", text, err)
					}
				}
			} else {
				if !os.IsNotExist(statErr) {
					t.Fatalf("expired unsubmitted record retained: %v", statErr)
				}
				if released, err := releasedInitTarget(wd, awconfig.IdentityHome{Root: home}); err != nil || !released {
					t.Fatalf("released init cannot try a correct invite with its retained key: %v", err)
				}
			}
			after, _ := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
			if !bytes.Equal(after, key) {
				t.Fatal("expiry replaced identity")
			}
		})
	}
}
