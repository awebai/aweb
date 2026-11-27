package main

import (
	"bytes"
	"encoding/json"
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

// A released `aw team admin add` or `extend` saved its own roster recovery in
// the child's identity home: first the selection, then again with the minted
// token before acceptance. This aw cannot finish that operation, so a join
// retry must refuse either phase before it rewrites the record or admits the
// token, and keep the home for the released aw to finish.
func TestInitJoinFromRefusesAReleasedRosterRecovery(t *testing.T) {
	for _, phase := range []string{"selection", "minted token"} {
		t.Run(phase, func(t *testing.T) {
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
			record := map[string]any{"roster": true, "parent_from_source": false, "minted_key": false, "source": source, "source_home": "", "team_id": "backend:example.com", "alias": "child", "scope": "global", "token": "", "origin": "", "did_key": awid.ComputeDIDKey(pub)}
			if phase == "minted token" {
				record["token"] = "aw_inv_DO_NOT_PRINT"
			}
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, initInviteRecoveryFile)
			if err := (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: home}, Name: initInviteRecoveryFile}).Write(raw); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
				t.Fatal(err)
			}
			before := snapshotJoinFiles(t, home)
			var out bytes.Buffer
			err = runRecoverableJoinFrom(authTestCmd(&out), wd, source, "backend:example.com")
			if err == nil || !strings.Contains(err.Error(), "released aw") || strings.Contains(err.Error()+out.String(), "aw_inv_DO_NOT_PRINT") {
				t.Fatalf("released roster recovery was not refused: %v", err)
			}
			if after := snapshotJoinFiles(t, home); !reflect.DeepEqual(before, after) {
				t.Fatalf("refusal changed the home: before=%v after=%v", before, after)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("refusal removed the recovery record: %v", err)
			}
		})
	}
}

// An ordinary join recovery still loads; only a released roster record is refused.
func TestInitInviteRecoveryLoadsAnOrdinaryJoinRecord(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, initInviteRecoveryFile)
	state := &initInviteRecovery{Source: t.TempDir(), TeamID: "backend:example.com", Alias: "child", Scope: "local", Token: "aw_inv_DO_NOT_PRINT"}
	if err := state.save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadInitInviteRecovery(path)
	if err != nil || loaded == nil || loaded.Token != state.Token {
		t.Fatalf("ordinary join recovery: %+v, %v", loaded, err)
	}
}
