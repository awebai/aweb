package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestInitGlobalInviteTargetRefusalsBeforeIssuance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	home := t.TempDir()
	bin := filepath.Join(home, awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	var calls atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "target must be checked before issuing an invite", http.StatusInternalServerError)
	}))
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did, stable := awid.ComputeDIDKey(pub), awid.ComputeStableID(pub)
	const team = "shared:aweb.ai"
	source := t.TempDir()
	writeSelectionFixtureForTest(t, source, testSelectionFixture{AwebURL: server.URL, TeamID: team, Alias: "source", DID: did, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: key})
	for _, outcome := range []string{"join-from", "admission", "invite"} {
		for _, state := range []string{"missing", "local", "key-mismatch", "connected"} {
			t.Run(outcome+"/"+state, func(t *testing.T) {
				target := t.TempDir()
				want := "requires an existing global identity"
				if state != "missing" {
					identity := awconfig.WorktreeIdentity{DID: did, StableID: stable, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: server.URL}
					if state == "local" {
						identity.StableID, identity.IdentityScope = "", awid.IdentityModeLocal
					}
					if state == "key-mismatch" {
						other, _, err := awid.GenerateKeypair()
						if err != nil {
							t.Fatal(err)
						}
						identity.DID = awid.ComputeDIDKey(other)
						want = "does not match identity.yaml"
					}
					writeIdentityForTest(t, target, identity)
					if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(target), key); err != nil {
						t.Fatal(err)
					}
					if state == "connected" {
						if err := os.WriteFile(awconfig.WorktreeWorkspacePath(target), []byte("aweb_url: "+server.URL+"\n"), 0600); err != nil {
							t.Fatal(err)
						}
						want = "refusing to overwrite existing " + awconfig.WorktreeWorkspacePath(target)
					}
				}
				before := snapshotJoinFiles(t, filepath.Join(target, ".aw"))
				args := []string{"init", "--global", "--name", "alice", "--json"}
				if outcome == "join-from" {
					args = append(args, "--join-from", source)
				} else if outcome == "admission" {
					args = append(args, "--admission-team-id", team, "--expect-account", "acct-test")
				} else {
					args = append(args, "--invite", hostedJoinTokenForTest(t, "aw_inv_global", server.URL))
				}
				command := exec.CommandContext(ctx, bin, args...)
				command.Dir, command.Env = target, append(testCommandEnv(home), "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AWID_REGISTRY_URL="+server.URL, "AW_NO_UPDATE_CHECK=1")
				if out, err := command.CombinedOutput(); err == nil || !strings.Contains(string(out), want) {
					t.Fatalf("target refusal: %v\n%s\nwant %s", err, out, want)
				}
				after := snapshotJoinFiles(t, filepath.Join(target, ".aw"))
				for path, digest := range before {
					if after[path] != digest {
						t.Errorf("refusal changed %s", path)
					}
				}
				if state == "missing" {
					if _, err := os.Stat(awconfig.WorktreeSigningKeyPath(target)); !os.IsNotExist(err) {
						t.Errorf("refused global join created a signing key: %v", err)
					}
				}
			})
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid target made %d network calls", calls.Load())
	}
}
