package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestInitGlobalExpiredInvitePreservesExistingHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	home := t.TempDir()
	bin := filepath.Join(home, awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did, stable := awid.ComputeDIDKey(pub), awid.ComputeStableID(pub)
	const team = "shared:aweb.ai"
	source, target := t.TempDir(), t.TempDir()
	writeSelectionFixtureForTest(t, source, testSelectionFixture{AwebURL: "https://unused.invalid", TeamID: team, Alias: "source", DID: did, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: key})
	writeIdentityForTest(t, target, awconfig.WorktreeIdentity{DID: did, StableID: stable, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryStatus: "registered"})
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(target), key); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(target, ".aw")
	if err := os.WriteFile(filepath.Join(root, initInviteRecoveryFile+".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	before := snapshotJoinFiles(t, root)
	state := map[string]any{"source": source, "source_home": "", "team_id": team, "alias": "child", "scope": "global", "token": "aw_inv_expired", "origin": "https://unused.invalid", "expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "did_key": did, "minted_key": false}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, initInviteRecoveryFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, bin, "init", "--join-from", source, "--global", "--name", "child", "--json")
	command.Dir, command.Env = target, append(testCommandEnv(home), "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AW_NO_UPDATE_CHECK=1")
	if out, err := command.CombinedOutput(); err == nil || !strings.Contains(string(out), "invite expired") {
		t.Fatalf("expired global init: %v\n%s", err, out)
	}
	if after := snapshotJoinFiles(t, root); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused global init changed the existing identity home:\nbefore=%v\nafter=%v", before, after)
	}
}

func TestInitGlobalJoinFromLocalParentRefusesBeforeInviteOrHomeWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	home := t.TempDir()
	bin := filepath.Join(home, awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	v := loadWhoVectors(t)
	seed, _ := hex.DecodeString(v.Keys["coordinator"].SeedHex)
	parentKey := ed25519.NewKeyFromSeed(seed)
	parent := v.Keys["coordinator"].DIDKey
	pub, key, _ := awid.GenerateKeypair()
	did, stable := awid.ComputeDIDKey(pub), awid.ComputeStableID(pub)
	const team = "shared:example.com"
	var previews, accepts, creates atomic.Int32
	service := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/spawn/create-invite" {
			creates.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "token": "aw_inv_explicit_source", "id_tree": map[string]any{"v": 1, "issuer_id": parent, "domain": "example.com", "child_kind": "agent", "mode": "self_custodial"}})
			return
		}
		if r.URL.Path != "/api/v1/spawn/invite-preview" {
			accepts.Add(1)
			http.Error(w, "must refuse before submission", 500)
			return
		}
		previews.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": team, "identity_scope": "unknown", "server_url": origin, "status": "active", "id_tree": map[string]any{"v": 1, "issuer_id": parent, "domain": "example.com", "child_kind": "agent", "mode": "self_custodial"}})
	})
	source, target := t.TempDir(), t.TempDir()
	writeSelectionFixtureForTest(t, source, testSelectionFixture{AwebURL: service.URL, TeamID: team, Alias: "parent", DID: parent, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: parentKey})
	if err := awconfig.SaveInstalledIDChain(filepath.Join(source, ".aw"), map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}); err != nil {
		t.Fatal(err)
	}
	writeIdentityForTest(t, target, awconfig.WorktreeIdentity{DID: did, StableID: stable, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryStatus: "registered"})
	root := filepath.Join(target, ".aw")
	if err := awid.SaveSigningKey(filepath.Join(root, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	before := snapshotJoinFiles(t, root)
	for attempt := 0; attempt < 2; attempt++ {
		command := exec.CommandContext(ctx, bin, "init", "--join-from", source, "--global", "--name", "child", "--json")
		command.Dir, command.Env = target, append(testCommandEnv(home), "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AW_NO_UPDATE_CHECK=1")
		out, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "unregistered_parent") || !strings.Contains(string(out), "aw id parent request --human") || !strings.Contains(string(out), "registered source") {
			t.Fatalf("explicit local parent: %v\n%s", err, out)
		}
		if after := snapshotJoinFiles(t, root); !reflect.DeepEqual(before, after) {
			t.Fatalf("impossible parent choice changed the existing home: before=%v after=%v", before, after)
		}
	}
	if accepts.Load() != 0 || previews.Load() != 0 || creates.Load() != 0 {
		t.Fatalf("impossible parent choice made create=%d preview=%d submit=%d calls", creates.Load(), previews.Load(), accepts.Load())
	}
}

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
