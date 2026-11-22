package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestRegistryUpgradeFrom13658(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "")
	t.Setenv("AWEB_IDENTITY_HOME", "")
	t.Setenv("APP_ENV", "production")
	t.Setenv("AWEB_FEDERATION_TEST", "")
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	const teamID = "backend:local"
	publicKey, privateKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did, stableID := awid.ComputeDIDKey(publicKey), awid.ComputeStableID(publicKey)
	var requests atomic.Int32
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/log"):
			fmt.Fprint(w, `[]`)
		case r.URL.Path == "/v1/namespaces/local/addresses/alice":
			json.NewEncoder(w).Encode(map[string]string{"did_aw": stableID, "current_did_key": did})
		case strings.HasPrefix(r.URL.Path, "/v1/did/"):
			json.NewEncoder(w).Encode(map[string]string{"did_aw": stableID, "current_did_key": did})
		default:
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	binding := workspaceBinding(registry.URL, teamID, "alice", "workspace-id")
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), privateKey); err != nil {
		t.Fatal(err)
	}
	writeWorkspaceBindingForTest(t, root, binding)
	// This is the released v1.36.58 identity.yaml shape. Its URL was
	// supplied through the environment for creation only.
	identityPath := filepath.Join(root, awconfig.DefaultWorktreeIdentityRelativePath())
	writeIdentity := func(registryURL string) {
		t.Helper()
		raw := fmt.Sprintf("schema_version: 2\ndid: %s\nstable_id: %s\naddress: local/alice\ncustody: self\nidentity_scope: global\nregistry_url: %q\nregistry_status: registered\ncreated_at: '2026-04-04T00:00:00Z'\n", did, stableID, registryURL)
		if err := os.WriteFile(identityPath, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeIdentity(registry.URL)

	t.Run("later command", func(t *testing.T) {
		before := requests.Load()
		out, err := loadDIDLog(context.Background(), root, nil)
		if err != nil || out.Status == "UNREACHABLE" || requests.Load() != before+1 {
			t.Fatalf("stored registry not reached: %#v, %v", out, err)
		}
	})
	t.Run("wake identity", func(t *testing.T) {
		client, _, err := wakeIdentityClient(context.Background(), filepath.Dir(identityPath), teamID, func(_ context.Context, stored string) (string, error) {
			return stored, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		resolver := client.Resolver().(*awid.ChainResolver).Registry
		got, err := resolver.Resolve(context.Background(), "local/alice")
		if err != nil || got.StableID != stableID {
			t.Fatalf("wake could not resolve through stored registry: %#v, %v", got, err)
		}
	})
	t.Run("invite membership stays pinned", func(t *testing.T) {
		writeIdentity("")
		state, err := awconfig.LoadTeamState(root)
		if err != nil {
			t.Fatal(err)
		}
		state.Membership(teamID).RegistryURL = registry.URL
		if err := awconfig.SaveTeamState(root, state); err != nil {
			t.Fatal(err)
		}
		client, _, err := wakeIdentityClient(context.Background(), filepath.Dir(identityPath), teamID, func(_ context.Context, stored string) (string, error) {
			return stored, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		before := requests.Load()
		resolver := client.Resolver().(*awid.ChainResolver).DeliveryTeamRegistry
		_, err = resolver.Resolve(context.Background(), teamID+"/alice")
		if err == nil || !strings.Contains(err.Error(), "must use https") || requests.Load() != before {
			t.Fatalf("invite registry was not refused at the pinned transport: %v", err)
		}
	})
	t.Run("operator choice persists after the environment is removed", func(t *testing.T) {
		identity := &awconfig.WorktreeIdentity{DID: did, StableID: stableID, Address: "local/alice", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: registry.URL}
		t.Setenv("AWID_REGISTRY_URL", registry.URL)
		if err := saveWorktreeIdentityWithRegistryOrigin(identityPath, identity); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWID_REGISTRY_URL", "")
		before := requests.Load()
		out, err := loadDIDLog(context.Background(), root, nil)
		if err != nil || out.Status == "UNREACHABLE" || requests.Load() != before+1 {
			t.Fatalf("saved operator origin didn't reach registry: %#v, %v", out, err)
		}
	})
	t.Run("new unmarked identity stays pinned until repaired", func(t *testing.T) {
		writeIdentity(registry.URL)
		identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
		if err != nil {
			t.Fatal(err)
		}
		identity.RegistryOperatorOrigin = ""
		if err := awconfig.SaveWorktreeIdentityTo(identityPath, identity); err != nil {
			t.Fatal(err)
		}
		before := requests.Load()
		out, err := loadDIDLog(context.Background(), root, nil)
		if err != nil || out.Status != "UNREACHABLE" || !strings.Contains(out.Error, awid.RegistryTrustCommand) || requests.Load() != before {
			t.Fatalf("unmarked stored origin was not refused with repair guidance: %#v, %v", out, err)
		}
		home := awconfig.IdentityHome{Root: filepath.Dir(identityPath)}
		if err := markStoredRegistryOrigin(home, registry.URL); err != nil {
			t.Fatal(err)
		}
		out, err = loadDIDLog(context.Background(), root, nil)
		if err != nil || out.Status == "UNREACHABLE" || requests.Load() != before+1 {
			t.Fatalf("explicit repair didn't reach registry: %#v, %v", out, err)
		}
	})

}
