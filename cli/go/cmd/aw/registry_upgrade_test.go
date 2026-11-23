package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestRegistryUpgradeFrom13658(t *testing.T) {
	t.Run("implicit local init", testLegacyLocalRegistryUpgrade)
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

func testLegacyLocalRegistryUpgrade(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AWEB_IDENTITY_HOME", "")
	t.Setenv("AWID_REGISTRY_URL", "")
	t.Setenv("APP_ENV", "production")
	t.Setenv("AWEB_FEDERATION_TEST", "")
	const teamID = "default:local"
	const teamPath = "/v1/namespaces/local/teams/default"
	var mu sync.Mutex
	var teamKey, memberDID string
	var lists, resolves atomic.Int32
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/v1/namespaces/local" || r.URL.Path == teamPath):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(body)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams":
			var body struct {
				TeamKey string `json:"team_did_key"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			teamKey = body.TeamKey
			_ = json.NewEncoder(w).Encode(map[string]string{"domain": "local", "name": "default", "team_did_key": teamKey})
		case r.Method == http.MethodPost && r.URL.Path == teamPath+"/certificates":
			var body struct {
				MemberDID string `json:"member_did_key"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			memberDID = body.MemberDID
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && (r.URL.Path == "/health" || r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat"):
			_, _ = fmt.Fprint(w, `{}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]string{"team_id": teamID, "alias": "alice", "agent_id": "agent-1", "workspace_id": "ws-1", "team_did_key": teamKey})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1", teamID, "alice")
		case r.Method == http.MethodGet && r.URL.Path == teamPath+"/certificates":
			lists.Add(1)
			_, _ = fmt.Fprint(w, `{"certificates":[]}`)
		case r.Method == http.MethodGet && r.URL.Path == teamPath+"/members/alice":
			resolves.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"alias": "alice", "member_did_key": memberDID, "identity_scope": "local"})
		default:
			t.Errorf("unexpected fixture request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := func(binary string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir = root
		cmd.Env = append(testCommandEnv(home), "AW_NO_UPDATE_CHECK=1", "AWEB_API_KEY=", "AWEB_URL="+registry.URL)
		return cmd
	}
	if released := os.Getenv("AW_TEST_AW_13658"); released != "" {
		cmd := command(released, "init", "--new-team", "--name", "alice", "--do-not-touch-agents-md", "--json")
		cmd.Env = append(cmd.Env, "AWID_REGISTRY_URL="+registry.URL)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("released implicit init: %v\n%s", err, out)
		}
	} else {
		// Use the released wire shape in routine tests. Set AW_TEST_AW_13658
		// to exercise the actual released writer against the same endpoints.
		t.Setenv("AWID_REGISTRY_URL", registry.URL)
		if _, err := runImplicitLocalInit(implicitLocalInitRequest{WorkingDir: root, AwebURL: registry.URL, RegistryURL: registry.URL, Alias: "alice"}); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWID_REGISTRY_URL", "")
		controllerPath, err := awconfig.ControllerMetaPath("local")
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{controllerPath, awconfig.TeamStatePath(root)} {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var legacy []string
			for _, line := range strings.Split(string(data), "\n") {
				field := strings.TrimSpace(line)
				if strings.HasPrefix(field, "registry_operator_origin:") || (path != controllerPath && strings.HasPrefix(field, "registry_url:")) {
					continue
				}
				legacy = append(legacy, line)
			}
			if err := os.WriteFile(path, []byte(strings.Join(legacy, "\n")), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	state, err := awconfig.LoadTeamState(root)
	if err != nil {
		t.Fatal(err)
	}
	if membership := state.Membership(teamID); membership == nil || membership.RegistryURL != "" {
		t.Fatalf("released implicit init did not leave its registry in controller metadata only: %#v", membership)
	}
	controller, err := awconfig.LoadControllerMeta("local")
	if err != nil || controller.RegistryURL != registry.URL || !controller.LegacyRegistryOrigin {
		t.Fatalf("expected the released controller record with the init origin: %#v, %v", controller, err)
	}
	if _, err := os.Stat(filepath.Join(root, awconfig.DefaultWorktreeIdentityRelativePath())); !os.IsNotExist(err) {
		t.Fatalf("implicit local init should have no identity.yaml: %v", err)
	}
	current := filepath.Join(t.TempDir(), awBinaryNameForTest())
	buildAwBinary(t, ctx, current)
	t.Run("later command", func(t *testing.T) {
		cmd := command(current, "id", "team", "members", "--json")
		if out, err := cmd.CombinedOutput(); err != nil || lists.Load() != 1 {
			t.Fatalf("later CLI did not list members at the original registry: %v\n%s", err, out)
		}
	})
	checkWake := func(t *testing.T) {
		t.Helper()
		client, _, err := wakeIdentityClient(ctx, awconfig.WorktreeIdentityHome(root), teamID, func(_ context.Context, stored string) (string, error) { return stored, nil })
		if err != nil {
			t.Fatal(err)
		}
		delivery := client.Resolver().(*awid.ChainResolver).DeliveryTeamRegistry
		delivery.DNSResolver = failingTXTResolver{}
		before := resolves.Load()
		got, err := delivery.Resolve(ctx, teamID+"/alice")
		if err != nil || got.RegistryURL != registry.URL || resolves.Load() != before+1 {
			t.Fatalf("wake did not resolve the local team at the original registry: %#v, %v", got, err)
		}
	}
	t.Run("wake identity", checkWake)
	t.Run("wake after team state rewrite", func(t *testing.T) {
		if err := awconfig.SaveTeamState(root, state); err != nil {
			t.Fatal(err)
		}
		checkWake(t)
	})
}
