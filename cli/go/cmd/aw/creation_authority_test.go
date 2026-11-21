package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestCreationAuthorityDecision(t *testing.T) {
	const notice = "Using this workspace's signed invitation; the supplied agent API key is not creating the child."
	const a5 = "This is an agent's workspace key. Run creation from that agent's workspace, or use a setup key from the dashboard. To create here from another workspace, use aw init --join-from <workspace>."
	for _, tc := range []struct {
		name    string
		input   creationAuthorityInput
		mode    creationAuthorityMode
		notice  string
		refusal string
	}{
		{"stored key is not an input", creationAuthorityInput{SourceTeam: "dev:example.com"}, creationAuthorityInvitation, "", ""},
		{"no key with signer", creationAuthorityInput{SourceTeam: "dev:example.com", RequestedTeam: "dev:example.com"}, creationAuthorityInvitation, "", ""},
		{"workspace key with signer", creationAuthorityInput{SuppliedKey: true, KeyKind: creationKeyKindWorkspace, SourceTeam: "dev:example.com", RequestedTeam: "dev:example.com"}, creationAuthorityInvitation, notice, ""},
		{"workspace key without signer", creationAuthorityInput{SuppliedKey: true, KeyKind: creationKeyKindWorkspace}, creationAuthorityUnselected, "", a5},
		{"workspace key wrong team", creationAuthorityInput{SuppliedKey: true, KeyKind: creationKeyKindWorkspace, SourceTeam: "dev:example.com", RequestedTeam: "ops:example.com"}, creationAuthorityUnselected, "", "This workspace belongs to dev:example.com, not ops:example.com. " + a5},
		{"person key wins", creationAuthorityInput{SuppliedKey: true, KeyKind: creationKeyKindPerson, SourceTeam: "dev:example.com"}, creationAuthorityAPI, "", ""},
		{"absent field older server", creationAuthorityInput{SuppliedKey: true, SourceTeam: "dev:example.com"}, creationAuthorityAPI, "", ""},
		{"unknown field older behavior", creationAuthorityInput{SuppliedKey: true, KeyKind: "future", SourceTeam: "dev:example.com"}, creationAuthorityAPI, "", ""},
		{"stale team kind is unknown", creationAuthorityInput{SuppliedKey: true, KeyKind: "team", SourceTeam: "dev:example.com"}, creationAuthorityAPI, "", ""},
		{"local controller", creationAuthorityInput{SourceTeam: "dev:example.com", LocalController: true}, creationAuthorityController, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decideCreationAuthority(tc.input)
			if tc.refusal != "" {
				if err == nil || err.Error() != tc.refusal {
					t.Fatalf("error=%v, want %q", err, tc.refusal)
				}
				return
			}
			if err != nil || got.Mode != tc.mode || got.Notice != tc.notice {
				t.Fatalf("decision=%+v err=%v", got, err)
			}
		})
	}
}

func TestCreationCommandsWorkspaceKeyWithoutSignerRefuseBeforeWrites(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"add", []string{"team", "admin", "add", "child:local", "--json"}, creationA5},
		{"extend", []string{"team", "admin", "extend", "child:local", "--api-key", "aw_sk_agent", "--json"}, creationA5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/teams/current" {
					json.NewEncoder(w).Encode(map[string]any{"team_id": "00000000-0000-4000-8000-000000000001", "canonical_team_id": "dev:example.com", "api_key_kind": "workspace"})
					return
				}
				t.Errorf("unexpected request before refusal: %s %s", r.Method, r.URL.Path)
				http.Error(w, "unexpected", 500)
			}))
			bin := filepath.Join(t.TempDir(), "aw")
			buildAwBinary(t, context.Background(), bin)
			cmd := exec.Command(bin, tc.args...)
			cmd.Dir = root
			cmd.Env = append(testCommandEnv(t.TempDir()), "AWEB_URL="+server.URL, "AWEB_API_KEY=aw_sk_agent")
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err=%v output=%s; want %s", err, out, tc.want)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("refusal wrote target: %v %v", entries, err)
			}
		})
	}
}

func TestCreationAuthorityLegacyAndPersonMetadataKeepAPIPath(t *testing.T) {
	for _, kind := range []string{"person", "", "future", "team"} {
		t.Run(kind, func(t *testing.T) {
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/teams/current" {
					t.Errorf("unexpected request %s", r.URL)
					http.Error(w, "unexpected", 500)
					return
				}
				body := map[string]any{"team_id": "00000000-0000-4000-8000-000000000001", "canonical_team_id": "dev:example.com"}
				if kind != "" {
					body["api_key_kind"] = kind
				}
				json.NewEncoder(w).Encode(body)
			}))
			got, err := resolveAgentCreation(agentCreationRequest{WorkingDir: t.TempDir(), APIKey: "aw_sk_input", AwebURL: server.URL})
			if err != nil || got.Mode != creationAuthorityAPI || got.Notice != "" {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestTeamExtendNeverChoosesCreatorByDirectoryOrder(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	root := t.TempDir()
	for _, name := range []string{"alice", "zebra"} {
		home := filepath.Join(root, "agents", "instances", name)
		if err := awconfig.SaveTeamState(home, &awconfig.TeamState{ActiveTeam: "dev:example.com", Memberships: []awconfig.TeamMembership{{TeamID: "dev:example.com", Alias: name, CertPath: awconfig.TeamCertificateRelativePath("dev:example.com")}}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, swapped := range []bool{false, true} {
		if swapped {
			first := filepath.Join(root, "agents", "instances", "alice")
			last := filepath.Join(root, "agents", "instances", "zebra")
			if err := os.Rename(first, first+"-swap"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(last, first); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(first+"-swap", last); err != nil {
				t.Fatal(err)
			}
		}
		_, err := resolveTeamExtendAuthority(root)
		if err == nil {
			t.Fatal("extend silently selected a sibling as creator")
		}
		for _, want := range []string{"choose the creating workspace", filepath.Join(root, "agents", "instances", "alice"), filepath.Join(root, "agents", "instances", "zebra")} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v missing %q", err, want)
			}
		}
		if _, err := os.Stat(filepath.Join(root, "agents", "instances", "child")); !os.IsNotExist(err) {
			t.Fatalf("wrote a child before choosing creator: %v", err)
		}

	}
}

func TestTeamHumanCreateExistingFoundingPathIgnoresAmbientWorkspaceKey(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	dir := whoIdentity(t, loadWhoVectors(t), false, true)
	t.Chdir(dir)
	reads := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		http.Error(w, "API path must not replace founding authority", 500)
	}))
	t.Setenv("AWEB_API_KEY", "aw_sk_workspace")
	t.Setenv("AWEB_URL", server.URL)
	before := fileDigestsForTest(t, filepath.Join(dir, ".aw"))
	err := runTeamHumanCreate(nil, []string{"newteam"})
	if err == nil || !strings.Contains(err.Error(), "hosted-managed for namespace example.com") || reads != 0 {
		t.Fatalf("existing namespace founding replaced by API: reads=%d err=%v", reads, err)
	}
	if after := fileDigestsForTest(t, filepath.Join(dir, ".aw")); !reflect.DeepEqual(before, after) {
		t.Fatal("founding refusal changed existing identity")
	}
}

func TestInitExternalCreationRequiresExplicitJoinAndPreservesCreatorKeyRefusal(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	source := t.TempDir()
	writeWorkspaceBindingForTest(t, source, workspaceBinding("http://127.0.0.1:1", "dev:example.com", "source", "workspace-source"))
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(source, ".aw", "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	old := activeIdentityHome
	t.Cleanup(func() { activeIdentityHome = old })
	activeIdentityHome = awconfig.IdentityHome{Root: filepath.Join(source, ".aw"), Source: awconfig.IdentityHomeFlag}
	t.Chdir(t.TempDir())
	err = validateInitOutcomeFlags(initInviteInput{})
	if err == nil || !strings.Contains(err.Error(), "only supported for --workspace-team or explicit fresh --join-from") {
		t.Fatalf("implicit creation did not refuse the external identity home: %v", err)
	}
	activeIdentityHome = awconfig.IdentityHome{}
	t.Setenv(awconfig.IdentityHomeEnv, "")
	_, err = resolveAgentCreation(agentCreationRequest{WorkingDir: source})
	if err == nil || err.Error() != "workspace signing key does not match its team certificate" {
		t.Fatalf("creator resolution hid the key mismatch: %v", err)
	}
}

func TestCreationWorkspaceKeyDoesNotHideMalformedSource(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".aw", "teams.yaml"), []byte("active_team: ["), 0600); err != nil {
		t.Fatal(err)
	}
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"team_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "dev:example.com", "api_key_kind": "workspace"})
	}))
	if _, err := resolveAgentCreation(agentCreationRequest{WorkingDir: root, APIKey: "aw_sk_workspace", AwebURL: server.URL}); err == nil {
		t.Fatal("malformed source enabled API bootstrap")
	}
}
