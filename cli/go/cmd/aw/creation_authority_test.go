package main

import (
	"context"
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreationAuthorityDecision(t *testing.T) {
	const notice = "Using this workspace's signed invitation; the supplied agent API key is not creating the child."
	const a5 = "This is an agent's workspace key. Run creation from that agent's workspace, or use a setup key from the dashboard. To create here from another workspace, use aw init --join-from <workspace>."
	for _, tc := range []struct {
		name    string
		input   creationAuthorityInput
		mode    string
		notice  string
		refusal string
	}{
		{"stored key is not an input", creationAuthorityInput{SourceTeam: "dev:example.com"}, "invitation", "", ""},
		{"no key with signer", creationAuthorityInput{SourceTeam: "dev:example.com", RequestedTeam: "dev:example.com"}, "invitation", "", ""},
		{"workspace key with signer", creationAuthorityInput{SuppliedKey: true, KeyKind: "workspace", SourceTeam: "dev:example.com", RequestedTeam: "dev:example.com"}, "invitation", notice, ""},
		{"workspace key without signer", creationAuthorityInput{SuppliedKey: true, KeyKind: "workspace"}, "", "", a5},
		{"workspace key wrong team", creationAuthorityInput{SuppliedKey: true, KeyKind: "workspace", SourceTeam: "dev:example.com", RequestedTeam: "ops:example.com"}, "", "", "This workspace belongs to dev:example.com, not ops:example.com. " + a5},
		{"person key wins", creationAuthorityInput{SuppliedKey: true, KeyKind: "person", SourceTeam: "dev:example.com"}, "api", "", ""},
		{"absent field older server", creationAuthorityInput{SuppliedKey: true, SourceTeam: "dev:example.com"}, "api", "", ""},
		{"unknown field older behavior", creationAuthorityInput{SuppliedKey: true, KeyKind: "future", SourceTeam: "dev:example.com"}, "api", "", ""},
		{"stale team kind is unknown", creationAuthorityInput{SuppliedKey: true, KeyKind: "team", SourceTeam: "dev:example.com"}, "api", "", ""},
		{"local controller", creationAuthorityInput{SourceTeam: "dev:example.com", LocalController: true}, "controller", "", ""},
		{"founding with workspace key", creationAuthorityInput{SuppliedKey: true, KeyKind: "workspace", Founding: true, SourceTeam: "dev:example.com"}, "", "", "An agent's workspace key cannot found a new team. Use a setup key from the dashboard, a namespace controller with aw team admin create --byot --namespace <domain>, or the signed aw id team create --hosted operation."},
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
		{"init", []string{"init", "--name", "child", "--json", "--do-not-touch-agents-md"}, creationA5},
		{"add", []string{"team", "admin", "add", "child:local", "--json"}, creationA5},
		{"extend", []string{"team", "admin", "extend", "child:local", "--api-key", "aw_sk_agent", "--json"}, creationA5},
		{"create", []string{"team", "admin", "create", "newteam", "--json"}, creationFoundingRefusal},
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
			got, err := resolveAgentCreation(t.TempDir(), "aw_sk_input", server.URL, "", false)
			if err != nil || got.Mode != "api" || got.Notice != "" {
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
