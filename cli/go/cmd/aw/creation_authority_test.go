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
	const mismatch = "workspace signing key does not match its team certificate"
	const dev, ops = "dev:example.com", "ops:example.com"
	const key, other = "did:key:z6MkCreator", "did:key:z6MkOther"
	workspaceKey := func(in creationAuthorityInput) creationAuthorityInput {
		in.SuppliedKey, in.KeyKind = true, creationKeyKindWorkspace
		return in
	}
	for _, tc := range []struct {
		name    string
		input   creationAuthorityInput
		mode    creationAuthorityMode
		source  string
		notice  string
		refusal string
	}{
		{"no key and no membership selects nothing", creationAuthorityInput{}, creationAuthorityUnselected, "", "", ""},
		{"no key, member signer", creationAuthorityInput{ActiveTeam: dev, SigningKeyDID: key, CertificateDID: key}, creationAuthorityInvitation, dev, "", ""},
		{"no key, member signer for the requested team", creationAuthorityInput{RequestedTeam: dev, ActiveTeam: dev, SigningKeyDID: key, CertificateDID: key}, creationAuthorityInvitation, dev, "", ""},
		{"no key, member signer for another team selects nothing", creationAuthorityInput{RequestedTeam: ops, ActiveTeam: dev, SigningKeyDID: key, CertificateDID: key}, creationAuthorityUnselected, "", "", ""},
		{"no key, local controller", creationAuthorityInput{ActiveTeam: dev, LocalController: true}, creationAuthorityController, dev, "", ""},
		{"local controller never reads the certificate", creationAuthorityInput{ActiveTeam: dev, LocalController: true, SigningKeyDID: key, CertificateDID: other}, creationAuthorityController, dev, "", ""},
		{"membership without signing key is not a signer", creationAuthorityInput{ActiveTeam: dev}, creationAuthorityUnselected, "", "", ""},
		{"signing key without membership is not a signer", creationAuthorityInput{SigningKeyDID: key}, creationAuthorityUnselected, "", "", ""},
		{"signing key differs from certificate", creationAuthorityInput{ActiveTeam: dev, SigningKeyDID: key, CertificateDID: other}, creationAuthorityUnselected, "", "", mismatch},
		{"certificate without member key", creationAuthorityInput{ActiveTeam: dev, SigningKeyDID: key}, creationAuthorityUnselected, "", "", mismatch},
		{"workspace key with signer", workspaceKey(creationAuthorityInput{RequestedTeam: dev, ActiveTeam: dev, SigningKeyDID: key, CertificateDID: key}), creationAuthorityInvitation, dev, notice, ""},
		{"workspace key requests its own team", workspaceKey(creationAuthorityInput{KeyTeam: dev, ActiveTeam: dev, SigningKeyDID: key, CertificateDID: key}), creationAuthorityInvitation, dev, notice, ""},
		{"workspace key with local controller", workspaceKey(creationAuthorityInput{KeyTeam: dev, ActiveTeam: dev, LocalController: true}), creationAuthorityController, dev, notice, ""},
		{"workspace key without signer", workspaceKey(creationAuthorityInput{KeyTeam: dev}), creationAuthorityUnselected, "", "", a5},
		{"workspace key wrong team", workspaceKey(creationAuthorityInput{RequestedTeam: ops, ActiveTeam: dev, SigningKeyDID: key, CertificateDID: key}), creationAuthorityUnselected, "", "", "This workspace belongs to dev:example.com, not ops:example.com. " + a5},
		{"workspace key's own team differs from signer", workspaceKey(creationAuthorityInput{KeyTeam: ops, ActiveTeam: dev, SigningKeyDID: key, CertificateDID: key}), creationAuthorityUnselected, "", "", "This workspace belongs to dev:example.com, not ops:example.com. " + a5},
		{"workspace key with mismatched signer", workspaceKey(creationAuthorityInput{KeyTeam: dev, ActiveTeam: dev, SigningKeyDID: key, CertificateDID: other}), creationAuthorityUnselected, "", "", mismatch},
		{"person key wins", creationAuthorityInput{SuppliedKey: true, KeyKind: creationKeyKindPerson, ActiveTeam: dev, SigningKeyDID: key, CertificateDID: other}, creationAuthorityAPI, "", "", ""},
		{"absent field older server", creationAuthorityInput{SuppliedKey: true, ActiveTeam: dev, LocalController: true}, creationAuthorityAPI, "", "", ""},
		{"unknown field older behavior", creationAuthorityInput{SuppliedKey: true, KeyKind: "future", ActiveTeam: dev, LocalController: true}, creationAuthorityAPI, "", "", ""},
		{"stale team kind is unknown", creationAuthorityInput{SuppliedKey: true, KeyKind: "team", ActiveTeam: dev, LocalController: true}, creationAuthorityAPI, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decideCreationAuthority(tc.input)
			if tc.refusal != "" {
				if err == nil || err.Error() != tc.refusal {
					t.Fatalf("error=%v, want %q", err, tc.refusal)
				}
				return
			}
			if err != nil || got.Mode != tc.mode || got.SourceTeam != tc.source || got.Notice != tc.notice {
				t.Fatalf("decision=%+v err=%v", got, err)
			}
		})
	}
}

// The caller reads local facts only when the decision can use them: the API
// path reads nothing local, and only a non-controller member signer reads its
// certificate.
func TestCreationAuthorityFactsRead(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input       creationAuthorityInput
		local       bool
		certificate bool
	}{
		{"no key", creationAuthorityInput{}, true, false},
		{"person key", creationAuthorityInput{SuppliedKey: true, KeyKind: creationKeyKindPerson}, false, false},
		{"unknown key kind", creationAuthorityInput{SuppliedKey: true}, false, false},
		{"workspace key", creationAuthorityInput{SuppliedKey: true, KeyKind: creationKeyKindWorkspace}, true, false},
		{"member signer", creationAuthorityInput{ActiveTeam: "dev:example.com", SigningKeyDID: "did:key:z6MkCreator"}, true, true},
		{"member controller", creationAuthorityInput{ActiveTeam: "dev:example.com", LocalController: true, SigningKeyDID: "did:key:z6MkCreator"}, true, false},
		{"member without key", creationAuthorityInput{ActiveTeam: "dev:example.com"}, true, false},
		{"key without membership", creationAuthorityInput{SigningKeyDID: "did:key:z6MkCreator"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := !tc.input.takesAPIPath(); got != tc.local {
				t.Fatalf("reads local facts=%t, want %t", got, tc.local)
			}
			if got := tc.input.needsCertificate(); got != tc.certificate {
				t.Fatalf("reads certificate=%t, want %t", got, tc.certificate)
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
