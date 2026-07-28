package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/blueprint"
)

func TestTeamAddAPIKeyBootstrapRequiresActuallyMissingTeamState(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv(initAPIKeyEnvVar, "aw_sk_clean_bootstrap")

	if _, _, _, _, err := resolveTeamInviteTarget(root); !errors.Is(err, errTeamInviteTargetHasNoActiveTeam) {
		t.Fatalf("clean directory error=%v, want explicit no-active-team classification", err)
	}
	bootstrap, err := shouldUseAPIKeyBootstrapForTeamAdd(root)
	if err != nil {
		t.Fatalf("shouldUseAPIKeyBootstrapForTeamAdd: %v", err)
	}
	if !bootstrap {
		t.Fatal("clean directory with API key should use bootstrap")
	}
}

func TestTeamAddAPIKeyBootstrapDoesNotSwallowInvalidTeamState(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv(initAPIKeyEnvVar, "aw_sk_must_not_hide_error")
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".aw", "teams.yaml"), []byte("active_team: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, _, _, err := resolveTeamInviteTarget(root); err == nil || errors.Is(err, errTeamInviteTargetHasNoActiveTeam) {
		t.Fatalf("invalid team state error=%v, must not classify as no active team", err)
	}
	bootstrap, err := shouldUseAPIKeyBootstrapForTeamAdd(root)
	if err == nil {
		t.Fatal("invalid team state was silently treated as no active team")
	}
	if bootstrap {
		t.Fatal("invalid team state must not enable API-key bootstrap")
	}
}

func TestTeamAddAmbientAPIKeyKeepsActiveTeamAuthority(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv(initAPIKeyEnvVar, "aw_sk_forgotten_export")
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "active:acme.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "active:acme.com",
			Alias:    "captain",
			CertPath: ".aw/team-certs/active.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	bootstrap, err := shouldUseAPIKeyBootstrapForTeamAdd(root)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap {
		t.Fatal("ambient API key overrode aw team add active-team authority")
	}
}

func TestTeamBlueprintsSOTDescribesAmbientAPIKeyAssertion(t *testing.T) {
	path := filepath.Join(cmdMonorepoRootForTest(t), "docs", "team-blueprints-sot.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"selects API-key authority and uses the active team as an assertion",
		"pass an explicit `--api-key`, which bypasses the workspace assertion",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("%s missing post-aary.1 guidance %q", path, want)
		}
	}
	for _, stale := range []string{
		"Unset the variable to extend the active team",
		"ambient `AWEB_API_KEY` does not silently override it",
	} {
		if strings.Contains(text, stale) {
			t.Errorf("%s still contains stale ambient-key refusal %q", path, stale)
		}
	}
}

func TestTeamExtendAmbientAPIKeyUsesActiveTeamAssertion(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	const apiKey = "aw_sk_forgotten_export"
	const activeTeamID = "active:acme.com"
	t.Setenv(initAPIKeyEnvVar, apiKey)
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: activeTeamID,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   activeTeamID,
			Alias:    "captain",
			CertPath: ".aw/team-certs/active.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	authority, err := resolveTeamExtendAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Tier != teamExtendAuthorityTierAPIKeyWorkspaceAsserted || authority.APIKey != apiKey {
		t.Fatalf("authority=%+v", authority)
	}
	expectedTeamID, source := expectedTeamIDForExtend(authority)
	if expectedTeamID != activeTeamID || source != teamIDAssertionSourceWorkspaceActiveTeam {
		t.Fatalf("expected team/source=%q/%q", expectedTeamID, source)
	}
}

func TestTeamExtendAmbientAPIKeyInCleanDirKeepsPlainAPIKeyTier(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	const apiKey = "aw_sk_clean_bootstrap"
	t.Setenv(initAPIKeyEnvVar, apiKey)

	authority, err := resolveTeamExtendAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Tier != teamExtendAuthorityTierAPIKey || authority.APIKey != apiKey {
		t.Fatalf("authority=%+v", authority)
	}
	expectedTeamID, source := expectedTeamIDForExtend(authority)
	if expectedTeamID != "" || source != teamIDAssertionSourceNone {
		t.Fatalf("clean-dir ambient key unexpectedly asserted team/source=%q/%q", expectedTeamID, source)
	}
}

func TestTeamExtendAmbientAPIKeyWithExplicitTeamIDIsIntentional(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv(initAPIKeyEnvVar, "aw_sk_intentional_env")
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "active:acme.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "active:acme.com",
			Alias:    "captain",
			CertPath: ".aw/team-certs/active.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	teamHumanExtendTeamID = "target:other.example"

	authority, err := resolveTeamExtendAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Tier != teamExtendAuthorityTierAPIKey || authority.APIKey != "aw_sk_intentional_env" || authority.TeamID != teamHumanExtendTeamID {
		t.Fatalf("authority=%+v", authority)
	}
	expectedTeamID, source := expectedTeamIDForExtend(authority)
	if expectedTeamID != teamHumanExtendTeamID || source != teamIDAssertionSourceExplicitFlag {
		t.Fatalf("expected team/source=%q/%q", expectedTeamID, source)
	}
}

func TestTeamExtendExplicitAPIKeyOverridesActiveTeamIntentionally(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv(initAPIKeyEnvVar, "aw_sk_ambient")
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "active:acme.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "active:acme.com",
			Alias:    "captain",
			CertPath: ".aw/team-certs/active.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	teamHumanExtendAPIKey = "aw_sk_explicit"

	authority, err := resolveTeamExtendAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Tier != teamExtendAuthorityTierAPIKey || authority.APIKey != teamHumanExtendAPIKey {
		t.Fatalf("authority=%+v", authority)
	}
	expectedTeamID, source := expectedTeamIDForExtend(authority)
	if expectedTeamID != "" || source != teamIDAssertionSourceNone {
		t.Fatalf("explicit key unexpectedly asserted team/source=%q/%q", expectedTeamID, source)
	}
}

func TestTeamExtendCleanDirWithoutAuthorityErrorsClearly(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv(initAPIKeyEnvVar, "")

	err := runTeamHumanExtend(nil, []string{"developer"})
	if err == nil {
		t.Fatal("expected error")
	}
	text := err.Error()
	for _, want := range []string{"--api-key", initAPIKeyEnvVar, "agents/instances", "aw team create"} {
		if !strings.Contains(text, want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	if strings.Contains(strings.ToLower(text), "eof") {
		t.Fatalf("error should not mention EOF: %v", err)
	}
}

func TestTeamExtendDiscoveryCurrentWorkspaceBeatsSiblingAmbiguity(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "agents", "instances", "other", ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{ActiveTeam: "current:acme.com", Memberships: []awconfig.TeamMembership{{TeamID: "current:acme.com", Alias: "captain", CertPath: ".aw/team-certs/current.pem"}}}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(filepath.Join(root, "agents", "instances", "other"), &awconfig.TeamState{ActiveTeam: "other:acme.com", Memberships: []awconfig.TeamMembership{{TeamID: "other:acme.com", Alias: "other", CertPath: ".aw/team-certs/other.pem"}}}); err != nil {
		t.Fatal(err)
	}
	authority, err := resolveTeamExtendAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Tier != "current-workspace" || authority.TeamID != "current:acme.com" || authority.AnchorDir != root {
		t.Fatalf("authority=%+v", authority)
	}
}

func TestTeamExtendDiscoveryScanAmbiguityAndTeamIDFilter(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	agentsRoot := filepath.Join(root, "agents", "instances")
	for _, tc := range []struct{ name, teamID string }{{"b", "beta:acme.com"}, {"a", "alpha:acme.com"}} {
		home := filepath.Join(agentsRoot, tc.name)
		if err := os.MkdirAll(filepath.Join(home, ".aw"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := awconfig.SaveTeamState(home, &awconfig.TeamState{ActiveTeam: tc.teamID, Memberships: []awconfig.TeamMembership{{TeamID: tc.teamID, Alias: tc.name, CertPath: ".aw/team-certs/" + tc.name + ".pem"}}}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := resolveTeamExtendAuthority(root)
	if err == nil || !strings.Contains(err.Error(), "multiple teams found") || !strings.Contains(err.Error(), "alpha:acme.com") || !strings.Contains(err.Error(), "beta:acme.com") {
		t.Fatalf("ambiguity error=%v", err)
	}
	teamHumanExtendTeamID = "beta:acme.com"
	authority, err := resolveTeamExtendAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Tier != "discovered-agent" || authority.TeamID != "beta:acme.com" || filepath.Base(authority.AnchorDir) != "b" {
		t.Fatalf("authority=%+v", authority)
	}
}

func TestFormatTeamHumanExtendIncludesTeamAndAuthority(t *testing.T) {
	out := teamHumanAddOutput{
		Status:        "extended",
		AgentsRoot:    "/tmp/team/agents/instances",
		TeamID:        "active:acme.com",
		AuthorityTier: teamExtendAuthorityTierAPIKeyWorkspaceAsserted,
		NoLibrary:     true,
		NoProfile:     true,
		Agents:        []teamHumanAddedAgent{{Name: "developer", HomeDir: "/tmp/team/agents/instances/developer"}},
	}

	human := formatTeamHumanAdd(out)
	for _, want := range []string{"Extended with", "Team: active:acme.com", "Authority tier: " + teamExtendAuthorityTierAPIKeyWorkspaceAsserted} {
		if !strings.Contains(human, want) {
			t.Fatalf("human output missing %q:\n%s", want, human)
		}
	}
	payload, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"status":"extended"`, `"team_id":"active:acme.com"`, `"authority_tier":"` + teamExtendAuthorityTierAPIKeyWorkspaceAsserted + `"`} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("JSON output missing %q: %s", want, payload)
		}
	}
	if strings.Contains(string(payload), `"outcome"`) || strings.Contains(string(payload), `"reason"`) || strings.Contains(human, "Roster outcome after failure") {
		t.Fatalf("successful output changed to failure-report shape: human=%q JSON=%s", human, payload)
	}
}

func TestTeamExtendAmbientAPIKeyMatchingActiveTeamCreatesRoster(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	const apiKey = "aw_sk_ambient_extend"
	const teamID = "active:workspace.aweb.ai"
	t.Setenv(initAPIKeyEnvVar, apiKey)
	t.Setenv("AW_CONFIG_PATH", "")
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Chdir(root)
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: teamID,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   teamID,
			Alias:    "captain",
			CertPath: ".aw/team-certs/active.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	var initCalls int
	server := newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			initCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
				t.Fatalf("workspace init Authorization=%q", got)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			alias, _ := body["alias"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: didKey, Alias: alias, Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": serverURL, "team_cert": encoded, "alias": alias, "team_id": teamID, "workspace_id": "ws-created", "did": didKey, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": "aw_sk_returned_member"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "alias": "developer", "agent_id": "agent-created", "workspace_id": "ws-created", "repo_id": "repo-1", "team_did_key": teamDIDKey})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-created", teamID, "developer")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	initAwebURL = server.URL

	if err := runTeamHumanExtend(nil, []string{"developer"}); err != nil {
		t.Fatalf("runTeamHumanExtend: %v", err)
	}
	if initCalls != 1 {
		t.Fatalf("workspace init calls=%d want 1", initCalls)
	}
	if _, err := os.Stat(filepath.Join(root, "agents", "instances", "developer", ".aw", "workspace.yaml")); err != nil {
		t.Fatalf("created workspace missing: %v", err)
	}
}

func TestTeamAddGlobalPreflightSuggestsSupportedExtendCommand(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv(initAPIKeyEnvVar, "")
	t.Chdir(root)

	const teamID = "default:add-hosted.aweb.ai"
	mutationCalls := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"aweb_url": "", "registry_url": ""})
		default:
			mutationCalls++
			t.Fatalf("unexpected mutation %s %s", r.Method, r.URL.Path)
		}
	}))
	writeWorkspaceBindingForTest(t, root, workspaceBinding(server.URL, teamID, "owner", "workspace-owner"))

	err := runTeamHumanAdd(nil, []string{"probe:global"})
	if err == nil {
		t.Fatal("expected add global authority preflight error")
	}
	for _, want := range []string{"aw team add: agent probe", "run aw team extend from a fresh directory with --api-key <key>", "use probe:local"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("add error %q missing %q", err, want)
		}
	}
	if mutationCalls != 0 {
		t.Fatalf("mutation calls=%d", mutationCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", "probe")); !os.IsNotExist(statErr) {
		t.Fatalf("probe home created before add authority preflight: %v", statErr)
	}
}

func TestTeamExtendCurrentWorkspaceGlobalPreflightHasZeroMutation(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv(initAPIKeyEnvVar, "")
	t.Chdir(root)

	const teamID = "default:hosted.aweb.ai"
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	mutationCalls := 0
	var server *httptest.Server
	server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"aweb_url": serverURL, "registry_url": serverURL})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/create-invite":
			mutationCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{"invite_id": "invite-1", "token": "aw_inv_hosted_rollback_token", "server_url": serverURL})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/accept-invite":
			mutationCalls++
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			didKey, _ := req["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: didKey, Alias: "first", Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_slug": "default", "namespace": "hosted.aweb.ai", "alias": "first", "server_url": serverURL, "did": didKey, "custody": "self", "lifetime": "ephemeral", "team_cert": encoded})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-first", teamID, "first")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	initAwebURL = server.URL
	workspace := workspaceBinding(server.URL, teamID, "owner", "workspace-owner")
	writeWorkspaceBindingForTest(t, root, workspace)

	err = runTeamHumanExtend(nil, []string{"first:local", "aw-coord@aweb.team/coordinator:global=claude-code"})
	if err == nil {
		t.Fatal("expected global authority preflight error")
	}
	for _, want := range []string{
		"aw team extend: agent aw-coord resolves to global identity scope",
		"current-workspace, team " + teamID,
		"cannot mint global identities",
		"aw-coord@aweb.team/coordinator:local=claude-code",
		"No agents were created",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "--byot") || strings.Contains(err.Error(), "--first-agent-global") {
		t.Fatalf("error names flags the caller did not pass: %v", err)
	}
	if strings.Contains(err.Error(), "from profile") {
		t.Fatalf("explicit :global suffix was misattributed to the profile: %v", err)
	}
	if mutationCalls != 0 {
		t.Fatalf("membership mutation calls=%d; preflight ran after roster mutation", mutationCalls)
	}
	for _, name := range []string{"first", "aw-coord"} {
		if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", name)); !os.IsNotExist(statErr) {
			t.Fatalf("%s home created before authority preflight: %v", name, statErr)
		}
	}
}

func TestTeamExtendDiscoveredAgentGlobalPreflightHasZeroMutation(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv(initAPIKeyEnvVar, "")
	t.Chdir(root)

	const teamID = "default:discovered.aweb.ai"
	mutationCalls := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/agents" {
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery" {
			_ = json.NewEncoder(w).Encode(map[string]any{"aweb_url": "", "registry_url": ""})
			return
		}
		mutationCalls++
		t.Fatalf("unexpected mutation %s %s", r.Method, r.URL.Path)
	}))
	anchor := filepath.Join(root, "agents", "instances", "anchor")
	writeWorkspaceBindingForTest(t, anchor, workspaceBinding(server.URL, teamID, "owner", "workspace-owner"))

	err := runTeamHumanExtend(nil, []string{"aw-coord@aweb.team/coordinator:global=pi"})
	if err == nil || !strings.Contains(err.Error(), teamExtendAuthorityTierDiscoveredAgent) || !strings.Contains(err.Error(), "aw-coord@aweb.team/coordinator:local=pi") {
		t.Fatalf("discovered authority error=%v", err)
	}
	if mutationCalls != 0 {
		t.Fatalf("mutation calls=%d", mutationCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", "aw-coord")); !os.IsNotExist(statErr) {
		t.Fatalf("global home created before discovered-authority preflight: %v", statErr)
	}
}

func TestTeamExtendGlobalPreflightUsesProfileDefaultScope(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	files := withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: coordinator\nname: Coordinator\nversion: 0.1.0\nscope: global\nmission: Coordinate.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Coordinate.\n"},
	})
	digest := testLibraryProfilePayloadDigestForProfile(t, "coordinator", files)
	library := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/blueprints/aweb.team/profiles/coordinator" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.team", "blueprint_version": "0.1.0", "profile_ref": "coordinator", "version": "0.1.0", "digest": digest, "files": files})
	}))
	defer library.Close()
	t.Setenv(libraryURLEnvVar, library.URL)
	t.Setenv("HOME", t.TempDir())

	plans, err := resolveTeamHumanAddAgentSpecs(t.TempDir(), []string{"aw-coord@aweb.team/coordinator=claude-code"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].Scope != awid.IdentityModeGlobal || plans[0].Profile == nil || plans[0].Profile.IdentityScope != "" {
		t.Fatalf("profile-defaulted scope was not preserved: %+v", plans)
	}
	resolvedPlans := []teamHumanAddedAgent{{Name: plans[0].Name, Profile: plans[0].Profile, Scope: plans[0].Scope}}
	err = preflightTeamHumanAddRosterAuthority(t.TempDir(), resolvedPlans, false, teamHumanAddRunOptions{
		OutputAuthorityTier: teamExtendAuthorityTierDiscoveredAgent,
		AuthorityTeamID:     "default:hosted.aweb.ai",
		CommandName:         "aw team extend",
	})
	if err == nil {
		t.Fatal("expected profile-defaulted global preflight error")
	}
	for _, want := range []string{"from profile aweb.team/coordinator", teamExtendAuthorityTierDiscoveredAgent, "aw-coord@aweb.team/coordinator:local=claude-code"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestTeamExtendMiddleFailureReportsEveryRosterOutcome(t *testing.T) {
	for _, tc := range []struct {
		name string
		json bool
	}{
		{name: "human"},
		{name: "json", json: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetTeamHumanCreateGlobals(t)
			const apiKey = "aw_sk_partial_roster"
			const teamID = "active:workspace.aweb.ai"
			t.Setenv(initAPIKeyEnvVar, apiKey)
			t.Setenv("AW_CONFIG_PATH", "")
			t.Setenv("HOME", t.TempDir())
			root := t.TempDir()
			t.Chdir(root)
			jsonFlag = tc.json

			teamPub, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			teamDIDKey := awid.ComputeDIDKey(teamPub)
			var attempted []string
			server := newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
					if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
						t.Fatalf("workspace init Authorization=%q", got)
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					alias, _ := body["alias"].(string)
					attempted = append(attempted, alias)
					if alias == "second" {
						http.Error(w, "injected middle-member failure", http.StatusServiceUnavailable)
						return
					}
					if alias != "first" {
						t.Fatalf("unexpected roster member attempted: %q", alias)
					}
					didKey, _ := body["did"].(string)
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: didKey, Alias: alias, Lifetime: awid.LifetimeEphemeral})
					if err != nil {
						t.Fatal(err)
					}
					encoded, err := awid.EncodeTeamCertificateHeader(cert)
					if err != nil {
						t.Fatal(err)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"server_url": serverURL, "team_cert": encoded, "alias": alias, "team_id": teamID, "workspace_id": "ws-" + alias, "did": didKey, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": "aw_sk_returned_member"})
				case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
					requireCertificateAuthForTest(t, r)
					_ = json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "alias": "first", "agent_id": "agent-first", "workspace_id": "ws-first", "repo_id": "repo-1", "team_did_key": teamDIDKey})
				case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
					writePublishEncryptionKeyResponseForTest(t, w, "agent-first", teamID, "first")
				default:
					t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
				}
			})
			initAwebURL = server.URL

			var runErr error
			output := captureIDCommandStdout(t, func() {
				runErr = runTeamHumanExtend(nil, []string{"first", "second", "third"})
			})
			if runErr == nil || !strings.Contains(runErr.Error(), "injected middle-member failure") {
				t.Fatalf("error=%v", runErr)
			}
			if got := strings.Join(attempted, ","); got != "first,second" {
				t.Fatalf("attempted=%q, want first,second", got)
			}
			if _, err := os.Stat(filepath.Join(root, "agents", "instances", "first", ".aw", "workspace.yaml")); err != nil {
				t.Fatalf("successfully created first member was not kept: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "agents", "instances", "second")); !os.IsNotExist(err) {
				t.Fatalf("failed second member retained local state: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "agents", "instances", "third")); !os.IsNotExist(err) {
				t.Fatalf("not-attempted third member has local state: %v", err)
			}

			if tc.json {
				var report struct {
					Status string `json:"status"`
					Agents []struct {
						Name    string `json:"name"`
						Outcome string `json:"outcome"`
						Reason  string `json:"reason"`
					} `json:"agents"`
				}
				if err := json.Unmarshal([]byte(output), &report); err != nil {
					t.Fatalf("decode JSON report %q: %v", output, err)
				}
				if report.Status != "failed" || len(report.Agents) != 3 {
					t.Fatalf("report=%+v", report)
				}
				wantOutcomes := []string{"created", "failed", "not_attempted"}
				for i, want := range wantOutcomes {
					if report.Agents[i].Name != []string{"first", "second", "third"}[i] || report.Agents[i].Outcome != want {
						t.Fatalf("agent[%d]=%+v want outcome %q", i, report.Agents[i], want)
					}
				}
				if !strings.Contains(report.Agents[1].Reason, "injected middle-member failure") || report.Agents[0].Reason != "" || report.Agents[2].Reason != "" {
					t.Fatalf("failure reasons=%q/%q/%q", report.Agents[0].Reason, report.Agents[1].Reason, report.Agents[2].Reason)
				}
				return
			}

			positions := []int{
				strings.Index(output, "- first: created"),
				strings.Index(output, "- second: failed"),
				strings.Index(output, "- third: not attempted"),
			}
			if positions[0] < 0 || positions[1] <= positions[0] || positions[2] <= positions[1] {
				t.Fatalf("human report does not list all outcomes in input order:\n%s", output)
			}
			if !strings.Contains(output, "injected middle-member failure") {
				t.Fatalf("human report missing failure reason:\n%s", output)
			}
		})
	}
}

func TestTeamExtendFailedBootstrapAndWorktreeSetupRemoveHomeAndAllowSameNameRetry(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv(initAPIKeyEnvVar, "")
	teamHumanExtendAPIKey = "aw_sk_retry"
	teamHumanAddWorkDir = filepath.Join(root, "missing-work-repo")
	t.Chdir(root)

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	const teamID = "default:retry.aweb.ai"
	var initCalls, connectCalls, removeCalls int
	var server *httptest.Server
	server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			initCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer "+teamHumanExtendAPIKey {
				t.Fatalf("workspace init Authorization=%q", got)
			}
			if initCalls == 1 {
				http.Error(w, `{"detail":"injected bootstrap failure"}`, http.StatusUnauthorized)
				return
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			alias, _ := body["alias"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: didKey, Alias: alias, Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": serverURL, "team_cert": encoded, "alias": alias, "team_id": teamID, "workspace_id": "ws-retry", "did": didKey, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": "aw_sk_member_retry"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectCalls++
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "alias": "retry", "agent_id": "agent-retry", "workspace_id": "ws-retry", "repo_id": "repo-1", "team_did_key": teamDIDKey})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-retry", teamID, "retry")
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/agents/remove-member"):
			removeCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer "+teamHumanExtendAPIKey {
				t.Fatalf("remove Authorization=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "certificate_id": "removed"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	initAwebURL = server.URL

	firstErr := runTeamHumanExtend(nil, []string{"retry"})
	if firstErr == nil || !strings.Contains(firstErr.Error(), "injected bootstrap failure") {
		t.Fatalf("first error=%v", firstErr)
	}
	agentHome := filepath.Join(root, "agents", "instances", "retry")
	if _, statErr := os.Lstat(agentHome); !os.IsNotExist(statErr) {
		t.Fatalf("failed bootstrap left agent home %s: %v", agentHome, statErr)
	}
	secondErr := runTeamHumanExtend(nil, []string{"retry"})
	if secondErr == nil || !strings.Contains(secondErr.Error(), "is not inside a git repo") {
		t.Fatalf("worktree setup error=%v", secondErr)
	}
	if _, statErr := os.Lstat(agentHome); !os.IsNotExist(statErr) {
		t.Fatalf("failed worktree setup left agent home %s: %v", agentHome, statErr)
	}
	if removeCalls != 1 {
		t.Fatalf("worktree failure member rollback calls=%d", removeCalls)
	}
	teamHumanAddWorkDir = ""
	if err := runTeamHumanExtend(nil, []string{"retry"}); err != nil {
		t.Fatalf("same-name retry after worktree failure: %v", err)
	}
	if initCalls != 3 || connectCalls != 2 {
		t.Fatalf("calls init/connect=%d/%d", initCalls, connectCalls)
	}
	if _, statErr := os.Stat(filepath.Join(agentHome, ".aw", "workspace.yaml")); statErr != nil {
		t.Fatalf("retry did not create agent workspace: %v", statErr)
	}
}

func TestTeamExtendAmbientAPIKeyTeamMismatchRollsBackWithWorkspaceAssertion(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	const ambientKey = "aw_sk_ambient_extend"
	t.Setenv(initAPIKeyEnvVar, ambientKey)
	t.Setenv("AW_CONFIG_PATH", "")
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(root)
	const expectedTeamID = "active:workspace.aweb.ai"
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: expectedTeamID,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   expectedTeamID,
			Alias:    "captain",
			CertPath: ".aw/team-certs/active.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	const returnedKey = "aw_sk_returned_member"
	const actualTeamID = "default:keyteam.aweb.ai"
	var initCalls, connectCalls, removeCalls int
	var server *httptest.Server
	server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			initCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer "+ambientKey {
				t.Fatalf("workspace init Authorization=%q", got)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			alias, _ := body["alias"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: actualTeamID, MemberDIDKey: didKey, Alias: alias, Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": serverURL, "team_cert": encoded, "alias": alias, "team_id": actualTeamID, "workspace_id": "ws-rollback", "did": didKey, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": returnedKey})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectCalls++
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": actualTeamID, "alias": "rollback", "agent_id": "agent-rollback", "workspace_id": "ws-rollback", "repo_id": "repo-1", "team_did_key": teamDIDKey})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-rollback", actualTeamID, "rollback")
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/agents/remove-member"):
			removeCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer "+ambientKey {
				t.Fatalf("remove Authorization=%q want ambient key", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": actualTeamID, "certificate_id": "removed"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	initAwebURL = server.URL

	err = runTeamHumanExtend(nil, []string{"rollback", "should-not-run"})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if strings.Contains(err.Error(), "would silently use the API key's team") {
		t.Fatalf("ambient API key was refused before bootstrap: %v", err)
	}
	if strings.Contains(err.Error(), "--team-id") || !strings.Contains(err.Error(), "workspace active team "+expectedTeamID) || !strings.Contains(err.Error(), "API key team "+actualTeamID) {
		t.Fatalf("unexpected error: %v", err)
	}
	if initCalls != 1 || connectCalls != 1 || removeCalls != 1 {
		t.Fatalf("calls init/connect/remove=%d/%d/%d", initCalls, connectCalls, removeCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", "rollback")); !os.IsNotExist(statErr) {
		t.Fatalf("rollback home remains: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", "should-not-run")); !os.IsNotExist(statErr) {
		t.Fatalf("second member attempted despite mismatch: %v", statErr)
	}
}

func TestTeamExtendAPIKeyTeamIDMismatchRollsBackWithExplicitAuth(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv(initAPIKeyEnvVar, "")
	t.Setenv("AW_CONFIG_PATH", "")
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(root)
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "active:workspace.aweb.ai",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "active:workspace.aweb.ai",
			Alias:    "captain",
			CertPath: ".aw/team-certs/active.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	const explicitKey = "aw_sk_explicit_extend"
	const returnedKey = "aw_sk_returned_member"
	const actualTeamID = "default:keyteam.aweb.ai"
	var initCalls, connectCalls, removeCalls int
	var removeAuth string
	var server *httptest.Server
	server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			initCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer "+explicitKey {
				t.Fatalf("workspace init Authorization=%q", got)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			alias, _ := body["alias"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: actualTeamID, MemberDIDKey: didKey, Alias: alias, Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": serverURL, "team_cert": encoded, "alias": alias, "team_id": actualTeamID, "workspace_id": "ws-rollback", "did": didKey, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": returnedKey})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectCalls++
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": actualTeamID, "alias": "rollback", "agent_id": "agent-rollback", "workspace_id": "ws-rollback", "repo_id": "repo-1", "team_did_key": teamDIDKey})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-rollback", actualTeamID, "rollback")
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/agents/remove-member"):
			removeCalls++
			removeAuth = r.Header.Get("Authorization")
			if removeAuth != "Bearer "+explicitKey {
				t.Fatalf("remove Authorization=%q want explicit key", removeAuth)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": actualTeamID, "certificate_id": "removed"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	teamHumanExtendAPIKey = explicitKey
	teamHumanExtendTeamID = "default:other.aweb.ai"
	initAwebURL = server.URL

	err = runTeamHumanExtend(nil, []string{"rollback", "should-not-run"})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	wantMismatch := "--team-id " + teamHumanExtendTeamID + " does not match API key team " + actualTeamID
	if !strings.Contains(err.Error(), wantMismatch) {
		t.Fatalf("unexpected error: %v", err)
	}
	if initCalls != 1 || connectCalls != 1 || removeCalls != 1 {
		t.Fatalf("calls init/connect/remove=%d/%d/%d", initCalls, connectCalls, removeCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", "rollback")); !os.IsNotExist(statErr) {
		t.Fatalf("rollback home remains: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", "should-not-run")); !os.IsNotExist(statErr) {
		t.Fatalf("second member attempted despite mismatch: %v", statErr)
	}
}

func TestTeamExtendAgentHomePlacesSibling(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(root)
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), memberKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: memberDID, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	if err := awconfig.SaveControllerKey("acme.com", controllerKey); err != nil {
		t.Fatal(err)
	}
	var certAliases []string
	server := newBYOTRegistryTestServer(t, "acme.com", "ops", controllerKey, func(alias string) { certAliases = append(certAliases, alias) })
	defer server.Close()
	if err := awconfig.SaveControllerMeta("acme.com", &awconfig.ControllerMeta{Domain: "acme.com", ControllerDID: controllerDID, RegistryURL: server.URL, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	teamHumanCreateBYOT = true
	teamHumanCreateNamespace = "acme.com"
	teamHumanCreateRegistryURL = server.URL
	if err := runTeamHumanCreate(nil, []string{"Ops"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	captainHome := filepath.Join(root, "agents", "instances", "captain")
	if err := copyTestTree(filepath.Join(root, ".aw"), filepath.Join(captainHome, ".aw")); err != nil {
		t.Fatalf("seed captain home: %v", err)
	}
	if err := os.Chdir(captainHome); err != nil {
		t.Fatal(err)
	}
	if err := runTeamHumanExtend(nil, []string{"crew"}); err != nil {
		t.Fatalf("extend: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "agents", "instances", "crew", ".aw", "teams.yaml")); err != nil {
		t.Fatalf("crew sibling missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "agents", "instances", "captain", "agents")); !os.IsNotExist(err) {
		t.Fatalf("extend nested agents under caller home: %v", err)
	}
	if strings.Join(certAliases, ",") != "ops,crew" {
		t.Fatalf("cert aliases=%v", certAliases)
	}
}

func copyTestTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

func newBYOTRegistryTestServer(t *testing.T, domain, team string, controllerKey ed25519.PrivateKey, onCert func(alias string)) *httptest.Server {
	t.Helper()
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	namespaceCreated := false
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+domain:
			if !namespaceCreated {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": domain, "controller_did": controllerDID, "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			namespaceCreated = true
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": domain, "controller_did": controllerDID, "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/"+domain+"/teams":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": team + ":" + domain, "domain": domain, "name": team, "team_did_key": body["team_did_key"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/namespaces/"+domain+"/teams/") && strings.HasSuffix(r.URL.Path, "/certificates"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			alias, _ := body["alias"].(string)
			onCert(strings.TrimSpace(alias))
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
}
