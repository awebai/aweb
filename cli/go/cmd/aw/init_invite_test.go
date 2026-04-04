package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"gopkg.in/yaml.v3"
)

func TestAwInitInviteAcceptWritesConfigAndUsesServerAliasFlag(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/accept-invite":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "myteam",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-1",
				"alias":          "reviewer",
				"address":        "myteam.aweb.ai/reviewer",
				"api_key":        "aw_sk_invited",
				"server_url":     serverURL + "/api",
				"did":            "did:key:z6MkInvite",
				"stable_id":      "did:aw:invite",
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "owner_only",
				"created":        true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/workspaces/register", "/v1/workspaces/attach":
			w.WriteHeader(http.StatusNotFound)
		case "/v1/did":
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/did:aw:invite/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          "did:aw:invite",
				"current_did_key": "did:key:z6MkInvite",
				"server":          "https://app.aweb.ai",
				"address":         "myteam.aweb.ai/maintainer",
				"handle":          "maintainer",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--alias", "reviewer",
		"--server", server.URL,
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"AWID_REGISTRY_URL=local",
	)
	run.Dir = tmp
	run.Stdin = strings.NewReader("developer\n")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if gotBody["token"] != "aw_inv_test" {
		t.Fatalf("token=%v", gotBody["token"])
	}
	if gotBody["alias"] != "reviewer" {
		t.Fatalf("alias=%v", gotBody["alias"])
	}
	if gotBody["custody"] != "self" {
		t.Fatalf("custody=%v", gotBody["custody"])
	}
	if gotBody["lifetime"] != "ephemeral" {
		t.Fatalf("lifetime=%v", gotBody["lifetime"])
	}
	if _, ok := gotBody["public_key"]; !ok {
		t.Fatal("missing public_key")
	}

	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["alias"] != "reviewer" {
		t.Fatalf("alias=%v", resp["alias"])
	}

	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg awconfig.GlobalConfig
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	found := false
	for _, acct := range cfg.Accounts {
		if acct.APIKey == "aw_sk_invited" {
			found = true
			if acct.IdentityHandle != "reviewer" {
				t.Fatalf("agent_alias=%q", acct.IdentityHandle)
			}
			if acct.NamespaceSlug != "myteam" {
				t.Fatalf("namespace_slug=%q", acct.NamespaceSlug)
			}
		}
	}
	if !found {
		t.Fatalf("missing invited account in config:\n%s", string(cfgData))
	}
}

func TestAwSpawnInviteRoundTripAcceptsIntoRepoWorktree(t *testing.T) {
	t.Parallel()

	const origin = "https://github.com/acme/repo.git"

	var createInviteAuth string
	var acceptedRole string
	var serverURL string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/create-invite":
			createInviteAuth = r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id":      "inv-1",
				"token":          "aw_inv_roundtrip",
				"token_prefix":   "aw_inv_roun",
				"alias_hint":     "reviewer",
				"access_mode":    "open",
				"max_uses":       1,
				"expires_at":     "2099-01-01T00:00:00Z",
				"namespace_slug": "demo",
				"namespace":      "demo",
				"server_url":     serverURL,
			})
		case "/api/v1/spawn/accept-invite":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"namespace":      "demo",
				"identity_id":    "identity-1",
				"alias":          "reviewer",
				"address":        "demo/reviewer",
				"api_key":        "aw_sk_invited",
				"server_url":     serverURL,
				"did":            "did:key:z6MkInvite",
				"stable_id":      "did:aw:invite",
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "open",
				"created":        true,
			})
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "roles-1",
				"roles": map[string]any{
					"reviewer": map[string]any{"title": "Reviewer"},
				},
			})
		case "/v1/workspaces/register":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode register request: %v", err)
			}
			acceptedRole, _ = req["role"].(string)
			if req["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", req["repo_origin"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     "ws-1",
				"project_id":       "proj-1",
				"project_slug":     "demo",
				"repo_id":          "repo-1",
				"canonical_origin": "github.com/acme/repo",
				"alias":            "reviewer",
				"human_name":       "Reviewer",
				"created":          true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	ownerDir := filepath.Join(tmp, "owner")
	childRepo := filepath.Join(tmp, "child")
	if err := os.MkdirAll(ownerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(childRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOrigin(t, childRepo, origin)

	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)
	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct-owner:
    server: local
    api_key: aw_sk_owner
    identity_id: owner-1
    identity_handle: alice
    namespace_slug: demo
default_account: acct-owner
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	create := exec.CommandContext(ctx, bin, "spawn", "create-invite",
		"--alias", "reviewer",
		"--json",
	)
	create.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	create.Dir = ownerDir
	createOut, err := create.CombinedOutput()
	if err != nil {
		t.Fatalf("create invite failed: %v\n%s", err, string(createOut))
	}
	var inviteResp map[string]any
	if err := json.Unmarshal(extractJSON(t, createOut), &inviteResp); err != nil {
		t.Fatalf("invalid create-invite json: %v\n%s", err, string(createOut))
	}
	token, _ := inviteResp["token"].(string)
	if token != "aw_inv_roundtrip" {
		t.Fatalf("token=%q", token)
	}
	if createInviteAuth != "Bearer aw_sk_owner" {
		t.Fatalf("create invite auth=%q", createInviteAuth)
	}

	accept := exec.CommandContext(ctx, bin, "spawn", "accept-invite", token,
		"--server-url", server.URL,
		"--alias", "reviewer",
		"--role", "reviewer",
		"--json",
	)
	accept.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	accept.Dir = childRepo
	acceptOut, err := accept.CombinedOutput()
	if err != nil {
		t.Fatalf("accept invite failed: %v\n%s", err, string(acceptOut))
	}
	if acceptedRole != "reviewer" {
		t.Fatalf("accepted role=%q", acceptedRole)
	}
	var acceptResp map[string]any
	if err := json.Unmarshal(extractJSON(t, acceptOut), &acceptResp); err != nil {
		t.Fatalf("invalid accept-invite json: %v\n%s", err, string(acceptOut))
	}
	if acceptResp["alias"] != "reviewer" {
		t.Fatalf("alias=%v", acceptResp["alias"])
	}

	data, err := os.ReadFile(filepath.Join(childRepo, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("read workspace state: %v", err)
	}
	var state awconfig.WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal workspace state: %v", err)
	}
	if state.Role != "reviewer" {
		t.Fatalf("role=%q", state.Role)
	}
	if state.CanonicalOrigin != "github.com/acme/repo" {
		t.Fatalf("canonical_origin=%q", state.CanonicalOrigin)
	}
}

func TestCollectInviteInitOptionsInteractiveRequiresAliasPrompt(t *testing.T) {
	t.Parallel()

	oldResolveBaseURLForCollection := initResolveBaseURLForCollection
	t.Cleanup(func() {
		initResolveBaseURLForCollection = oldResolveBaseURLForCollection
	})

	initResolveBaseURLForCollection = func(baseURL, serverName string) (string, string, *awconfig.GlobalConfig, error) {
		return "https://app.aweb.ai/api", "app.aweb.ai", nil, nil
	}

	var promptOut strings.Builder
	opts, err := collectInviteInitOptionsWithInput("aw_inv_test", initCollectionInput{
		WorkingDir:      t.TempDir(),
		Interactive:     true,
		PromptIn:        strings.NewReader("\nreviewer\n"),
		PromptOut:       &promptOut,
		ServerURL:       "https://app.aweb.ai",
		HumanName:       "tester",
		AgentType:       "agent",
		SaveConfig:      true,
		WriteContext:    true,
		DeferRolePrompt: true,
	})
	if err != nil {
		t.Fatalf("collectInviteInitOptionsWithInput returned error: %v", err)
	}
	if opts.IdentityAlias != "reviewer" {
		t.Fatalf("expected prompted alias to be captured, got %+v", opts)
	}
	if !opts.PromptRoleAfterBootstrap {
		t.Fatalf("expected role selection to stay deferred until after bootstrap, got %+v", opts)
	}
	if !strings.Contains(promptOut.String(), "Agent alias:") {
		t.Fatalf("expected agent alias prompt label, got %q", promptOut.String())
	}
	if !strings.Contains(promptOut.String(), "Agent alias is required.") {
		t.Fatalf("expected blank interactive alias to reprompt, got %q", promptOut.String())
	}
}

func TestAwInitInviteAcceptUsesServerProvidedAliasHint(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/accept-invite":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "myteam",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-1",
				"alias":          "reviewer",
				"address":        "myteam.aweb.ai/reviewer",
				"api_key":        "aw_sk_invited",
				"server_url":     "https://app.aweb.ai/api",
				"did":            "did:key:z6MkInvite",
				"stable_id":      "did:aw:invite",
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "open",
				"created":        true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/workspaces/register", "/v1/workspaces/attach":
			w.WriteHeader(http.StatusNotFound)
		case "/v1/did":
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/did:aw:invite/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          "did:aw:invite",
				"current_did_key": "did:key:z6MkInvite",
				"server":          "https://app.aweb.ai",
				"address":         "myteam.aweb.ai/maintainer",
				"handle":          "maintainer",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--server", server.URL,
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"AWID_REGISTRY_URL=local",
	)
	run.Dir = tmp
	run.Stdin = strings.NewReader("\ndeveloper\n")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if _, ok := gotBody["alias"]; ok {
		t.Fatalf("alias should be omitted when not provided: %+v", gotBody)
	}
	if !strings.Contains(string(out), "\"alias\": \"reviewer\"") {
		t.Fatalf("expected server-provided alias in output:\n%s", string(out))
	}
}

func TestAwInitInviteAcceptPermanentUsesExplicitName(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	var bootstrappedDID string
	var bootstrappedStableID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/accept-invite":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			bootstrappedDID, _ = gotBody["did"].(string)
			bootstrappedStableID = stableIDFromDidForTest(t, bootstrappedDID)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "myteam",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-1",
				"name":           "maintainer",
				"address":        "myteam.aweb.ai/maintainer",
				"api_key":        "aw_sk_invited",
				"server_url":     "https://app.aweb.ai/api",
				"did":            bootstrappedDID,
				"stable_id":      bootstrappedStableID,
				"custody":        "self",
				"lifetime":       "persistent",
				"access_mode":    "open",
				"created":        true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/workspaces/register", "/v1/workspaces/attach":
			w.WriteHeader(http.StatusNotFound)
		case "/v1/did":
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/" + bootstrappedStableID + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          bootstrappedStableID,
				"current_did_key": bootstrappedDID,
				"server":          "https://app.aweb.ai",
				"address":         "myteam.aweb.ai/maintainer",
				"handle":          "maintainer",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--server", server.URL,
		"--permanent",
		"--name", "maintainer",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"AWID_REGISTRY_URL=local",
	)
	run.Dir = tmp
	run.Stdin = strings.NewReader("\ndeveloper\n\n")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotBody["name"] != "maintainer" {
		t.Fatalf("name=%v", gotBody["name"])
	}
	if gotBody["lifetime"] != "persistent" {
		t.Fatalf("lifetime=%v", gotBody["lifetime"])
	}
	if !strings.Contains(string(out), "Name:       maintainer") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwInitInviteAcceptRequiresAPIKeyInResponse(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/accept-invite":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "myteam",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-1",
				"alias":          "reviewer",
				"address":        "myteam.aweb.ai/reviewer",
				"server_url":     "https://app.aweb.ai/api",
				"created":        true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--alias", "reviewer",
		"--server", server.URL,
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	run.Stdin = strings.NewReader("\ndeveloper\n")
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "invite accept failed: missing api_key in response") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwInitInviteAliasErrorOnlyMapsAliasValidation(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/accept-invite":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"detail":"Invalid public_key"}`))
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--server", server.URL,
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	run.Stdin = strings.NewReader("\ndeveloper\n\n")
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if strings.Contains(string(out), "alias is required") {
		t.Fatalf("should not rewrite non-alias 422 errors:\n%s", string(out))
	}
	if !strings.Contains(string(out), `{"detail":"Invalid public_key"}`) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwInitInviteTextOutputSaysJoined(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/accept-invite":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "myteam",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-1",
				"alias":          "reviewer",
				"address":        "myteam.aweb.ai/reviewer",
				"api_key":        "aw_sk_invited",
				"server_url":     "https://app.aweb.ai/api",
				"did":            "did:key:z6MkInvite",
				"stable_id":      "did:aw:invite",
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "open",
				"created":        true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/workspaces/register", "/v1/workspaces/attach":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--alias", "reviewer",
		"--server", server.URL,
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	run.Stdin = strings.NewReader("\ndeveloper\n")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Accepted spawn invite") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Alias:      reviewer") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwInitInviteDefaultsToEphemeralWithoutLifetimePrompt(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/accept-invite":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "myteam",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-1",
				"alias":          "reviewer",
				"address":        "myteam.aweb.ai/reviewer",
				"api_key":        "aw_sk_invited",
				"server_url":     "https://app.aweb.ai/api",
				"did":            "did:key:z6MkInvite",
				"stable_id":      "did:aw:invite",
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "open",
				"created":        true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/workspaces/register", "/v1/workspaces/attach":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--alias", "reviewer",
		"--role", "developer",
		"--server", server.URL,
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	run.Stdin = strings.NewReader("")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if strings.Contains(text, "Identity type number") {
		t.Fatalf("did not expect identity-type prompt:\n%s", text)
	}
	if !strings.Contains(text, "Accepted spawn invite") {
		t.Fatalf("unexpected output:\n%s", text)
	}
}
