package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func newLocalHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// aw probes for aweb by calling GET /v1/agents/heartbeat on candidate bases.
		// Return any non-404 to indicate "endpoint exists" without side effects.
		// Only intercept GET; POST is the actual heartbeat and should reach the inner handler.
		if r.Method == http.MethodGet && (r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat") {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handler.ServeHTTP(w, r)
	})
	srv := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: wrapped},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// extractJSON finds the first JSON object in mixed output (e.g. from
// CombinedOutput where stderr warnings precede stdout JSON).
func extractJSON(t *testing.T, out []byte) []byte {
	t.Helper()
	idx := bytes.IndexByte(out, '{')
	if idx < 0 {
		t.Fatalf("no JSON object in output:\n%s", string(out))
	}
	return out[idx:]
}

func stableIDFromDidForTest(t *testing.T, did string) string {
	t.Helper()
	pub, err := awid.ExtractPublicKey(did)
	if err != nil {
		t.Fatalf("ExtractPublicKey(%q): %v", did, err)
	}
	return awid.ComputeStableID(pub)
}

func TestAwIntrospect(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-123"})
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

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "introspect", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
}

func TestAwIntrospectUsesBYODAddressFromIdentity(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"project_id":     "proj-123",
				"namespace_slug": "myteam.aweb.ai",
				"alias":          "support",
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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "support",
		NamespaceSlug:  "myteam.aweb.ai",
		ProjectSlug:    "myteam",
	})
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       "did:key:z6MkByodSupport",
		StableID:  "did:aw:byod-support",
		Address:   "acme.com/support",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-04T00:00:00Z",
	})

	run := exec.CommandContext(ctx, bin, "whoami", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["address"] != "acme.com/support" {
		t.Fatalf("address=%v want acme.com/support", got["address"])
	}
}

func TestAwIntrospectTextOutput(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"project_id":  "proj-123",
				"identity_id": "agent-1",
				"alias":       "alice",
				"human_name":  "Alice Dev",
				"agent_type":  "developer",
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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "testns",
		ProjectSlug:    "testns",
		WorkspaceID:    "workspace-1",
	})

	// Run WITHOUT --json: should produce human-readable text.
	run := exec.CommandContext(ctx, bin, "introspect")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	text := string(out)
	for _, want := range []string{"Routing:", "Project:", "Human:", "Type:"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "{") {
		t.Errorf("text output should not contain JSON braces:\n%s", text)
	}
}

func TestAwIntrospectIncludesIdentityFields(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"project_id":  "proj-123",
				"identity_id": "agent-1",
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

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		WorkspaceID:    "workspace-1",
		DID:            "did:key:z6MkTestKey123",
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
	})

	run := exec.CommandContext(ctx, bin, "introspect", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
	if got["did"] != "did:key:z6MkTestKey123" {
		t.Fatalf("did=%v", got["did"])
	}
	if got["custody"] != "self" {
		t.Fatalf("custody=%v", got["custody"])
	}
	if got["lifetime"] != "persistent" {
		t.Fatalf("lifetime=%v", got["lifetime"])
	}
	if _, ok := got["public_key"]; ok {
		t.Fatal("public_key should not be present in introspect output")
	}
}

func TestAwIdentityCommandSurface(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	identityHelp := exec.CommandContext(ctx, bin, "id", "--help")
	identityHelp.Dir = tmp
	identityOut, err := identityHelp.CombinedOutput()
	if err != nil {
		t.Fatalf("identity help failed: %v\n%s", err, string(identityOut))
	}

	identityText := string(identityOut)
	for _, want := range []string{
		"create",
		"register",
		"show",
		"resolve",
		"verify",
		"namespace",
		"rotate-key",
		"log",
		"access-mode",
		"reachability",
		"delete",
	} {
		if !strings.Contains(identityText, want) {
			t.Fatalf("identity help missing %q:\n%s", want, identityText)
		}
	}

	if strings.Contains(identityText, "create-permanent") {
		t.Fatalf("identity help should not expose create-permanent:\n%s", identityText)
	}
}

func TestAwProjectCreatePermanentRequiresName(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "project", "create", "--project", "demo", "--permanent")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected project create --permanent to fail without --name:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--name is required with --permanent") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwInitPermanentRequiresName(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init", "--permanent")
	run.Dir = tmp
	run.Env = append(os.Environ(), "AWEB_API_KEY=aw_sk_project_test")
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected init --permanent to fail without --name:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--name is required with --permanent") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwSpawnAcceptInvitePermanentRequiresName(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test", "--permanent")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected spawn accept-invite --permanent to fail without --name:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--name is required with --permanent") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwTopLevelHelpGroupsCommandsByArchitecture(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	helpCmd := exec.CommandContext(ctx, bin, "--help")
	helpCmd.Dir = tmp
	out, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("top-level help failed: %v\n%s", err, string(out))
	}

	text := string(out)
	for _, want := range []string{
		"Workspace Setup",
		"Identity",
		"Messaging & Network",
		"Coordination & Runtime",
		"Utility",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("top-level help missing group %q:\n%s", want, text)
		}
	}

	identityIdx := strings.Index(text, "Identity")
	networkIdx := strings.Index(text, "Messaging & Network")
	coordinationIdx := strings.Index(text, "Coordination & Runtime")
	if identityIdx < 0 || networkIdx < 0 || coordinationIdx < 0 {
		t.Fatalf("missing expected group boundaries:\n%s", text)
	}

	mcpIdx := strings.Index(text, "mcp-config")
	if mcpIdx < identityIdx || mcpIdx > networkIdx {
		t.Fatalf("expected mcp-config in Identity group:\n%s", text)
	}

	whoamiIdx := strings.Index(text, "whoami")
	if whoamiIdx < identityIdx || whoamiIdx > networkIdx {
		t.Fatalf("expected whoami in Identity group:\n%s", text)
	}

	runIdx := strings.Index(text, "run")
	if runIdx < coordinationIdx {
		t.Fatalf("expected run in Coordination & Runtime group:\n%s", text)
	}
}

func TestAwWhoAmIIsCanonicalCommandName(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	helpCmd := exec.CommandContext(ctx, bin, "whoami", "--help")
	helpCmd.Dir = tmp
	out, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("whoami help failed: %v\n%s", err, string(out))
	}

	text := string(out)
	if !strings.Contains(text, "Usage:\n  aw whoami [flags]") {
		t.Fatalf("expected canonical whoami usage:\n%s", text)
	}
	if !strings.Contains(text, "Aliases:\n  whoami, introspect") {
		t.Fatalf("expected introspect alias in help:\n%s", text)
	}
}

func TestAwInitRejectsProjectOverrideFlag(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init", "--project", "demo")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected aw init --project to fail, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), `unknown flag: --project`) {
		t.Fatalf("expected unknown flag error for aw init --project:\n%s", string(out))
	}
}

func TestAwProjectCreateRejectsProjectNameFlag(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "project", "create", "--project", "demo", "--project-name", "Demo")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected aw project create --project-name to fail, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), `unknown flag: --project-name`) {
		t.Fatalf("expected unknown flag error for aw project create --project-name:\n%s", string(out))
	}
}

func TestAwIntrospectEnvOverridesConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_env" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-123"})
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

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "introspect", "--json")
	run.Env = append(testCommandEnv(tmp),
		"AWEB_API_KEY=aw_sk_env",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
}

func TestAwProjectCreateUsesSuggestedAliasWhenNotExplicit(t *testing.T) {
	t.Parallel()

	var createCalls int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/create-project":
			createCalls++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["alias"] != "alice" {
				t.Fatalf("alias=%v", payload["alias"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"created_at":     "now",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-alice",
				"alias":          "alice",
				"api_key":        "aw_sk_alice",
				"created":        true,
			})
			return
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"project_id":   nil,
				"name_prefix":  "alice",
			})
			return
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "project", "create", "--project", "demo", "--print-exports=false", "--write-context=false", "--json")
	// Ensure non-TTY mode so aw init doesn't prompt during tests.
	run.Stdin = strings.NewReader("")
	run.Env = append(testCommandEnv(tmp),
		"AWEB_URL="+server.URL,
		"AW_DID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["alias"] != "alice" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if createCalls != 1 {
		t.Fatalf("createCalls=%d", createCalls)
	}
}

func TestAwAgents(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"identities": []map[string]any{
					{
						"identity_id": "agent-1",
						"alias":       "alice",
						"human_name":  "Alice",
						"agent_type":  "agent",
						"status":      "active",
						"last_seen":   "2026-02-04T10:00:00Z",
						"online":      true,
					},
					{
						"identity_id": "agent-2",
						"alias":       "bob",
						"human_name":  "Bob",
						"agent_type":  "agent",
						"status":      nil,
						"last_seen":   nil,
						"online":      false,
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "identities", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
	identities, ok := got["identities"].([]any)
	if !ok || len(identities) != 2 {
		t.Fatalf("identities=%v", got["identities"])
	}
	first := identities[0].(map[string]any)
	if first["alias"] != "alice" {
		t.Fatalf("first alias=%v", first["alias"])
	}
	if first["online"] != true {
		t.Fatalf("first online=%v", first["online"])
	}
}

func TestAwLockRenew(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/reservations/renew":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["resource_key"] != "my-lock" {
				t.Fatalf("resource_key=%v", payload["resource_key"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "renewed",
				"resource_key": "my-lock",
				"expires_at":   "2026-02-04T11:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "lock", "renew", "--resource-key", "my-lock", "--ttl-seconds", "3600", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["resource_key"] != "my-lock" {
		t.Fatalf("resource_key=%v", got["resource_key"])
	}
	if got["status"] != "renewed" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestAwNamespace(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects/current":
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"project_id": "proj-abc",
				"slug":       "my-project",
				"name":       "My Project",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "project", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-abc" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
	if got["slug"] != "my-project" {
		t.Fatalf("slug=%v", got["slug"])
	}
}

func TestAwLockRevoke(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/reservations/revoke":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["prefix"] != "test-" {
				t.Fatalf("prefix=%v", payload["prefix"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"revoked_count": 2,
				"revoked_keys":  []string{"test-lock-1", "test-lock-2"},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "lock", "revoke", "--prefix", "test-", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["revoked_count"] != float64(2) {
		t.Fatalf("revoked_count=%v", got["revoked_count"])
	}
}

func TestAwChatSendAndLeavePositionalArgs(t *testing.T) {
	t.Parallel()

	var gotReq map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":        "sess-1",
				"message_id":        "msg-1",
				"participants":      []map[string]any{},
				"sse_url":           "/v1/chat/sessions/sess-1/stream",
				"targets_connected": []string{},
				"targets_left":      []string{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "eve",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		WorkspaceID:    "workspace-1",
	})

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "bob", "hello there", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["session_id"] != "sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}

	// Verify the API request used the positional alias and message
	aliases, ok := gotReq["to_aliases"].([]any)
	if !ok || len(aliases) != 1 || aliases[0] != "bob" {
		t.Fatalf("to_aliases=%v", gotReq["to_aliases"])
	}
	if gotReq["message"] != "hello there" {
		t.Fatalf("message=%v", gotReq["message"])
	}
	if gotReq["leaving"] != true {
		t.Fatalf("leaving=%v", gotReq["leaving"])
	}
}

func TestAwChatSendAndWaitMissingArgs(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	// No positional args at all
	run := exec.CommandContext(ctx, bin, "chat", "send-and-wait")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got: %s", string(out))
	}
	if !strings.Contains(string(out), "accepts 2 arg(s)") {
		t.Fatalf("expected args error, got: %s", string(out))
	}
}

func TestAwChatSendAndWaitExtraArgsRejected(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	run := exec.CommandContext(ctx, bin, "chat", "send-and-wait", "bob", "hello", "extra-arg")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for extra args, got: %s", string(out))
	}
	if !strings.Contains(string(out), "accepts 2 arg(s)") {
		t.Fatalf("expected args error, got: %s", string(out))
	}
}

func TestAwInitWritesConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"project_id":   nil,
				"name_prefix":  "alice",
			})
			return
		case "/v1/workspaces/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"created_at":     "now",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-alice",
				"alias":          "alice",
				"api_key":        "aw_sk_alice",
				"created":        true,
				"stable_id":      "did:aw:test-stable-id",
			})
			return
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "init", "--alias", "alice", "--server-url", server.URL, "--print-exports=false", "--write-context=false", "--json")
	run.Stdin = strings.NewReader("")
	run.Env = append(testCommandEnv(tmp),
		"AWEB_API_KEY=aw_sk_project_test",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_alice" {
		t.Fatalf("api_key=%v", got["api_key"])
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if workspace.ServerURL != server.URL {
		t.Fatalf("workspace server_url=%q", workspace.ServerURL)
	}
	if workspace.APIKey != "aw_sk_alice" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
	}
	if workspace.NamespaceSlug != "demo" {
		t.Fatalf("workspace namespace_slug=%q", workspace.NamespaceSlug)
	}
	if workspace.IdentityID != "identity-alice" {
		t.Fatalf("workspace identity_id=%q", workspace.IdentityID)
	}
	if workspace.IdentityHandle != "alice" {
		t.Fatalf("workspace identity_handle=%q", workspace.IdentityHandle)
	}
	if workspace.StableID != "did:aw:test-stable-id" {
		t.Fatalf("workspace stable_id=%q", workspace.StableID)
	}
}

func TestAwInitStoresFullDomainAddress(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "myteam",
				"name_prefix":  "deploy-bot",
			})
		case "/api/v1/create-project":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"created_at":     "now",
				"project_id":     "proj-1",
				"project_slug":   "myteam",
				"identity_id":    "identity-1",
				"alias":          "deploy-bot",
				"api_key":        "aw_sk_test",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"address":        "myteam.aweb.ai/deploy-bot",
				"created":        true,
			})
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "project", "create",
		"--project", "myteam",
		"--server-url", server.URL,
		"--print-exports=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if workspace.NamespaceSlug != "myteam" {
		t.Fatalf("namespace_slug=%q, want myteam", workspace.NamespaceSlug)
	}
}

func TestAwChatSendAndLeavePositionalArgsOrder(t *testing.T) {
	t.Parallel()

	var gotReq map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":        "sess-1",
				"message_id":        "msg-1",
				"participants":      []map[string]any{},
				"sse_url":           "/v1/chat/sessions/sess-1/stream",
				"targets_connected": []string{},
				"targets_left":      []string{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "eve",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		WorkspaceID:    "workspace-1",
	})

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "bob", "hello there", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["session_id"] != "sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}

	aliases, ok := gotReq["to_aliases"].([]any)
	if !ok || len(aliases) != 1 || aliases[0] != "bob" {
		t.Fatalf("to_aliases=%v", gotReq["to_aliases"])
	}
	if gotReq["message"] != "hello there" {
		t.Fatalf("message=%v", gotReq["message"])
	}
	if gotReq["leaving"] != true {
		t.Fatalf("leaving=%v", gotReq["leaving"])
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	run := exec.CommandContext(ctx, bin, "version")
	run.Env = append(os.Environ(), "AWEB_URL=", "AWEB_API_KEY=")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if !strings.HasPrefix(string(out), "aw ") {
		t.Fatalf("unexpected version output: %s", string(out))
	}
}

func TestAwContactsList(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{
					{
						"contact_id":      "ct-1",
						"contact_address": "alice@example.com",
						"label":           "Alice",
						"created_at":      "2026-02-08T10:00:00Z",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "contacts", "list", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	contacts, ok := got["contacts"].([]any)
	if !ok || len(contacts) != 1 {
		t.Fatalf("contacts=%v", got["contacts"])
	}
	first := contacts[0].(map[string]any)
	if first["contact_address"] != "alice@example.com" {
		t.Fatalf("contact_address=%v", first["contact_address"])
	}
}

func TestAwContactsAdd(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contact_id":      "ct-1",
				"contact_address": gotBody["contact_address"],
				"label":           gotBody["label"],
				"created_at":      "2026-02-08T10:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "contacts", "add", "bob@example.com", "--label", "Bob", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["contact_id"] != "ct-1" {
		t.Fatalf("contact_id=%v", got["contact_id"])
	}
	if got["contact_address"] != "bob@example.com" {
		t.Fatalf("contact_address=%v", got["contact_address"])
	}
	if gotBody["contact_address"] != "bob@example.com" {
		t.Fatalf("req contact_address=%v", gotBody["contact_address"])
	}
	if gotBody["label"] != "Bob" {
		t.Fatalf("req label=%v", gotBody["label"])
	}
}

func TestAwContactsRemove(t *testing.T) {
	t.Parallel()

	var deletePath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/contacts" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{
					{"contact_id": "ct-1", "contact_address": "alice@example.com", "created_at": "2026-02-08T10:00:00Z"},
					{"contact_id": "ct-2", "contact_address": "bob@example.com", "created_at": "2026-02-08T11:00:00Z"},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/v1/contacts/") && r.Method == http.MethodDelete:
			deletePath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "contacts", "remove", "bob@example.com", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["deleted"] != true {
		t.Fatalf("deleted=%v", got["deleted"])
	}
	if deletePath != "/v1/contacts/ct-2" {
		t.Fatalf("delete path=%s (expected /v1/contacts/ct-2)", deletePath)
	}
}

func TestAwContactsRemoveNotFound(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "contacts", "remove", "nobody@example.com")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got: %s", string(out))
	}
	if !strings.Contains(string(out), "contact not found") {
		t.Fatalf("expected 'contact not found' error, got: %s", string(out))
	}
}

func TestAwAgentAccessModeGet(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agent_id":   "agent-1",
				"alias":      "alice",
			})
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agents": []map[string]any{
					{
						"agent_id":    "agent-1",
						"alias":       "alice",
						"online":      true,
						"access_mode": "contacts_only",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		WorkspaceID:    "workspace-1",
	})

	run := exec.CommandContext(ctx, bin, "id", "access-mode", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["identity_id"] != "agent-1" {
		t.Fatalf("identity_id=%v", got["identity_id"])
	}
	if got["access_mode"] != "contacts_only" {
		t.Fatalf("access_mode=%v", got["access_mode"])
	}
}

func TestAwAgentAccessModeSet(t *testing.T) {
	t.Parallel()

	var patchBody map[string]any
	var patchPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agent_id":   "agent-1",
				"alias":      "alice",
			})
		case strings.HasPrefix(r.URL.Path, "/v1/agents/") && r.Method == http.MethodPatch:
			patchPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&patchBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":    "agent-1",
				"access_mode": patchBody["access_mode"],
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		WorkspaceID:    "workspace-1",
	})

	run := exec.CommandContext(ctx, bin, "id", "access-mode", "open", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["agent_id"] != "agent-1" {
		t.Fatalf("agent_id=%v", got["agent_id"])
	}
	if got["access_mode"] != "open" {
		t.Fatalf("access_mode=%v", got["access_mode"])
	}
	if patchPath != "/v1/agents/agent-1" {
		t.Fatalf("patch path=%s", patchPath)
	}
	if patchBody["access_mode"] != "open" {
		t.Fatalf("patch access_mode=%v", patchBody["access_mode"])
	}
}

func TestAwIntrospectVerificationRequired(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		maskedEmail string
		wantEmail   bool
	}{
		{"with_masked_email", "t***@example.com", true},
		{"without_masked_email", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			details := map[string]any{}
			if tc.maskedEmail != "" {
				details["masked_email"] = tc.maskedEmail
			}

			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/introspect":
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error": map[string]any{
							"code":    "EMAIL_VERIFICATION_REQUIRED",
							"message": "Email verification pending.",
							"details": details,
						},
					})
				default:
					// Accept heartbeat probes.
				}
			}))

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tmp := t.TempDir()
			bin := filepath.Join(tmp, "aw")

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

			writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
				ServerURL:      server.URL,
				APIKey:         "aw_sk_test",
				IdentityID:     "agent-1",
				IdentityHandle: "alice",
				NamespaceSlug:  "demo",
				ProjectSlug:    "demo",
				WorkspaceID:    "workspace-1",
			})

			run := exec.CommandContext(ctx, bin, "introspect")
			run.Env = testCommandEnv(tmp)
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("expected failure, got success:\n%s", string(out))
			}
			outStr := string(out)
			if !strings.Contains(outStr, "aw init") {
				t.Fatalf("expected reconnect hint in error, got: %s", outStr)
			}
			if tc.wantEmail {
				if !strings.Contains(outStr, tc.maskedEmail) {
					t.Fatalf("expected masked email %q in output, got: %s", tc.maskedEmail, outStr)
				}
			} else {
				if strings.Contains(outStr, "(") {
					t.Fatalf("expected no parenthetical email in output, got: %s", outStr)
				}
			}
			// Should NOT show the raw error code.
			if strings.Contains(outStr, "EMAIL_VERIFICATION_REQUIRED") {
				t.Fatalf("expected parsed error, not raw code: %s", outStr)
			}
		})
	}
}

func TestAwIdentityReachabilityGet(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"identity_id":    "agent-1",
				"namespace_slug": "demo",
				"alias":          "alice",
				"address":        "demo/alice",
			})
		case "/v1/agents/resolve/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address":  "demo/alice",
				"lifetime": "persistent",
				"custody":  "self",
			})
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"identities": []map[string]any{
					{
						"identity_id":          "agent-1",
						"alias":                "alice",
						"online":               true,
						"address_reachability": "private",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		WorkspaceID:    "workspace-1",
	})

	run := exec.CommandContext(ctx, bin, "id", "reachability", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["identity_id"] != "agent-1" {
		t.Fatalf("identity_id=%v", got["identity_id"])
	}
	if got["address_reachability"] != "private" {
		t.Fatalf("address_reachability=%v", got["address_reachability"])
	}
}

func TestAwIdentityReachabilitySet(t *testing.T) {
	t.Parallel()

	var patchBody map[string]any
	var patchPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"identity_id":    "agent-1",
				"namespace_slug": "demo",
				"alias":          "alice",
				"address":        "demo/alice",
			})
		case r.URL.Path == "/v1/agents/resolve/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address":  "demo/alice",
				"lifetime": "persistent",
				"custody":  "self",
			})
		case strings.HasPrefix(r.URL.Path, "/v1/agents/") && r.Method == http.MethodPatch:
			patchPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&patchBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":             "agent-1",
				"address_reachability": patchBody["address_reachability"],
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		WorkspaceID:    "workspace-1",
	})

	run := exec.CommandContext(ctx, bin, "id", "reachability", "private", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["agent_id"] != "agent-1" {
		t.Fatalf("agent_id=%v", got["agent_id"])
	}
	if got["address_reachability"] != "private" {
		t.Fatalf("address_reachability=%v", got["address_reachability"])
	}
	if patchPath != "/v1/agents/agent-1" {
		t.Fatalf("patch path=%s", patchPath)
	}
	if patchBody["address_reachability"] != "private" {
		t.Fatalf("patch address_reachability=%v", patchBody["address_reachability"])
	}
	// Verify access_mode is NOT sent (omitempty should suppress it).
	if _, hasAccessMode := patchBody["access_mode"]; hasAccessMode {
		t.Fatalf("access_mode should not be in patch body when only setting reachability, got: %v", patchBody)
	}
}

// TestAwMailSendPassesThroughAllAddressFormats verifies that mail send
// passes any address format (including @handle) through to POST /v1/messages
// and lets the server resolve it.
func TestAwMailSendPassesThroughAllAddressFormats(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			gotPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-03-17T12:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	// All address formats should go through /v1/messages.
	for _, addr := range []string{"alice", "myteam.aweb.ai/deploy-bot", "@juanre"} {
		gotPath = ""
		gotBody = nil

		run := exec.CommandContext(ctx, bin, "mail", "send",
			"--to", addr,
			"--body", "hello",
			"--json",
		)
		run.Env = testCommandEnv(tmp)
		run.Dir = tmp
		out, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("addr=%q: run failed: %v\n%s", addr, err, string(out))
		}
		if gotPath != "/v1/messages" {
			t.Fatalf("addr=%q: expected /v1/messages, got %s", addr, gotPath)
		}
		if gotBody["to_alias"] != addr {
			t.Fatalf("addr=%q: to_alias=%v", addr, gotBody["to_alias"])
		}
	}
}

func TestAwInitProjectKeyRoutesToOSSInit(t *testing.T) {
	t.Parallel()

	// aw_sk_ keys from AWEB_API_KEY should route through /v1/workspaces/init.
	var initAuth string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/workspaces/init":
			initAuth = r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "live-publication-project",
				"namespace_slug": "livepub",
				"identity_id":    "identity-new",
				"alias":          "coordinator",
				"api_key":        "aw_sk_new",
				"created":        true,
				"did":            "did:key:z6MkTest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "coordinator", "roles": []string{}})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--alias", "coordinator",
		"--write-context=false",
	)
	run.Env = append(testCommandEnv(tmp),
		"AWEB_API_KEY=aw_sk_project",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if initAuth != "Bearer aw_sk_project" {
		t.Fatalf("Authorization=%q, want Bearer aw_sk_project", initAuth)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if workspace.APIKey != "aw_sk_new" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
	}
	if workspace.NamespaceSlug != "livepub" && workspace.NamespaceSlug != "live-publication-project" {
		t.Fatalf("workspace namespace_slug=%q, want livepub or live-publication-project", workspace.NamespaceSlug)
	}
	if workspace.IdentityHandle != "coordinator" {
		t.Fatalf("workspace identity_handle=%q", workspace.IdentityHandle)
	}
	if !strings.Contains(workspace.SigningKey, filepath.Join(".aw", "signing.key")) {
		t.Fatalf("workspace signing_key=%q, want .aw/signing.key", workspace.SigningKey)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.key")); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
}

func TestAwInitProjectKeyRequiresExplicitRoleInNonTTYRepo(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "coordinator", "roles": []string{"coordinator", "developer"}})
		case "/v1/workspaces/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-new",
				"alias":          "coordinator",
				"api_key":        "aw_sk_new",
				"created":        true,
				"did":            "did:key:z6MkTest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"coordinator": map[string]any{"title": "Coordinator"},
					"developer":   map[string]any{"title": "Developer"},
				},
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOrigin(t, repo, "https://github.com/acme/repo.git")

	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--alias", "coordinator",
	)
	run.Env = append(testCommandEnv(tmp),
		"AWEB_API_KEY=aw_sk_project",
	)
	run.Stdin = strings.NewReader("")
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing-role error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "no role specified; available roles: coordinator, developer") {
		t.Fatalf("unexpected error output:\n%s", string(out))
	}
}

func TestAwProjectCreateNonRepoDoesNotRequireRoleForLocalAttach(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "alice", "roles": []string{"coordinator", "developer"}})
		case "/api/v1/create-project":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-new",
				"alias":          "alice",
				"api_key":        "aw_sk_new",
				"created":        true,
				"did":            "did:key:z6MkTest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/workspaces/attach":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":    "11111111-1111-1111-1111-111111111111",
				"project_id":      "proj-1",
				"project_slug":    "demo",
				"alias":           "alice",
				"human_name":      "Alice",
				"attachment_type": "local_dir",
				"created":         true,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "project", "create",
		"--server-url", server.URL,
		"--project", "demo",
	)
	run.Env = testCommandEnv(tmp)
	run.Stdin = strings.NewReader("")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success, got error: %v\n%s", err, string(out))
	}
	if _, statErr := os.Stat(filepath.Join(tmp, ".aw", "workspace.yaml")); statErr != nil {
		t.Fatalf("workspace.yaml should be written on success, statErr=%v", statErr)
	}
}

func TestAwAcceptInviteNonRepoDoesNotRequireRoleForLocalAttach(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/accept-invite":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-new",
				"alias":          "alice",
				"api_key":        "aw_sk_new",
				"created":        true,
				"did":            "did:key:z6MkTest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/workspaces/attach":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":    "11111111-1111-1111-1111-111111111111",
				"project_id":      "proj-1",
				"project_slug":    "demo",
				"alias":           "alice",
				"human_name":      "Alice",
				"attachment_type": "local_dir",
				"created":         true,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--server-url", server.URL,
	)
	run.Env = testCommandEnv(tmp)
	run.Stdin = strings.NewReader("")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success, got error: %v\n%s", err, string(out))
	}
	if _, statErr := os.Stat(filepath.Join(tmp, ".aw", "workspace.yaml")); statErr != nil {
		t.Fatalf("workspace.yaml should be written on success, statErr=%v", statErr)
	}
}

func TestAwInitProjectKeyNonRepoDoesNotRequireRoleForLocalAttach(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/workspaces/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-new",
				"alias":          "bob",
				"api_key":        "aw_sk_new",
				"created":        true,
				"did":            "did:key:z6MkTest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "coordinator", "roles": []string{"coordinator", "developer"}})
		case "/v1/workspaces/attach":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":    "11111111-1111-1111-1111-111111111111",
				"project_id":      "proj-1",
				"project_slug":    "demo",
				"alias":           "bob",
				"human_name":      "Bob",
				"attachment_type": "local_dir",
				"created":         true,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--alias", "bob",
		"--json",
	)
	run.Env = append(testCommandEnv(tmp),
		"AWEB_API_KEY=aw_sk_project",
	)
	run.Stdin = strings.NewReader("")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success, got error: %v\n%s", err, string(out))
	}
	if !json.Valid(extractJSON(t, out)) {
		t.Fatalf("expected JSON output, got:\n%s", string(out))
	}
	if _, statErr := os.Stat(filepath.Join(tmp, ".aw", "workspace.yaml")); statErr != nil {
		t.Fatalf("workspace.yaml should be written on success, statErr=%v", statErr)
	}
}

func TestAwInitProjectKeyWithExplicitRoleAttachesLocalDir(t *testing.T) {
	t.Parallel()

	var attachCalls int

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "alice", "roles": []string{"developer", "reviewer"}})
		case "/v1/workspaces/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"identity_id":    "identity-new",
				"alias":          "alice",
				"api_key":        "aw_sk_new",
				"created":        true,
				"did":            "did:key:z6MkTest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
					"reviewer":  map[string]any{"title": "Reviewer"},
				},
			})
		case "/v1/workspaces/attach":
			attachCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":    "11111111-1111-1111-1111-111111111111",
				"project_id":      "proj-1",
				"project_slug":    "demo",
				"alias":           "alice",
				"human_name":      "Alice",
				"attachment_type": "local_dir",
				"created":         true,
			})
		case "/v1/workspaces/register":
			t.Fatalf("unexpected repo register for non-repo init")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--alias", "alice",
		"--role", "developer",
		"--json",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_API_KEY=aw_sk_project")
	run.Stdin = strings.NewReader("")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if attachCalls != 1 {
		t.Fatalf("attach calls=%d, want 1", attachCalls)
	}
	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["alias"] != "alice" {
		t.Fatalf("alias=%v", resp["alias"])
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "context")); err != nil {
		t.Fatalf("expected .aw/context: %v", err)
	}
	workspaceState, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if workspaceState.ServerURL != server.URL {
		t.Fatalf("server_url=%q", workspaceState.ServerURL)
	}
	if workspaceState.APIKey != "aw_sk_new" {
		t.Fatalf("api_key=%q", workspaceState.APIKey)
	}
	if workspaceState.ProjectSlug != "demo" {
		t.Fatalf("project_slug=%q", workspaceState.ProjectSlug)
	}
	if workspaceState.IdentityHandle != "alice" {
		t.Fatalf("identity_handle=%q", workspaceState.IdentityHandle)
	}
}

func TestAwInitProjectKeyPermanentRequestsPersistentIdentity(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	var bootstrappedDID string
	var bootstrappedStableID string
	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "Alice", "roles": []string{}})
		case "/v1/workspaces/init":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			bootstrappedDID, _ = gotBody["did"].(string)
			bootstrappedStableID = stableIDFromDidForTest(t, bootstrappedDID)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "default",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-new",
				"name":           "Alice",
				"address":        "myteam.aweb.ai/Alice",
				"api_key":        "aw_sk_new",
				"created":        true,
				"did":            bootstrappedDID,
				"stable_id":      bootstrappedStableID,
				"custody":        "self",
				"lifetime":       "persistent",
			})
		case "/v1/did":
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/" + bootstrappedStableID + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          bootstrappedStableID,
				"current_did_key": bootstrappedDID,
				"server":          serverURL,
				"address":         "myteam.aweb.ai/Alice",
				"handle":          "Alice",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--permanent",
		"--name", "Alice",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(testCommandEnv(tmp),
		"AWEB_API_KEY=aw_sk_project",
		"AWID_REGISTRY_URL=local",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if gotBody["lifetime"] != "persistent" {
		t.Fatalf("lifetime=%v", gotBody["lifetime"])
	}
	if gotBody["name"] != "Alice" {
		t.Fatalf("name=%v", gotBody["name"])
	}

	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["lifetime"] != "persistent" {
		t.Fatalf("response lifetime=%v", resp["lifetime"])
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if workspace.APIKey != "aw_sk_new" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
	}
	if workspace.NamespaceSlug != "myteam" {
		t.Fatalf("workspace namespace_slug=%q, want myteam", workspace.NamespaceSlug)
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("identity.yaml missing: %v", err)
	}
	if identity.Lifetime != "persistent" {
		t.Fatalf("identity lifetime=%q, want persistent", identity.Lifetime)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.key")); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
}

func TestAwInitProjectKeyPermanentUsesExistingWorktreeIdentity(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	address := "myteam.aweb.ai/alice"

	var gotBody map[string]any
	var didCreateCalls int
	var didUpdateCalls int
	currentRegistryServer := ""
	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "alice", "roles": []string{}})
		case "/v1/workspaces/init":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "default",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-existing",
				"name":           "alice",
				"address":        address,
				"api_key":        "aw_sk_existing",
				"created":        false,
				"did":            did,
				"stable_id":      stableID,
				"custody":        "self",
				"lifetime":       "persistent",
			})
		case "/v1/did":
			didCreateCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/" + stableID + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"server":          currentRegistryServer,
				"address":         address,
				"handle":          "alice",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"log_head": map[string]any{
					"seq":           1,
					"operation":     "create",
					"new_did_key":   did,
					"entry_hash":    strings.Repeat("a", 64),
					"state_hash":    strings.Repeat("b", 64),
					"authorized_by": did,
					"signature":     "sig",
					"timestamp":     "2026-04-04T00:00:00Z",
				},
			})
		case "/v1/did/" + stableID:
			if r.Method != http.MethodPut {
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
			didUpdateCalls++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["operation"] != "update_server" {
				t.Fatalf("operation=%v", payload["operation"])
			}
			if payload["new_did_key"] != did {
				t.Fatalf("new_did_key=%v want %v", payload["new_did_key"], did)
			}
			currentRegistryServer, _ = payload["server"].(string)
			if currentRegistryServer != serverURL {
				t.Fatalf("server=%q want %q", currentRegistryServer, serverURL)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"updated": true})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:            did,
		StableID:       stableID,
		Address:        address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    serverURL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--permanent",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_API_KEY=aw_sk_project")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if gotBody["name"] != "alice" {
		t.Fatalf("name=%v", gotBody["name"])
	}
	if gotBody["did"] != did {
		t.Fatalf("did=%v want %v", gotBody["did"], did)
	}
	if gotBody["public_key"] != base64.RawStdEncoding.EncodeToString(pub) {
		t.Fatalf("public_key=%v", gotBody["public_key"])
	}
	if gotBody["alias"] != nil {
		t.Fatalf("alias=%v want nil", gotBody["alias"])
	}
	if didCreateCalls != 0 {
		t.Fatalf("did create calls=%d want 0", didCreateCalls)
	}
	if didUpdateCalls != 1 {
		t.Fatalf("did update calls=%d want 1", didUpdateCalls)
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if workspace.APIKey != "aw_sk_existing" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if identity.DID != did {
		t.Fatalf("identity did=%q want %q", identity.DID, did)
	}
	if identity.StableID != stableID {
		t.Fatalf("identity stable_id=%q want %q", identity.StableID, stableID)
	}
	if identity.RegistryStatus != "registered" {
		t.Fatalf("registry_status=%q", identity.RegistryStatus)
	}
	if identity.RegistryURL != serverURL {
		t.Fatalf("registry_url=%q want %q", identity.RegistryURL, serverURL)
	}

	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["did"] != did {
		t.Fatalf("response did=%v want %v", resp["did"], did)
	}
}

func TestAwInitProjectKeyPermanentFailsWhenBootstrapReturnsDifferentDID(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	address := "myteam.aweb.ai/alice"

	otherPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	otherDID := awid.ComputeDIDKey(otherPub)

	var didCreateCalls int
	var didUpdateCalls int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "alice", "roles": []string{}})
		case "/v1/workspaces/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "default",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-existing",
				"name":           "alice",
				"address":        address,
				"api_key":        "aw_sk_existing",
				"created":        false,
				"did":            otherDID,
				"stable_id":      stableID,
				"custody":        "self",
				"lifetime":       "persistent",
			})
		case "/v1/did":
			didCreateCalls++
			t.Fatalf("unexpected registry create after bootstrap mismatch")
		case "/v1/did/" + stableID:
			didUpdateCalls++
			t.Fatalf("unexpected registry update after bootstrap mismatch")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:            did,
		StableID:       stableID,
		Address:        address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    server.URL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--permanent",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_API_KEY=aw_sk_project")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected bootstrap DID mismatch failure:\n%s", string(out))
	}
	if !strings.Contains(string(out), `bootstrap returned did "`) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if didCreateCalls != 0 {
		t.Fatalf("did create calls=%d want 0", didCreateCalls)
	}
	if didUpdateCalls != 0 {
		t.Fatalf("did update calls=%d want 0", didUpdateCalls)
	}
}

func TestAwInitProjectKeyPermanentFallsBackToRegisterWhenUpdateServerIsMissing(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	address := "myteam.aweb.ai/alice"

	createEntry := testDidLogEntry(t, stableID, priv, did, "create", nil, nil, 1, strings.Repeat("a", 64))
	var didCreateCalls int
	var didUpdateCalls int
	currentRegistryServer := ""
	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "alice", "roles": []string{}})
		case "/v1/workspaces/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"project_id":     "proj-1",
				"project_slug":   "default",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-existing",
				"name":           "alice",
				"address":        address,
				"api_key":        "aw_sk_existing",
				"created":        false,
				"did":            did,
				"stable_id":      stableID,
				"custody":        "self",
				"lifetime":       "persistent",
			})
		case "/v1/did":
			didCreateCalls++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["did_aw"] != stableID {
				t.Fatalf("did_aw=%v want %v", payload["did_aw"], stableID)
			}
			if payload["did_key"] != did {
				t.Fatalf("did_key=%v want %v", payload["did_key"], did)
			}
			if payload["server"] != serverURL {
				t.Fatalf("server=%v want %v", payload["server"], serverURL)
			}
			if payload["address"] != address {
				t.Fatalf("address=%v want %v", payload["address"], address)
			}
			if payload["handle"] != "alice" {
				t.Fatalf("handle=%v want alice", payload["handle"])
			}
			currentRegistryServer = serverURL
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/" + stableID + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"server":          currentRegistryServer,
				"address":         address,
				"handle":          "alice",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"log_head":        didLogJSON(createEntry),
			})
		case "/v1/did/" + stableID:
			didUpdateCalls++
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:            did,
		StableID:       stableID,
		Address:        address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    serverURL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--permanent",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_API_KEY=aw_sk_project")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if didUpdateCalls != 1 {
		t.Fatalf("did update calls=%d want 1", didUpdateCalls)
	}
	if didCreateCalls != 1 {
		t.Fatalf("did create calls=%d want 1", didCreateCalls)
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["did"] != did {
		t.Fatalf("did=%v want %v", got["did"], did)
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.RegistryStatus != "registered" {
		t.Fatalf("identity registry_status=%q", identity.RegistryStatus)
	}
	if identity.RegistryURL != serverURL {
		t.Fatalf("identity registry_url=%q want %q", identity.RegistryURL, serverURL)
	}
}

func TestAwMailSendSignsWithIdentity(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	// Generate a recipient key so the resolver can return a DID.
	recipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(recipientPub)

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		case "/v1/agents/resolve/monitor", "/v1/agents/resolve/myco/monitor":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did":     recipientDID,
				"address": "myco/monitor",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	address := "myco/agent"

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "agent",
		NamespaceSlug:  "myco",
		ProjectSlug:    "myco",
		WorkspaceID:    "workspace-1",
		DID:            did,
		Address:        address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		SigningKey:     priv,
	})

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "monitor",
		"--body", "hello from identity",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Verify the request carries identity fields.
	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v, want %s", gotBody["from_did"], did)
	}
	if gotBody["to_did"] != recipientDID {
		t.Fatalf("to_did on wire=%v, want %s", gotBody["to_did"], recipientDID)
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing or empty")
	}
	msgID, ok := gotBody["message_id"].(string)
	if !ok || msgID == "" {
		t.Fatal("message_id missing or empty")
	}

	// Same-project local delivery verifies against plain alias addressing.
	var fromStableID string
	if v, ok := gotBody["from_stable_id"].(string); ok {
		fromStableID = v
	}
	env := &awid.MessageEnvelope{
		From:         "agent",
		FromDID:      did,
		To:           "monitor",
		ToDID:        recipientDID,
		Type:         "mail",
		Body:         "hello from identity",
		Timestamp:    gotBody["timestamp"].(string),
		MessageID:    msgID,
		FromStableID: fromStableID,
		Signature:    sig,
	}
	status, verifyErr := awid.VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != awid.Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestAwMailSendSignsWithIdentityNamespace(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	// Generate a recipient key so the resolver can return a DID.
	recipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(recipientPub)

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		case "/v1/agents/resolve/monitor", "/v1/agents/resolve/acme/monitor":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did":     recipientDID,
				"address": "acme/monitor",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	address := "acme/bot"

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "bot",
		NamespaceSlug:  "acme",
		ProjectSlug:    "fallback",
		WorkspaceID:    "workspace-1",
		DID:            did,
		Address:        address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		SigningKey:     priv,
	})

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "monitor",
		"--body", "hello from namespace",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Verify local same-project signing still works when namespace_slug is present.
	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v, want %s", gotBody["from_did"], did)
	}
	if gotBody["to_did"] != recipientDID {
		t.Fatalf("to_did on wire=%v, want %s", gotBody["to_did"], recipientDID)
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing")
	}

	// Same-project local delivery verifies against plain alias addressing.
	var fromStableID string
	if v, ok := gotBody["from_stable_id"].(string); ok {
		fromStableID = v
	}
	env := &awid.MessageEnvelope{
		From:         "bot",
		FromDID:      did,
		To:           "monitor",
		ToDID:        recipientDID,
		Type:         "mail",
		Body:         "hello from namespace",
		Timestamp:    gotBody["timestamp"].(string),
		MessageID:    gotBody["message_id"].(string),
		FromStableID: fromStableID,
		Signature:    sig,
	}
	status, verifyErr := awid.VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != awid.Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestAwResetLocal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	// Create .aw/context and .aw/workspace.yaml.
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctxPath := filepath.Join(awDir, "context")
	if err := os.WriteFile(ctxPath, []byte("default_account: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspacePath := filepath.Join(awDir, "workspace.yaml")
	if err := os.WriteFile(workspacePath, []byte("server_url: https://app.aweb.ai\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "reset")
	run.Dir = tmp
	run.Env = os.Environ()
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("aw reset failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Removed") {
		t.Fatalf("expected 'Removed' message, got: %s", string(out))
	}
	if _, err := os.Stat(ctxPath); !os.IsNotExist(err) {
		t.Fatal(".aw/context still exists after reset")
	}
	if _, err := os.Stat(workspacePath); !os.IsNotExist(err) {
		t.Fatal(".aw/workspace.yaml still exists after reset")
	}
	if _, err := os.Stat(awDir); !os.IsNotExist(err) {
		t.Fatal(".aw directory still exists after reset (should be cleaned up when empty)")
	}
}

func TestAwMailSendWritesCommLog(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-log-1",
				"status":       "delivered",
				"delivered_at": "2026-02-26T12:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "eve",
		"--body", "hello from log test",
		"--subject", "log test",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Communication logs now live in the per-user state dir under ~/.config/aw/logs.
	logMatches, err := filepath.Glob(filepath.Join(tmp, ".config", "aw", "logs", "*.jsonl"))
	if err != nil {
		t.Fatalf("glob log files: %v", err)
	}
	if len(logMatches) != 1 {
		t.Fatalf("expected one log file, got %v", logMatches)
	}
	logData, err := os.ReadFile(logMatches[0])
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}

	var entry CommLogEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(logData))), &entry); err != nil {
		t.Fatalf("invalid log entry: %v\ndata: %s", err, string(logData))
	}
	if entry.Dir != "send" {
		t.Fatalf("dir=%q, want send", entry.Dir)
	}
	if entry.Channel != "mail" {
		t.Fatalf("channel=%q, want mail", entry.Channel)
	}
	if entry.MessageID != "msg-log-1" {
		t.Fatalf("message_id=%q, want msg-log-1", entry.MessageID)
	}
	if entry.Body != "hello from log test" {
		t.Fatalf("body=%q", entry.Body)
	}
	if entry.Subject != "log test" {
		t.Fatalf("subject=%q", entry.Subject)
	}
}

func TestDefaultServerURL(t *testing.T) {
	t.Parallel()
	if DefaultServerURL != "https://app.aweb.ai" {
		t.Fatalf("DefaultServerURL=%q, want https://app.aweb.ai", DefaultServerURL)
	}
}

func TestResolveBaseURLForInitFallsBackToDefault(t *testing.T) {
	// Cannot use t.Parallel() — needs env and cwd control.

	tmp := t.TempDir()

	origCfg := os.Getenv("AW_CONFIG_PATH")
	origURL := os.Getenv("AWEB_URL")
	origWd, _ := os.Getwd()
	os.Setenv("AW_CONFIG_PATH", "")
	os.Setenv("AWEB_URL", "")
	os.Chdir(tmp)
	defer func() {
		os.Setenv("AW_CONFIG_PATH", origCfg)
		os.Setenv("AWEB_URL", origURL)
		os.Chdir(origWd)
	}()

	// resolveBaseURLForInit should fall back to the default URL.
	// If the server is reachable, we get a URL back; if not, the error
	// should mention app.aweb.ai. Either way, the default was used.
	baseURL, serverName, err := resolveBaseURLForInit("", "")
	if err != nil {
		if !strings.Contains(err.Error(), "app.aweb.ai") {
			t.Fatalf("expected error to reference default URL app.aweb.ai, got: %v", err)
		}
		return
	}
	if !strings.Contains(baseURL, "app.aweb.ai") {
		t.Fatalf("expected baseURL to contain app.aweb.ai, got %q", baseURL)
	}
	if !strings.Contains(serverName, "app.aweb.ai") {
		t.Fatalf("expected serverName to contain app.aweb.ai, got %q", serverName)
	}
}

func TestInitDefaultServerUsedWhenNoURLProvided(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "alice", "roles": []string{}})
		case "/api/v1/create-project":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"created_at":     "2026-03-16T10:00:00Z",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"identity_id":    "identity-1",
				"alias":          "alice",
				"api_key":        "aw_sk_test",
				"namespace_slug": "demo",
				"created":        true,
				"did":            "did:key:z6Mktest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	buildAwBinary(t, ctx, bin)

	// Use AWEB_URL to point at test server. The test verifies that
	// when --server-url is omitted, the init flow still works (using
	// whatever URL resolution provides, including the default).
	run := exec.CommandContext(ctx, bin, "project", "create",
		"--project", "demo",
		"--alias", "alice",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(testCommandEnv(tmp),
		"AWEB_URL="+server.URL,
		"AW_DID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "alice") {
		t.Fatalf("expected output to mention alias alice, got: %s", string(out))
	}
}

func TestInitWorkspaceAttachNonFatal(t *testing.T) {
	t.Parallel()

	// Server handles create-project but returns 404 for /v1/workspaces/register.
	// Init should succeed with a warning, not fail.
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/create-project":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"created_at":     "2026-03-16T10:00:00Z",
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"identity_id":    "identity-1",
				"alias":          "alice",
				"api_key":        "aw_sk_test",
				"namespace_slug": "demo",
				"created":        true,
				"did":            "did:key:z6Mktest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/workspaces/register":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		case "/v1/roles/active":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		default:
			// Ignore other requests (heartbeat etc handled by wrapper)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOrigin(t, repo, "https://github.com/acme/repo.git")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "project", "create",
		"--project", "demo",
		"--alias", "alice",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(testCommandEnv(tmp),
		"AWEB_URL="+server.URL,
		"AW_DID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init should succeed even when workspace attach fails: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "alice") {
		t.Fatalf("expected output to mention alias, got: %s", string(out))
	}
}

func TestMCPConfig(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      "https://app.aweb.ai",
		APIKey:         "aw_sk_testkey123",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		WorkspaceID:    "workspace-1",
	})

	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "mcp-config")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("mcp-config failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}

	servers, ok := got["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("expected mcpServers key, got: %s", string(out))
	}
	aweb, ok := servers["aweb"].(map[string]any)
	if !ok {
		t.Fatalf("expected mcpServers.aweb key, got: %s", string(out))
	}
	if aweb["url"] != "https://app.aweb.ai/mcp" {
		t.Fatalf("url=%v", aweb["url"])
	}
	headers, ok := aweb["headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected headers key, got: %s", string(out))
	}
	if headers["Authorization"] != "Bearer aw_sk_testkey123" {
		t.Fatalf("Authorization=%v", headers["Authorization"])
	}
}
