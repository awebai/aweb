package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
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
	cfgPath := filepath.Join(tmp, "config.yaml")

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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "introspect", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    namespace_slug: testns
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Run WITHOUT --json: should produce human-readable text.
	run := exec.CommandContext(ctx, bin, "introspect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    did: "did:key:z6MkTestKey123"
    custody: "self"
    lifetime: "persistent"
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "introspect", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	identityHelp := exec.CommandContext(ctx, bin, "identity", "--help")
	identityHelp.Dir = tmp
	identityOut, err := identityHelp.CombinedOutput()
	if err != nil {
		t.Fatalf("identity help failed: %v\n%s", err, string(identityOut))
	}

	identityText := string(identityOut)
	for _, want := range []string{
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

	idHelp := exec.CommandContext(ctx, bin, "id", "--help")
	idHelp.Dir = tmp
	idOut, err := idHelp.CombinedOutput()
	if err == nil {
		t.Fatalf("expected aw id --help to fail, got success:\n%s", string(idOut))
	}

	idText := string(idOut)
	if !strings.Contains(idText, `unknown command "id"`) {
		t.Fatalf("expected unknown command error for aw id --help:\n%s", idText)
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

func TestAwIntrospectServerFlagSelectsConfiguredServer(t *testing.T) {
	t.Parallel()

	serverA := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_a" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-a"})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	serverB := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_b" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-b"})
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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  a:
    url: `+serverA.URL+`
  b:
    url: `+serverB.URL+`
accounts:
  acct_a:
    server: a
    api_key: aw_sk_a
  acct_b:
    server: b
    api_key: aw_sk_b
default_account: acct_a
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".aw", "context"), []byte(strings.TrimSpace(`
default_account: acct_a
server_accounts:
  b: acct_b
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write context: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "introspect", "--server-name", "b", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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
	if got["project_id"] != "proj-b" {
		t.Fatalf("project_id=%v", got["project_id"])
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
	cfgPath := filepath.Join(tmp, "config.yaml")

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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_config
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "introspect", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_API_KEY=aw_sk_env",
		"AWEB_URL=",
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
	cfgPath := filepath.Join(tmp, "config.yaml")

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
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "identities", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "lock", "renew", "--resource-key", "my-lock", "--ttl-seconds", "3600", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "project", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "lock", "revoke", "--prefix", "test-", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    identity_handle: eve
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "bob", "hello there", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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
	run.Env = append(os.Environ(), "AW_CONFIG_PATH=/nonexistent")
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
	run.Env = append(os.Environ(), "AW_CONFIG_PATH=/nonexistent")
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
	cfgPath := filepath.Join(tmp, "config.yaml")

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

	run := exec.CommandContext(ctx, bin, "init", "--alias", "alice", "--server-name", "local", "--server-url", server.URL, "--account", "acct", "--print-exports=false", "--write-context=false", "--json")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
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

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Servers        map[string]map[string]any `yaml:"servers"`
		Accounts       map[string]map[string]any `yaml:"accounts"`
		DefaultAccount string                    `yaml:"default_account"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	if cfg.DefaultAccount != "acct" {
		t.Fatalf("default_account=%q", cfg.DefaultAccount)
	}
	localSrv, ok := cfg.Servers["local"]
	if !ok {
		t.Fatalf("missing servers.local")
	}
	if localSrv["url"] != server.URL {
		t.Fatalf("servers.local.url=%v", localSrv["url"])
	}
	acct, ok := cfg.Accounts["acct"]
	if !ok {
		t.Fatalf("missing accounts.acct")
	}
	if acct["server"] != "local" {
		t.Fatalf("accounts.acct.server=%v", acct["server"])
	}
	if acct["api_key"] != "aw_sk_alice" {
		t.Fatalf("accounts.acct.api_key=%v", acct["api_key"])
	}
	if acct["namespace_slug"] != "demo" {
		t.Fatalf("accounts.acct.namespace_slug=%v", acct["namespace_slug"])
	}
	if acct["identity_id"] != "identity-alice" {
		t.Fatalf("accounts.acct.identity_id=%v", acct["identity_id"])
	}
	if acct["identity_handle"] != "alice" {
		t.Fatalf("accounts.acct.identity_handle=%v", acct["identity_handle"])
	}
	stableID, _ := acct["stable_id"].(string)
	if stableID != "did:aw:test-stable-id" {
		t.Fatalf("accounts.acct.stable_id=%v, want did:aw:test-stable-id", acct["stable_id"])
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
	cfgPath := filepath.Join(tmp, "config.yaml")

	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "project", "create",
		"--project", "myteam",
		"--server-name", "local",
		"--server-url", server.URL,
		"--account", "acct",
		"--print-exports=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	acct, ok := cfg.Accounts["acct"]
	if !ok {
		t.Fatalf("missing accounts.acct")
	}
	// The config should store the authoritative namespace slug, not the
	// full domain label.
	if acct["namespace_slug"] != "myteam" {
		t.Fatalf("namespace_slug=%v, want myteam", acct["namespace_slug"])
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    identity_handle: eve
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "bob", "hello there", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "contacts", "list", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "contacts", "add", "bob@example.com", "--label", "Bob", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "contacts", "remove", "bob@example.com", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "contacts", "remove", "nobody@example.com")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "access-mode", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "access-mode", "open", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

			if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    email: test@example.com
default_account: acct
`)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			run := exec.CommandContext(ctx, bin, "introspect")
			run.Env = append(os.Environ(),
				"AW_CONFIG_PATH="+cfgPath,
				"AWEB_URL=",
				"AWEB_API_KEY=",
			)
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("expected failure, got success:\n%s", string(out))
			}
			outStr := string(out)
			if !strings.Contains(outStr, "aw connect") {
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "reachability", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "reachability", "private", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// All address formats should go through /v1/messages.
	for _, addr := range []string{"alice", "myteam.aweb.ai/deploy-bot", "@juanre"} {
		gotPath = ""
		gotBody = nil

		run := exec.CommandContext(ctx, bin, "mail", "send",
			"--to", addr,
			"--body", "hello",
			"--json",
		)
		run.Env = append(os.Environ(),
			"AW_CONFIG_PATH="+cfgPath,
			"AWEB_URL=",
			"AWEB_API_KEY=",
		)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--alias", "coordinator",
		"--write-context=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
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
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	var found bool
	for name, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_new" {
			found = true
			if acct["namespace_slug"] != "livepub" && acct["namespace_slug"] != "live-publication-project" {
				t.Fatalf("accounts.%s.namespace_slug=%v, want livepub or live-publication-project", name, acct["namespace_slug"])
			}
			if acct["identity_handle"] != "coordinator" {
				t.Fatalf("accounts.%s.identity_handle=%v, want coordinator", name, acct["identity_handle"])
			}
		}
	}
	if !found {
		t.Fatalf("no account with api_key=aw_sk_new in config:\n%s", string(data))
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--alias", "coordinator",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "project", "create",
		"--server-url", server.URL,
		"--project", "demo",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Stdin = strings.NewReader("")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success, got error: %v\n%s", err, string(out))
	}
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		t.Fatalf("config should be written on success, statErr=%v", statErr)
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "spawn", "accept-invite", "aw_inv_test",
		"--server-url", server.URL,
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Stdin = strings.NewReader("")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success, got error: %v\n%s", err, string(out))
	}
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		t.Fatalf("config should be written on success, statErr=%v", statErr)
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--alias", "bob",
		"--json",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
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
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		t.Fatalf("config should be written on success, statErr=%v", statErr)
	}
}

func TestAwInitProjectKeyPermanentRequestsPersistentIdentity(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "Alice", "roles": []string{}})
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
				"identity_id":    "identity-new",
				"name":           "Alice",
				"address":        "myteam.aweb.ai/Alice",
				"api_key":        "aw_sk_new",
				"created":        true,
				"did":            "did:key:z6MkPermanentProjectKey",
				"stable_id":      "stable-project-key",
				"custody":        "self",
				"lifetime":       "persistent",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--permanent",
		"--name", "Alice",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=aw_sk_project",
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

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	var found bool
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_new" {
			found = true
			if acct["namespace_slug"] != "myteam" {
				t.Fatalf("namespace_slug=%v, want myteam", acct["namespace_slug"])
			}
			if acct["lifetime"] != "persistent" {
				t.Fatalf("lifetime=%v, want persistent", acct["lifetime"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("no account with api_key=aw_sk_new in config:\n%s", string(data))
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	keysDir := filepath.Join(tmp, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

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

	// Save the signing key to disk.
	address := "myco/agent"
	if err := awid.SaveKeypair(keysDir, address, pub, priv); err != nil {
		t.Fatal(err)
	}
	keyPath := awid.SigningKeyPath(keysDir, address)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    did: "`+did+`"
    signing_key: "`+keyPath+`"
    custody: "self"
    default_project: "myco"
    identity_handle: "agent"
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "monitor",
		"--body", "hello from identity",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	keysDir := filepath.Join(tmp, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

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

	// namespace_slug still determines the external address, but same-project
	// local mail signs plain local names.
	address := "acme/bot"
	if err := awid.SaveKeypair(keysDir, address, pub, priv); err != nil {
		t.Fatal(err)
	}
	keyPath := awid.SigningKeyPath(keysDir, address)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    did: "`+did+`"
    signing_key: "`+keyPath+`"
    custody: "self"
    namespace_slug: "acme"
    default_project: "fallback"
    identity_handle: "bot"
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "monitor",
		"--body", "hello from namespace",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
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

func TestAwConnect(t *testing.T) {
	t.Parallel()

	const stableID = "did:aw:GrRZYotwid5A4FxaddwPxsxChzo"
	const did = "did:key:z6MkConnectImported"
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"agent_id":   "agent-1",
				"alias":      "alice",
				"human_name": "Alice",
				"agent_type": "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
				"name":       "My Company",
			})
		case "/v1/agents/resolve/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":       did,
				"stable_id": stableID,
				"address":   "myco/alice",
				"custody":   "custodial",
				"lifetime":  "persistent",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Write empty config — no accounts configured.
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if strings.Contains(string(out), "(agent-1)") {
		t.Fatalf("connect output should not expose raw identity UUID:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Imported identity context for myco/alice") {
		t.Fatalf("expected identity-focused import summary, got:\n%s", string(out))
	}

	// Verify config was written with identity fields.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Servers        map[string]map[string]any `yaml:"servers"`
		Accounts       map[string]map[string]any `yaml:"accounts"`
		DefaultAccount string                    `yaml:"default_account"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	if cfg.DefaultAccount == "" {
		t.Fatal("default_account not set")
	}
	// Find the account with our API key.
	var found bool
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_test" {
			found = true
			if acct["identity_id"] != "agent-1" {
				t.Fatalf("identity_id=%v", acct["identity_id"])
			}
			if acct["identity_handle"] != "alice" {
				t.Fatalf("identity_handle=%v", acct["identity_handle"])
			}
			if acct["namespace_slug"] != "myco" {
				t.Fatalf("namespace_slug=%v, want myco", acct["namespace_slug"])
			}
			// Verify identity fields are populated.
			importedDID, _ := acct["did"].(string)
			if importedDID != did {
				t.Fatalf("did=%v, want did:key:z...", acct["did"])
			}
			signingKey, _ := acct["signing_key"].(string)
			if signingKey != "" {
				t.Fatalf("signing_key=%q, want empty for imported custodial identity", signingKey)
			}
			if acct["custody"] != "custodial" {
				t.Fatalf("custody=%v, want custodial", acct["custody"])
			}
			if acct["lifetime"] != "persistent" {
				t.Fatalf("lifetime=%v, want persistent", acct["lifetime"])
			}
			if acct["stable_id"] != stableID {
				t.Fatalf("stable_id=%v, want %s", acct["stable_id"], stableID)
			}
			break
		}
	}
	if !found {
		t.Fatalf("no account with api_key=aw_sk_test in config:\n%s", string(data))
	}
	// Verify server entry exists.
	if len(cfg.Servers) == 0 {
		t.Fatal("no servers in config")
	}

	// Verify .aw/context was written.
	ctxPath := filepath.Join(tmp, ".aw", "context")
	if _, err := os.Stat(ctxPath); os.IsNotExist(err) {
		t.Fatal(".aw/context not written")
	}
}

func TestAwConnectPreservesExistingIdentity(t *testing.T) {
	t.Parallel()

	pub, priv, _ := ed25519.GenerateKey(nil)
	existingDID := awid.ComputeDIDKey(pub)

	var identityCalled atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-123",
				"identity_id":    "agent-1",
				"namespace_slug": "myco",
				"alias":          "alice",
				"agent_type":     "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})
		case "/v1/agents/resolve/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":       existingDID,
				"address":   "myco/alice",
				"stable_id": "did:aw:existing",
				"custody":   "self",
				"lifetime":  "persistent",
			})
		case "/v1/agents/me/identity":
			identityCalled.Store(true)
			w.WriteHeader(200)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Pre-populate config with existing identity.
	keysDir := filepath.Join(tmp, "keys")
	_ = os.MkdirAll(keysDir, 0o700)
	_ = awid.SaveKeypair(keysDir, "myco/alice", pub, priv)
	keyPath := awid.SigningKeyPath(keysDir, "myco/alice")

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  `+server.Listener.Addr().String()+`:
    url: `+server.URL+`
accounts:
  acct-`+server.Listener.Addr().String()+`__agent-1:
    server: `+server.Listener.Addr().String()+`
    api_key: aw_sk_test
    identity_id: agent-1
    identity_handle: alice
    namespace_slug: myco
    did: "`+existingDID+`"
    signing_key: "`+keyPath+`"
    custody: self
    lifetime: persistent
    stable_id: "did:aw:existing"
default_account: acct-`+server.Listener.Addr().String()+`__agent-1
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Should NOT call /v1/agents/me/identity when identity exists.
	if identityCalled.Load() {
		t.Fatal("/v1/agents/me/identity should not be called when identity already exists")
	}

	// Verify existing identity is preserved.
	data, _ := os.ReadFile(cfgPath)
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	_ = yaml.Unmarshal(data, &cfg)
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_test" {
			if acct["did"] != existingDID {
				t.Fatalf("did=%v, want %s (preserved)", acct["did"], existingDID)
			}
			if acct["stable_id"] != "did:aw:existing" {
				t.Fatalf("stable_id=%v, want did:aw:existing (preserved)", acct["stable_id"])
			}
			break
		}
	}
}

func TestAwConnectDoesNotOverrideExistingContextDefaultWithoutSetDefault(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-123",
				"identity_id":    "agent-1",
				"namespace_slug": "myco",
				"alias":          "alice",
				"agent_type":     "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})
		case "/v1/agents/resolve/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":      "did:key:z6MkConnectDefault",
				"address":  "myco/alice",
				"custody":  "custodial",
				"lifetime": "persistent",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Pre-create a context that already has a default identity.
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".aw", "context"), []byte(strings.TrimSpace(`
default_account: keep-me
server_accounts:
  example.com: keep-me
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Write empty config — connect will add the new account.
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
		"AW_DID_REGISTRY_URL=http://127.0.0.1:1", // unreachable — forces best-effort failure
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	ctxData, err := os.ReadFile(filepath.Join(tmp, ".aw", "context"))
	if err != nil {
		t.Fatalf("read context: %v", err)
	}
	var got awconfig.WorktreeContext
	if err := yaml.Unmarshal(ctxData, &got); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(ctxData))
	}
	if got.DefaultAccount != "keep-me" {
		t.Fatalf("default_account=%q, want keep-me", got.DefaultAccount)
	}
	serverName, _ := awconfig.DeriveServerNameFromURL(server.URL)
	if got.ServerAccounts[serverName] == "" {
		t.Fatalf("expected server_accounts[%q] to be set", serverName)
	}
}

func TestAwConnectIdentityAlreadySetNoLocalKey(t *testing.T) {
	t.Parallel()
	t.Skip("obsolete under import-only connect semantics")

	// Pre-create a keypair that the server will report as the agent's identity,
	// but do NOT save it to the test's keysDir — simulating key loss.
	// provisionIdentity will generate and save a different key, which won't
	// match the server's DID, triggering the "no matching key" error.
	pub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverDID := awid.ComputeDIDKey(pub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":  "proj-123",
				"identity_id": "agent-1",
				"alias":       "alice",
				"agent_type":  "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})
		case "/v1/agents/me/identity":
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "IDENTITY_ALREADY_SET",
					"message": "identity already bound",
				},
			})
		case "/v1/agents/resolve/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":         serverDID,
				"identity_id": "agent-1",
				"address":     "myco/alice",
				"custody":     "self",
				"lifetime":    "persistent",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	if runErr == nil {
		t.Fatalf("expected error for 409 with no local key, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "no matching signing key found locally") {
		t.Fatalf("expected 'no matching signing key found locally', got: %s", string(out))
	}
	if !strings.Contains(string(out), "aw identity delete --confirm") {
		t.Fatalf("expected recovery suggestion with 'aw identity delete --confirm', got: %s", string(out))
	}
}

func TestAwConnectRecoverWith409AndLocalKey(t *testing.T) {
	t.Parallel()
	t.Skip("obsolete under import-only connect semantics")

	// Pre-create a keypair that the server will report as the agent's identity.
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverDID := awid.ComputeDIDKey(pub)
	serverStableID := awid.ComputeStableID(pub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":  "proj-123",
				"identity_id": "agent-1",
				"alias":       "alice",
				"agent_type":  "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})
		case "/v1/agents/me/identity":
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "IDENTITY_ALREADY_SET",
					"message": "identity already bound",
				},
			})
		case "/v1/agents/resolve/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":         serverDID,
				"stable_id":   serverStableID,
				"identity_id": "agent-1",
				"address":     "myco/alice",
				"custody":     "self",
				"lifetime":    "persistent",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Save the keypair to the keys directory so recovery can find it.
	keysDir := filepath.Join(filepath.Dir(cfgPath), "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveKeypair(keysDir, "myco/alice", pub, priv); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	if runErr != nil {
		t.Fatalf("expected 409 recovery to succeed, got error: %v\n%s", runErr, string(out))
	}

	// Verify config was written with recovered identity fields.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_test" {
			did, _ := acct["did"].(string)
			if did != serverDID {
				t.Fatalf("did=%q, want %q", did, serverDID)
			}
			signingKey, _ := acct["signing_key"].(string)
			if signingKey == "" {
				t.Fatal("signing_key not set after recovery")
			}
			if acct["custody"] != "self" {
				t.Fatalf("custody=%v, want self", acct["custody"])
			}
			if acct["lifetime"] != "persistent" {
				t.Fatalf("lifetime=%v, want persistent", acct["lifetime"])
			}
			if acct["stable_id"] != serverStableID {
				t.Fatalf("stable_id=%q, want %q", acct["stable_id"], serverStableID)
			}
			return
		}
	}
	t.Fatalf("no account with api_key=aw_sk_test in config:\n%s", string(data))
}

func TestAwConnectUsesServerStableID(t *testing.T) {
	t.Parallel()

	const stableID = "did:aw:4FAsTHsY3uUjQ6rLw8TDwQyd5Ek"
	const did = "did:key:z6MkServerStableID"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-123",
				"identity_id":    "agent-1",
				"namespace_slug": "myco",
				"address":        "myco/alice",
				"agent_type":     "agent",
			})
		case "/v1/agents/resolve/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":       did,
				"stable_id": stableID,
				"address":   "myco/alice",
				"custody":   "custodial",
				"lifetime":  "persistent",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed (should succeed despite stable ID failure): %v\n%s", err, string(out))
	}

	// Connect should persist the server-issued did:aw stable_id.
	data, _ := os.ReadFile(cfgPath)
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	_ = yaml.Unmarshal(data, &cfg)
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_test" {
			gotDID, _ := acct["did"].(string)
			if gotDID != did {
				t.Fatalf("did=%v, want did:key:z...", acct["did"])
			}
			if acct["stable_id"] != stableID {
				t.Fatalf("stable_id=%v, want %s", acct["stable_id"], stableID)
			}
			break
		}
	}
}

func TestAwConnectMissingEnvVars(t *testing.T) {
	t.Parallel()

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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	// No AWEB_URL or AWEB_API_KEY — should fail.
	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "AWEB_URL") {
		t.Fatalf("expected error mentioning AWEB_URL, got: %s", string(out))
	}
}

func TestAwConnectNoAgentID(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			// User-scoped key: no agent_id.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"user_id":    "user-1",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for user-scoped key, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "identity-bound") {
		t.Fatalf("expected error about identity-bound key, got: %s", string(out))
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

	// Create .aw/context.
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctxPath := filepath.Join(awDir, "context")
	if err := os.WriteFile(ctxPath, []byte("default_account: test\n"), 0o600); err != nil {
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

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct-log-test:
    server: local
    api_key: aw_sk_test
default_account: acct-log-test
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "eve",
		"--body", "hello from log test",
		"--subject", "log test",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// The log should be in the same directory as config.yaml, under logs/.
	logFile := filepath.Join(tmp, "logs", "acct-log-test.jsonl")
	logData, err := os.ReadFile(logFile)
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origCfg := os.Getenv("AW_CONFIG_PATH")
	origURL := os.Getenv("AWEB_URL")
	origWd, _ := os.Getwd()
	os.Setenv("AW_CONFIG_PATH", cfgPath)
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
	baseURL, serverName, _, err := resolveBaseURLForInit("", "")
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

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
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOrigin(t, repo, "https://github.com/acme/repo.git")
	buildAwBinary(t, ctx, bin)

	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "project", "create",
		"--project", "demo",
		"--alias", "alice",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
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
	cfgPath := filepath.Join(tmp, "config.yaml")

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  prod:
    url: https://app.aweb.ai
accounts:
  acct:
    server: prod
    api_key: aw_sk_testkey123
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "mcp-config")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
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

func TestMCPConfigAll(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: http://localhost:8000
  prod:
    url: https://app.aweb.ai
accounts:
  local-alice:
    server: local
    api_key: aw_sk_local
  prod-alice:
    server: prod
    api_key: aw_sk_prod
default_account: local-alice
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "mcp-config", "--all")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("mcp-config --all failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}

	servers, ok := got["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("expected mcpServers key, got: %s", string(out))
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 mcpServers entries, got %d: %s", len(servers), string(out))
	}
	local, ok := servers["local-alice"].(map[string]any)
	if !ok {
		t.Fatalf("expected mcpServers.local-alice, got: %s", string(out))
	}
	if local["url"] != "http://localhost:8000/mcp" {
		t.Fatalf("local url=%v", local["url"])
	}
	prod, ok := servers["prod-alice"].(map[string]any)
	if !ok {
		t.Fatalf("expected mcpServers.prod-alice, got: %s", string(out))
	}
	if prod["url"] != "https://app.aweb.ai/mcp" {
		t.Fatalf("prod url=%v", prod["url"])
	}
}
