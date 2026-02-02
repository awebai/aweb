package main

import (
	"context"
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

	"gopkg.in/yaml.v3"
)

func newLocalHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestAwIntrospect(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/introspect" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-123"})
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

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
}

func TestAwIntrospectServerFlagSelectsConfiguredServer(t *testing.T) {
	t.Parallel()

	serverA := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/introspect" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer aw_sk_a" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-a"})
	}))

	serverB := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/introspect" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer aw_sk_b" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-b"})
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

	run := exec.CommandContext(ctx, bin, "introspect", "--server", "b")
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
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-b" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
}

func TestAwIntrospectEnvOverridesConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/introspect" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer aw_sk_env" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-123"})
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

	run := exec.CommandContext(ctx, bin, "introspect")
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
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
}

func TestAwInitRetriesWhenSuggestedAliasAlreadyExists(t *testing.T) {
	t.Parallel()

	var initCalls int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"project_id":   nil,
				"name_prefix":  "alice",
			})
			return
		case "/v1/init":
			initCalls++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_, hasAuth := r.Header["Authorization"]
			if hasAuth {
				t.Fatalf("unexpected auth header on init")
			}

			switch initCalls {
			case 1:
				if payload["alias"] != "alice" {
					t.Fatalf("first alias=%v", payload["alias"])
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       "ok",
					"created_at":   "now",
					"project_id":   "proj-1",
					"project_slug": "demo",
					"agent_id":     "agent-alice",
					"alias":        "alice",
					"api_key":      "aw_sk_alice",
					"created":      false,
				})
				return
			case 2:
				if _, ok := payload["alias"]; ok {
					t.Fatalf("expected alias omitted on retry, got %v", payload["alias"])
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       "ok",
					"created_at":   "now",
					"project_id":   "proj-1",
					"project_slug": "demo",
					"agent_id":     "agent-bob",
					"alias":        "bob",
					"api_key":      "aw_sk_bob",
					"created":      true,
				})
				return
			default:
				t.Fatalf("unexpected init call %d", initCalls)
			}
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

	run := exec.CommandContext(ctx, bin, "init", "--project-slug", "demo", "--print-exports=false", "--write-context=false")
	// Ensure non-TTY mode so aw init doesn't prompt during tests.
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["alias"] != "bob" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if initCalls != 2 {
		t.Fatalf("initCalls=%d", initCalls)
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
		case "/v1/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "ok",
				"created_at":   "now",
				"project_id":   "proj-1",
				"project_slug": "demo",
				"agent_id":     "agent-alice",
				"alias":        "alice",
				"api_key":      "aw_sk_alice",
				"created":      true,
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

	run := exec.CommandContext(ctx, bin, "init", "--project-slug", "demo", "--server", "local", "--url", server.URL, "--account", "acct", "--print-exports=false", "--write-context=false")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
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
	if acct["default_project"] != "demo" {
		t.Fatalf("accounts.acct.default_project=%v", acct["default_project"])
	}
	if acct["agent_id"] != "agent-alice" {
		t.Fatalf("accounts.acct.agent_id=%v", acct["agent_id"])
	}
	if acct["agent_alias"] != "alice" {
		t.Fatalf("accounts.acct.agent_alias=%v", acct["agent_alias"])
	}
}
