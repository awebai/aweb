package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testNamespaceConfig(t *testing.T, serverURL string) (bin, cfgPath, tmp string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp = t.TempDir()
	bin = filepath.Join(tmp, "aw")
	cfgPath = filepath.Join(tmp, "config.yaml")

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
    url: `+serverURL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return
}

func TestAwNamespaceAdd(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case "/api/v1/projects/p-1/namespaces/external":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"slug":                "acme-com",
				"full_name":           "acme.com",
				"display_name":        "acme.com",
				"is_external":         true,
				"dns_txt_name":        "_awid.acme.com",
				"dns_txt_value":       "awid=v1; controller=did:key:z6Mkf; registry=https://api.awid.ai;",
				"dns_status":          "desired",
				"registration_status": "unregistered",
				"created_at":          "2026-03-19T10:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, bin, "project", "namespace", "add", "acme.com", "--json")
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

	if gotBody["domain"] != "acme.com" {
		t.Fatalf("domain=%v", gotBody["domain"])
	}

	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["full_name"] != "acme.com" {
		t.Fatalf("full_name=%v", resp["full_name"])
	}
}

func TestAwNamespaceAddTextOutput(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case "/api/v1/projects/p-1/namespaces/external":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":  "ns-1",
				"full_name":     "acme.com",
				"dns_txt_name":  "_awid.acme.com",
				"dns_txt_value": "awid=v1; controller=did:key:z6Mkf; registry=https://api.awid.ai;",
				"dns_status":    "desired",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, bin, "project", "namespace", "add", "acme.com")
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

	output := string(out)
	if !strings.Contains(output, "acme.com") {
		t.Fatalf("expected domain in output:\n%s", output)
	}
	if !strings.Contains(output, "_awid.acme.com") {
		t.Fatalf("expected TXT name in output:\n%s", output)
	}
	if !strings.Contains(output, "aw project namespace verify") {
		t.Fatalf("expected verify instruction in output:\n%s", output)
	}
	if !strings.Contains(output, "Wait for DNS propagation") {
		t.Fatalf("expected DNS propagation guidance in output:\n%s", output)
	}
}

func TestAwNamespaceList(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case "/api/v1/projects/p-1/namespaces":
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"namespace_id":            "ns-1",
					"full_name":               "myteam.aweb.ai",
					"is_external":             false,
					"registration_status":     "registered",
					"assigned_identity_count": 3,
				},
				{
					"namespace_id":            "ns-2",
					"full_name":               "acme.com",
					"is_external":             true,
					"registration_status":     "unregistered",
					"assigned_identity_count": 0,
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// JSON output.
	run := exec.CommandContext(ctx, bin, "project", "namespace", "list", "--json")
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

	if !strings.Contains(string(out), "myteam.aweb.ai") {
		t.Fatalf("expected myteam.aweb.ai in output:\n%s", string(out))
	}
}

func TestAwNamespaceListPreservesAPIBaseURL(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case "/api/v1/projects/p-1/namespaces":
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"full_name":               "myteam.aweb.ai",
					"is_external":             false,
					"registration_status":     "registered",
					"assigned_identity_count": 3,
				},
			})
		case "/v1/auth/introspect":
			t.Fatalf("unexpected introspect without /api prefix: %s", r.URL.Path)
		case "/v1/projects/p-1/namespaces":
			t.Fatalf("unexpected namespace list without /api prefix: %s", r.URL.Path)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL+"/api")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, bin, "project", "namespace", "list", "--json")
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

	if !strings.Contains(string(out), "myteam.aweb.ai") {
		t.Fatalf("expected myteam.aweb.ai in output:\n%s", string(out))
	}
}

func TestAwNamespaceListTextOutput(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case "/api/v1/projects/p-1/namespaces":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"full_name":               "myteam.aweb.ai",
					"is_external":             false,
					"registration_status":     "registered",
					"assigned_identity_count": 3,
				},
				{
					"full_name":               "acme.com",
					"is_external":             true,
					"registration_status":     "unregistered",
					"assigned_identity_count": 0,
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, bin, "project", "namespace", "list")
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

	output := string(out)
	if !strings.Contains(output, "managed") {
		t.Fatalf("expected 'managed' in table:\n%s", output)
	}
	if !strings.Contains(output, "external") {
		t.Fatalf("expected 'external' in table:\n%s", output)
	}
	if !strings.Contains(output, "acme.com") {
		t.Fatalf("expected 'acme.com' in table:\n%s", output)
	}
}

func TestAwNamespaceVerify(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case "/api/v1/projects/p-1/namespaces":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"namespace_id": "ns-1", "full_name": "acme.com"},
			})
		case "/api/v1/projects/p-1/namespaces/ns-1/verify":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"full_name":           "acme.com",
				"dns_status":          "published",
				"registration_status": "registered",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, bin, "project", "namespace", "verify", "acme.com")
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

	output := string(out)
	if !strings.Contains(output, "registered") {
		t.Fatalf("expected 'registered' in output:\n%s", output)
	}
}

func TestAwNamespaceVerifyDNSFailure(t *testing.T) {
	t.Parallel()

	// Test both 400 (wrong TXT content) and 422 (TXT not found) produce
	// guided error output with the expected TXT record.
	for _, code := range []int{400, 422} {
		code := code
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			t.Parallel()

			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/introspect":
					_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
				case "/api/v1/projects/p-1/namespaces":
					_ = json.NewEncoder(w).Encode([]map[string]any{
						{
							"namespace_id":  "ns-1",
							"full_name":     "acme.com",
							"dns_txt_name":  "_awid.acme.com",
							"dns_txt_value": "awid=v1; controller=did:key:z6Mkf; registry=https://api.awid.ai;",
						},
					})
				case "/api/v1/projects/p-1/namespaces/ns-1/verify":
					w.WriteHeader(code)
					_, _ = w.Write([]byte(`{"error":"dns verification failed"}`))
				case "/v1/agents/heartbeat":
					w.WriteHeader(http.StatusOK)
				default:
					t.Fatalf("unexpected path=%s", r.URL.Path)
				}
			}))

			bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			run := exec.CommandContext(ctx, bin, "project", "namespace", "verify", "acme.com")
			run.Env = append(os.Environ(),
				"AW_CONFIG_PATH="+cfgPath,
				"AWEB_URL=",
				"AWEB_API_KEY=",
			)
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("expected error for status %d, got success:\n%s", code, string(out))
			}

			output := string(out)
			if !strings.Contains(output, "_awid.acme.com") {
				t.Fatalf("expected TXT name in error guidance:\n%s", output)
			}
			if !strings.Contains(output, "did:key:z6Mkf") {
				t.Fatalf("expected TXT value in error guidance:\n%s", output)
			}
		})
	}
}

func TestAwNamespaceDelete(t *testing.T) {
	t.Parallel()

	var deletedID string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case r.URL.Path == "/api/v1/projects/p-1/namespaces" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"namespace_id": "ns-1", "full_name": "acme.com"},
			})
		case r.URL.Path == "/api/v1/projects/p-1/namespaces/ns-1" && r.Method == http.MethodDelete:
			deletedID = "ns-1"
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --force skips TTY confirmation.
	run := exec.CommandContext(ctx, bin, "project", "namespace", "delete", "acme.com", "--force")
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

	if deletedID != "ns-1" {
		t.Fatalf("expected ns-1 to be deleted, got %q", deletedID)
	}

	output := strings.TrimSpace(string(out))
	if !strings.Contains(output, "deleted") {
		t.Fatalf("expected 'deleted' in output:\n%s", output)
	}
}

func TestAwNamespaceDeleteNotFound(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case "/api/v1/projects/p-1/namespaces":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, bin, "project", "namespace", "delete", "nonexistent.com", "--force")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "not found") {
		t.Fatalf("expected 'not found' in error:\n%s", string(out))
	}
}

func TestAwNamespaceDeleteRequiresForceInNonTTY(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{"project_id": "p-1"})
		case "/api/v1/projects/p-1/namespaces":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"namespace_id": "ns-1", "full_name": "acme.com"},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	bin, cfgPath, tmp := testNamespaceConfig(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// No --force, stdin is not a TTY (piped from test).
	run := exec.CommandContext(ctx, bin, "project", "namespace", "delete", "acme.com")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--force") {
		t.Fatalf("expected '--force' in error:\n%s", string(out))
	}
}
