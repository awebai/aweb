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
)

func TestAwLockMutationUnsupportedMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		path       string
		statusCode int
	}{
		{name: "acquire", args: []string{"lock", "acquire", "--resource-key", "deploy"}, path: "/v1/reservations", statusCode: http.StatusMethodNotAllowed},
		{name: "renew", args: []string{"lock", "renew", "--resource-key", "deploy"}, path: "/v1/reservations/renew", statusCode: http.StatusNotFound},
		{name: "release", args: []string{"lock", "release", "--resource-key", "deploy"}, path: "/v1/reservations/release", statusCode: http.StatusNotFound},
		{name: "revoke", args: []string{"lock", "revoke", "--prefix", "deploy"}, path: "/v1/reservations/revoke", statusCode: http.StatusNotFound},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case tc.path:
					w.WriteHeader(tc.statusCode)
					_ = json.NewEncoder(w).Encode(map[string]any{"detail": "unsupported"})
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
			buildAwBinary(t, ctx, bin)

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

			run := exec.CommandContext(ctx, bin, tc.args...)
			run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("expected error, got success:\n%s", string(out))
			}
			if !strings.Contains(string(out), "only `aw lock list` is currently available") {
				t.Fatalf("unexpected output:\n%s", string(out))
			}
		})
	}
}

func TestAwLockListMineFiltersByCurrentAlias(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reservations": []map[string]any{
					{
						"project_id":      "proj-1",
						"resource_key":    "src/mine.go",
						"holder_agent_id": "11111111-1111-1111-1111-111111111111",
						"holder_alias":    "alice",
						"acquired_at":     "2026-03-10T10:00:00Z",
						"expires_at":      "2099-03-10T10:00:00Z",
						"metadata":        map[string]any{},
					},
					{
						"project_id":      "proj-1",
						"resource_key":    "src/theirs.go",
						"holder_agent_id": "22222222-2222-2222-2222-222222222222",
						"holder_alias":    "bob",
						"acquired_at":     "2026-03-10T10:00:00Z",
						"expires_at":      "2099-03-10T10:00:00Z",
						"metadata":        map[string]any{},
					},
				},
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
	buildAwBinary(t, ctx, bin)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    identity_handle: alice
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "lock", "list", "--mine")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	text := string(out)
	if !strings.Contains(text, "src/mine.go — alice") {
		t.Fatalf("expected own lock in output:\n%s", text)
	}
	if strings.Contains(text, "src/theirs.go") {
		t.Fatalf("expected other lock to be filtered out:\n%s", text)
	}
}
