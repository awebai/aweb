package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrgScopeBundleKeepsLegacyWorkspaceAuthority(t *testing.T) {
	for _, scope := range []string{"cli.workspace_team", "cli.org_create cli.workspace_team"} {
		cfg := cliAuthConfig{Issuer: "https://service.example", Resource: "https://service.example/cli", Scope: scope}
		if err := validateStoredCLIAuthAudience(cfg, "cli.workspace_team"); err != nil {
			t.Errorf("workspace scope membership rejected: %v", err)
		}
	}
	token := &cliTokenResponse{AccessToken: "test-only", RefreshToken: "test-only", Scope: "cli.org_create cli.workspace_team"}
	if err := validateCLIAuthTokenResponse(token, "https://service.example/cli", "cli.workspace_team cli.org_create"); err != nil {
		t.Errorf("equivalent scope sets rejected: %v", err)
	}
	token.Scope = "cli.workspace_team"
	if err := validateCLIAuthTokenResponse(token, "https://service.example/cli", "cli.workspace_team cli.org_create"); err == nil {
		t.Error("login accepted a response missing the requested org scope")
	}
}

func TestOrgCommandsUseOnlyHostHumanAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		name     string
		args     []string
		path     string
		status   int
		response any
		wantKey  string
		want     any
		failed   bool
	}{
		{"create", []string{"org", "create", "machine", "--name", "Machine"}, "/api/v1/cli/organizations", 201, map[string]any{"id": "org-1", "slug": "machine", "name": "Machine", "namespace": "machine.aweb.ai"}, "slug", "machine", false},
		{"replay", []string{"org", "create", "machine"}, "/api/v1/cli/organizations", 200, map[string]any{"id": "org-1", "slug": "machine", "name": "Machine", "namespace": "machine.aweb.ai"}, "id", "org-1", false},
		{"list", []string{"org", "list"}, "/api/v1/cli/organizations", 200, map[string]any{"organizations": []any{}}, "organizations", nil, false},
		{"availability", []string{"org", "availability", "machine"}, "/api/v1/cli/organizations/availability", 200, map[string]any{"available": false, "suggestion": "machine-abcd"}, "suggestion", "machine-abcd", false},
		{"collision", []string{"org", "create", "machine"}, "/api/v1/cli/organizations", 409, map[string]any{"code": "org_slug_taken", "suggestion": "machine-abcd"}, "suggestion", "machine-abcd", true},
		{"relogin", []string{"org", "list"}, "/api/v1/cli/organizations", 403, map[string]any{"detail": map[string]any{"code": "cli_auth_relogin_required", "message": "This CLI authorization does not include cli.org_create; run aw auth login again."}}, "code", "cli_auth_relogin_required", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := t.TempDir()
			wd := t.TempDir()
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				t.Fatal(err)
			}
			access := hex.EncodeToString(raw)
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveUnadvertisedHealth(w, r) {
					return
				}
				if r.Header.Get("Authorization") != "Bearer "+access {
					t.Error("request did not use the selected host token")
				}
				if r.URL.Path == "/api/v1/cli-auth/status" {
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "scope": "cli.org_create cli.workspace_team", "account": map[string]any{"id": "acct-1", "handle": "alice"}})
					return
				}
				if r.URL.Path != tc.path {
					t.Errorf("unexpected endpoint %s", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				calls++
				if tc.name == "availability" && r.URL.Query().Get("slug") != "machine" {
					t.Error("availability lost the exact slug")
				}
				if r.Method == http.MethodPost {
					var request map[string]any
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
					}
					if request["slug"] != "machine" {
						t.Error("create changed the requested slug")
					}
					if tc.name == "create" && request["name"] != "Machine" {
						t.Error("create lost the display name")
					}
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(tc.response)
			}))
			defer server.Close()
			cfg := cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", ClientID: cliAuthClientID, Scope: "cli.workspace_team cli.org_create", AccessToken: access, RefreshToken: access, ExpiresAt: time.Now().Add(time.Hour)}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(host, ".config", "aw")
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "auth.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, tc.args...), "--json")
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir = wd
			cmd.Env = append(os.Environ(), "HOME="+host, "AW_NO_UPDATE_CHECK=1", "AWEB_API_KEY=", "AWEB_IDENTITY_HOME=", "AW_IDENTITY_HOME=")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err = cmd.Run()
			if (err != nil) != tc.failed {
				t.Fatalf("exit=%v; stderr=%s", err, stderr.String())
			}
			var result map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("result is not JSON: %v; stderr=%s", err, stderr.String())
			}
			if _, ok := result[tc.wantKey]; !ok {
				t.Errorf("result lacks %s", tc.wantKey)
			}
			if tc.want != nil && result[tc.wantKey] != tc.want {
				t.Errorf("incorrect %s", tc.wantKey)
			}
			if calls != 1 {
				t.Errorf("API calls=%d, want 1 without mutation retry", calls)
			}
			if strings.Contains(stdout.String()+stderr.String(), access) {
				t.Error("credential leaked in command output")
			}
			if _, err := os.Stat(filepath.Join(wd, ".aw")); !os.IsNotExist(err) {
				t.Error("org command wrote identity state")
			}
		})
	}
}
