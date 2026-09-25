package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func resetAuthCommandGlobals(t *testing.T) {
	t.Helper()
	oldServer, oldJSON, oldTimeout, oldScope := serverFlag, jsonFlag, cliAuthLoginTimeout, cliAuthScopeFlag
	serverFlag = ""
	jsonFlag = false
	cliAuthLoginTimeout = cliAuthDefaultTimeout
	cliAuthScopeFlag = cliAuthScope
	t.Cleanup(func() {
		serverFlag = oldServer
		jsonFlag = oldJSON
		cliAuthLoginTimeout = oldTimeout
		cliAuthScopeFlag = oldScope
	})
}

func authTestCmd(out *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	return cmd
}

func TestAuthLoginUsesDeviceFlowAndStoresHostCredentialsOnly(t *testing.T) {
	resetAuthCommandGlobals(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	var sawDevice, sawToken bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device_authorization":
			if r.Method != http.MethodPost {
				t.Fatalf("device method=%s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			assertAuthForm(t, r.Form, map[string]string{
				"client_id": cliAuthClientID,
				"scope":     cliAuthScope,
				"resource":  serverFlag + "/cli",
			})
			sawDevice = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":               "device-secret",
				"user_code":                 "ABCD-EFGH",
				"verification_uri":          serverFlag + "/oauth/device",
				"verification_uri_complete": serverFlag + "/oauth/device?user_code=ABCD-EFGH",
				"expires_in":                600,
				"interval":                  1,
				"resource":                  serverFlag + "/cli",
				"scope":                     cliAuthScope,
			})
		case "/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			assertAuthForm(t, r.Form, map[string]string{
				"grant_type":  cliAuthDeviceGrant,
				"client_id":   cliAuthClientID,
				"device_code": "device-secret",
				"resource":    serverFlag + "/cli",
			})
			sawToken = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "access-secret",
				"token_type":    "bearer",
				"expires_in":    3600,
				"refresh_token": "refresh-secret",
				"scope":         cliAuthScope,
				"resource":      serverFlag + "/cli",
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	serverFlag = server.URL

	var out bytes.Buffer
	if err := runAuthLogin(context.Background(), authTestCmd(&out)); err != nil {
		t.Fatalf("runAuthLogin: %v", err)
	}
	if !sawDevice || !sawToken {
		t.Fatalf("device=%t token=%t", sawDevice, sawToken)
	}
	stdout := out.String()
	if strings.Contains(stdout, "access-secret") || strings.Contains(stdout, "refresh-secret") || strings.Contains(stdout, "device-secret") {
		t.Fatalf("stdout leaked secret: %q", stdout)
	}
	cfg, ok, err := loadCLIAuthConfig()
	if err != nil || !ok {
		t.Fatalf("load auth config ok=%t err=%v", ok, err)
	}
	if cfg.AccessToken != "access-secret" || cfg.RefreshToken != "refresh-secret" || cfg.Resource != server.URL+"/cli" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	path, err := cliAuthConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("auth config permissions=%o, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(home + "/.aw/auth.json"); !os.IsNotExist(err) {
		t.Fatalf("auth config must not be written to identity/workspace home, err=%v", err)
	}
}

func TestAuthLoginRejectsTokenResponseWrongResourceOrScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resource string
		scope    string
		wantErr  string
	}{
		{name: "wrong resource", resource: "https://mcp.example.invalid", scope: cliAuthScope, wantErr: "does not match CLI resource"},
		{name: "wrong scope", resource: "", scope: "mcp.connector", wantErr: "does not match CLI scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetAuthCommandGlobals(t)
			t.Setenv("HOME", t.TempDir())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/device_authorization":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"device_code":               "device-secret",
						"user_code":                 "ABCD-EFGH",
						"verification_uri":          serverFlag + "/oauth/device",
						"verification_uri_complete": serverFlag + "/oauth/device?user_code=ABCD-EFGH",
						"expires_in":                600,
						"interval":                  1,
					})
				case "/oauth/token":
					resource := serverFlag + "/cli"
					if tc.resource != "" {
						resource = tc.resource
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token":  "access-secret",
						"token_type":    "bearer",
						"expires_in":    3600,
						"refresh_token": "refresh-secret",
						"scope":         tc.scope,
						"resource":      resource,
					})
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			serverFlag = server.URL
			var out bytes.Buffer
			err := runAuthLogin(context.Background(), authTestCmd(&out))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v, want %q", err, tc.wantErr)
			}
			if _, ok, err := loadCLIAuthConfig(); err != nil || ok {
				t.Fatalf("auth config ok=%t err=%v, want no persisted credentials", ok, err)
			}
		})
	}
}

func TestAuthStatusRefreshesWithoutPrintingTokens(t *testing.T) {
	resetAuthCommandGlobals(t)
	t.Setenv("HOME", t.TempDir())
	var gotStatusAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			assertAuthForm(t, r.Form, map[string]string{
				"grant_type":    "refresh_token",
				"client_id":     cliAuthClientID,
				"refresh_token": "old-refresh",
				"resource":      serverFlag + "/cli",
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "new-access",
				"token_type":    "bearer",
				"expires_in":    3600,
				"refresh_token": "new-refresh",
				"scope":         cliAuthScope,
				"resource":      serverFlag + "/cli",
			})
		case "/api/v1/cli-auth/status":
			gotStatusAuth = r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	serverFlag = server.URL
	if err := saveCLIAuthConfig(cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(-time.Hour), UpdatedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runAuthStatus(context.Background(), authTestCmd(&out)); err != nil {
		t.Fatalf("runAuthStatus: %v", err)
	}
	if gotStatusAuth != "Bearer new-access" {
		t.Fatalf("status auth=%q", gotStatusAuth)
	}
	stdout := out.String()
	if !strings.Contains(stdout, "status: authorized") {
		t.Fatalf("stdout=%q", stdout)
	}
	if strings.Contains(stdout, "new-access") || strings.Contains(stdout, "new-refresh") || strings.Contains(stdout, "old-refresh") {
		t.Fatalf("stdout leaked token: %q", stdout)
	}
	cfg, _, err := loadCLIAuthConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessToken != "new-access" || cfg.RefreshToken != "new-refresh" {
		t.Fatalf("refresh not persisted atomically: %+v", cfg)
	}
}

func TestAuthStatusRejectsRefreshTokenResponseWrongResourceOrScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resource string
		scope    string
		wantErr  string
	}{
		{name: "wrong resource", resource: "https://mcp.example.invalid", scope: cliAuthScope, wantErr: "does not match CLI resource"},
		{name: "wrong scope", resource: "", scope: "mcp.connector", wantErr: "does not match CLI scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetAuthCommandGlobals(t)
			t.Setenv("HOME", t.TempDir())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oauth/token" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				resource := serverFlag + "/cli"
				if tc.resource != "" {
					resource = tc.resource
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "new-access",
					"token_type":    "bearer",
					"expires_in":    3600,
					"refresh_token": "new-refresh",
					"scope":         tc.scope,
					"resource":      resource,
				})
			}))
			defer server.Close()
			serverFlag = server.URL
			old := cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(-time.Hour), UpdatedAt: time.Now().Add(-time.Hour)}
			if err := saveCLIAuthConfig(old); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := runAuthStatus(context.Background(), authTestCmd(&out))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v, want %q", err, tc.wantErr)
			}
			cfg, ok, err := loadCLIAuthConfig()
			if err != nil || !ok {
				t.Fatalf("load config ok=%t err=%v", ok, err)
			}
			if cfg.AccessToken != "old-access" || cfg.RefreshToken != "old-refresh" {
				t.Fatalf("wrong-audience refresh must not be persisted: %+v", cfg)
			}
		})
	}
}

func TestAuthLogoutReportsRevocationFailureAndRetainsCredentials(t *testing.T) {
	resetAuthCommandGlobals(t)
	t.Setenv("HOME", t.TempDir())
	var revoked []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		revoked = append(revoked, r.Form.Get("token_type_hint")+":"+r.Form.Get("token"))
		mu.Unlock()
		if r.Form.Get("token_type_hint") == "refresh_token" {
			http.Error(w, `{"error":"temporarily_unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := saveCLIAuthConfig(cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "access-secret", RefreshToken: "refresh-secret", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runAuthLogout(context.Background(), authTestCmd(&out))
	if err == nil || !strings.Contains(err.Error(), "server revocation failed") {
		t.Fatalf("err=%v, want revocation failure", err)
	}
	if strings.Contains(err.Error(), "access-secret") || strings.Contains(err.Error(), "refresh-secret") {
		t.Fatalf("error leaked token: %v", err)
	}
	cfg, ok, err := loadCLIAuthConfig()
	if err != nil || !ok {
		t.Fatalf("config not retained ok=%t err=%v", ok, err)
	}
	if cfg.RefreshToken != "refresh-secret" || cfg.AccessToken != "access-secret" {
		t.Fatalf("unexpected retained config: %+v", cfg)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(revoked) != 2 {
		t.Fatalf("revoked=%v", revoked)
	}
}

func assertAuthForm(t *testing.T, form url.Values, want map[string]string) {
	t.Helper()
	for key, value := range want {
		if got := form.Get(key); got != value {
			t.Fatalf("form[%s]=%q want %q (full form %v)", key, got, value, form)
		}
	}
}

func TestAuthScopesAreStoredSeparately(t *testing.T) {
	resetAuthCommandGlobals(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cliAuthScopeFlag = cliAuthScopeTeamAdmission
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device_authorization":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			assertAuthForm(t, r.Form, map[string]string{"client_id": cliAuthClientID, "scope": cliAuthScopeTeamAdmission, "resource": serverFlag + "/cli"})
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "device-secret", "user_code": "ABCD-EFGH", "verification_uri": serverFlag + "/oauth/device", "expires_in": 600, "interval": 1, "resource": serverFlag + "/cli", "scope": cliAuthScopeTeamAdmission})
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "team-access", "token_type": "bearer", "expires_in": 3600, "refresh_token": "team-refresh", "scope": cliAuthScopeTeamAdmission, "resource": serverFlag + "/cli"})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	serverFlag = server.URL
	if err := saveCLIAuthConfig(cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "personal-access", RefreshToken: "personal-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runAuthLogin(context.Background(), authTestCmd(&out)); err != nil {
		t.Fatalf("runAuthLogin: %v", err)
	}
	personal, ok, err := loadCLIAuthConfigForScope(cliAuthScope)
	if err != nil || !ok {
		t.Fatalf("load personal ok=%t err=%v", ok, err)
	}
	team, ok, err := loadCLIAuthConfigForScope(cliAuthScopeTeamAdmission)
	if err != nil || !ok {
		t.Fatalf("load team ok=%t err=%v", ok, err)
	}
	if personal.AccessToken != "personal-access" || personal.Scope != cliAuthScope {
		t.Fatalf("personal credentials overwritten: %+v", personal)
	}
	if team.AccessToken != "team-access" || team.Scope != cliAuthScopeTeamAdmission {
		t.Fatalf("team credentials not stored separately: %+v", team)
	}
	personalPath, err := cliAuthConfigPathForScope(cliAuthScope)
	if err != nil {
		t.Fatal(err)
	}
	teamPath, err := cliAuthConfigPathForScope(cliAuthScopeTeamAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if personalPath == teamPath {
		t.Fatalf("scoped auth paths are not isolated: %s", personalPath)
	}
}
