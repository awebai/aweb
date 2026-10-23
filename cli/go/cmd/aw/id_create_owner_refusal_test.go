package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestOwnerPrincipalHostedIdentityRejectsUnavailableAuthorityBeforeNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, kind := range []string{"missing-key", "grant", "no-binding", "same-root", "relative-root", "without-org"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
			defer server.Close()
			ownerParent, host, wd := t.TempDir(), t.TempDir(), t.TempDir()
			writeDefaultWorkspaceBindingForTest(t, ownerParent, server.URL+"/api")
			owner, err := filepath.EvalSymlinks(filepath.Join(ownerParent, ".aw"))
			if err != nil {
				t.Fatal(err)
			}
			target, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing-key":
				if err := os.Remove(filepath.Join(owner, "signing.key")); err != nil {
					t.Fatal(err)
				}
			case "grant":
				if err := os.WriteFile(filepath.Join(owner, "grant.yaml"), []byte("version: 1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "no-binding":
				if err := os.Remove(filepath.Join(owner, "workspace.yaml")); err != nil {
					t.Fatal(err)
				}
			case "same-root":
				target = owner
			}
			keyBefore, _ := os.ReadFile(filepath.Join(owner, "signing.key"))
			bindingBefore, _ := os.ReadFile(filepath.Join(owner, "workspace.yaml"))
			cfg := cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", ClientID: cliAuthClientID, Scope: cliAuthDefaultScopes, AccessToken: "test-unused-human", ExpiresAt: time.Now().Add(time.Hour)}
			encoded, _ := json.Marshal(cfg)
			dir := filepath.Join(host, ".config", "aw")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "auth.json"), encoded, 0600); err != nil {
				t.Fatal(err)
			}
			selected := owner
			if kind == "relative-root" {
				selected = ".aw"
			}
			args := []string{"--identity-home", target, "id", "create", "--owner-identity-home", selected, "--team-id", "786a02e4-6a72-44f1-a722-bef232c49a97", "--name", "steward", "--inbound-mode", "contacts-only", "--json"}
			if kind != "without-org" {
				args = append(args, "--org", "chosen")
			}
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir = wd
			cmd.Env = append(os.Environ(), "HOME="+host, "AWEB_IDENTITY_HOME=", "AW_IDENTITY_HOME=", "AWEB_API_KEY=test-unused-api-key", "AW_NO_UPDATE_CHECK=1")
			if err := cmd.Run(); err == nil {
				t.Fatal("unavailable authority completed creation")
			}
			if requests.Load() != 0 {
				t.Error("authority refusal contacted the service or borrowed human auth")
			}
			if _, err := os.Stat(filepath.Join(target, "hosted-identity-create.json")); !os.IsNotExist(err) {
				t.Error("authority refusal created recovery signing material")
			}
			keyAfter, _ := os.ReadFile(filepath.Join(owner, "signing.key"))
			bindingAfter, _ := os.ReadFile(filepath.Join(owner, "workspace.yaml"))
			if !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(bindingBefore, bindingAfter) {
				t.Error("authority refusal modified the owner root")
			}
		})
	}
}
