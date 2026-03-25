package main

import (
	"context"
	"encoding/json"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAwIdentityDeleteEphemeral(t *testing.T) {
	t.Parallel()

	var deregisterCalled atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/introspect" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"agent_id":       "agent-1",
				"alias":          "alice",
				"namespace_slug": "myco",
				"address":        "myco/alice",
			})
		case r.URL.Path == "/v1/agents/resolve/myco/alice" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":   "agent-1",
				"did":        "did:key:z6MkEphemeral",
				"address":    "myco/alice",
				"custody":    "custodial",
				"lifetime":   "ephemeral",
				"public_key": "",
			})
		case r.URL.Path == "/v1/agents/me" && r.Method == http.MethodDelete:
			deregisterCalled.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/agents/heartbeat":
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

	cfg := strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_ephemeral
    identity_id: agent-1
    identity_handle: alice
    namespace_slug: myco
    custody: custodial
    lifetime: ephemeral
default_account: acct
`) + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := awid.NewPinStore()
	ps.StorePin("did:key:canonical", "myco/alice", "", "")
	ps.StorePin("did:key:handle", "alice", "", "")
	if err := ps.Save(filepath.Join(tmp, "known_agents.yaml")); err != nil {
		t.Fatal(err)
	}

	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "context"), []byte(strings.TrimSpace(`
default_account: acct
server_accounts:
  local: acct
client_default_accounts:
  aw: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "delete", "--confirm")
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
	if !deregisterCalled.Load() {
		t.Fatal("expected DELETE /v1/agents/me")
	}
	if !strings.Contains(string(out), "Identity deleted.") {
		t.Fatalf("expected delete output, got: %s", string(out))
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfgOut struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfgOut); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	if len(cfgOut.Accounts) != 0 {
		t.Fatalf("expected account removal after delete:\n%s", string(data))
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "context")); !os.IsNotExist(err) {
		t.Fatalf("expected .aw/context removal, err=%v", err)
	}
	pins, err := awid.LoadPinStore(filepath.Join(tmp, "known_agents.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pins.Addresses["myco/alice"]; ok {
		t.Fatal("expected canonical pin removal after delete")
	}
	if _, ok := pins.Addresses["alice"]; ok {
		t.Fatal("expected handle pin removal after delete")
	}
}

func TestAwIdentityDeleteRejectsPermanent(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/introspect" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"agent_id":       "agent-1",
				"alias":          "alice",
				"namespace_slug": "myco",
				"address":        "myco/alice",
			})
		case r.URL.Path == "/v1/agents/resolve/myco/alice" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "agent-1",
				"did":      "did:key:z6MkPermanent",
				"address":  "myco/alice",
				"custody":  "self",
				"lifetime": "persistent",
			})
		case r.URL.Path == "/v1/agents/heartbeat":
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

	cfg := strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_permanent
    identity_id: agent-1
    identity_handle: alice
    namespace_slug: myco
    custody: custodial
    lifetime: ephemeral
    did: did:key:z6MkWrongLocalState
default_account: acct
`) + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "delete", "--confirm")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "permanent archival and replacement are owner-admin lifecycle flows") {
		t.Fatalf("expected permanent-identity guidance, got: %s", string(out))
	}
}
