package main

import (
	"context"
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
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
		case r.URL.Path == "/v1/agents/resolve/alice" && r.Method == http.MethodGet:
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
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_ephemeral",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "myco",
		ProjectSlug:    "myco",
	})
	ps := awid.NewPinStore()
	ps.StorePin("did:key:canonical", "myco/alice", "", "")
	ps.StorePin("did:key:handle", "alice", "", "")
	legacyKnownAgentsPath := filepath.Join(tmp, "known_agents.yaml")
	knownAgentsPath := filepath.Join(tmp, ".config", "aw", "known_agents.yaml")
	if err := ps.Save(legacyKnownAgentsPath); err != nil {
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

	run := exec.CommandContext(ctx, bin, "id", "delete", "--confirm")
	run.Env = testCommandEnv(tmp)
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
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "context")); !os.IsNotExist(err) {
		t.Fatalf("expected .aw/context removal, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "workspace.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected .aw/workspace.yaml removal, err=%v", err)
	}
	pins, err := awid.LoadPinStore(knownAgentsPath)
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
		case r.URL.Path == "/v1/agents/resolve/alice" && r.Method == http.MethodGet:
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
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_permanent",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "myco",
		ProjectSlug:    "myco",
	})

	run := exec.CommandContext(ctx, bin, "id", "delete", "--confirm")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "permanent archival and replacement are owner-admin lifecycle flows") {
		t.Fatalf("expected permanent-identity guidance, got: %s", string(out))
	}
}
