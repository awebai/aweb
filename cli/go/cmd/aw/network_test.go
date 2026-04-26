package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func writeNetworkWorkspace(t *testing.T, workingDir, serverURL, handle, namespace string) string {
	t.Helper()
	if strings.TrimSpace(namespace) == "" {
		namespace = "demo"
	}
	return writeWorkspaceBindingForTest(t, workingDir, workspaceBinding(serverURL, "backend:"+namespace, handle, "workspace-1"))
}

func TestResolveClientSelectionEventStreamFallsBackFromStaleBaseURL(t *testing.T) {
	var pathsMu sync.Mutex
	var paths []string

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &httptest.Server{
		Listener: l,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pathsMu.Lock()
			paths = append(paths, r.URL.Path)
			pathsMu.Unlock()

			switch r.URL.Path {
			case "/v1/events/stream":
				http.NotFound(w, r)
			case "/v1/agents/heartbeat":
				http.NotFound(w, r)
			case "/api/v1/agents/heartbeat":
				w.WriteHeader(http.StatusOK)
			case "/api/v1/events/stream":
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("event: connected\ndata: {\"agent_id\":\"ag_123\",\"team_id\":\"backend:demo\"}\n\n"))
			default:
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
		})},
	}
	server.Start()
	t.Cleanup(server.Close)

	tmp := t.TempDir()
	workspacePath := writeNetworkWorkspace(t, tmp, server.URL, "", "")

	t.Setenv("HOME", tmp)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AWEB_URL", "")

	client, _, err := resolveClientSelectionForDir(tmp)
	if err != nil {
		t.Fatalf("resolveClientSelectionForDir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.EventStream(ctx, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("EventStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	event, err := stream.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if event.Type != "connected" {
		t.Fatalf("event=%#v", event)
	}

	cfgData, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfgData), "aweb_url: "+server.URL+"/api") {
		t.Fatalf("expected workspace binding to persist recovered /api URL under aweb_url, got:\n%s", string(cfgData))
	}

	pathsMu.Lock()
	gotPaths := append([]string(nil), paths...)
	pathsMu.Unlock()
	want := []string{
		"/v1/events/stream",
		"/v1/agents/heartbeat",
		"/api/v1/agents/heartbeat",
		"/api/v1/events/stream",
	}
	if len(gotPaths) != len(want) {
		t.Fatalf("paths=%v", gotPaths)
	}
	for i := range want {
		if gotPaths[i] != want[i] {
			t.Fatalf("paths=%v", gotPaths)
		}
	}
}

func TestResolveWorkingBaseURLContextHonorsCancellation(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		http.NotFound(w, r)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := resolveWorkingBaseURLContext(ctx, server.URL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("expected prompt cancellation, took %s", time.Since(start))
	}
}

func TestMailSendToAddressUsesUnifiedEndpoint(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/messages":
			gotPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":   "net-msg-1",
				"status":       "sent",
				"delivered_at": "2026-02-06T00:00:00Z",
			})
		case "/api/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Address not found"}`))
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     server.URL + "/api",
		TeamID:      "backend:demo",
		Alias:       "eve",
		WorkspaceID: "workspace-1",
		DID:         did,
		StableID:    awid.ComputeStableID(pub),
		Address:     "demo/eve",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		SigningKey:  priv,
	})
	writeKnownAgentPinForTest(t, tmp, "acme/researcher", registryServer.URL)

	run := exec.CommandContext(ctx, bin, "mail", "send", "--to-address", "acme/researcher", "--body", "hello network", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/api/v1/messages" {
		t.Fatalf("path=%s", gotPath)
	}
	if gotBody["to_address"] != "acme/researcher" {
		t.Fatalf("to_address=%v", gotBody["to_address"])
	}
	if gotBody["body"] != "hello network" {
		t.Fatalf("body=%v", gotBody["body"])
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["message_id"] != "net-msg-1" {
		t.Fatalf("message_id=%v", got["message_id"])
	}
}

func TestMailSendToFlagAutoDetectsFullAddress(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/messages":
			gotPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":   "auto-msg-1",
				"status":       "sent",
				"delivered_at": "2026-02-06T00:00:00Z",
			})
		case "/api/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Address not found"}`))
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     server.URL + "/api",
		TeamID:      "backend:demo",
		Alias:       "eve",
		WorkspaceID: "workspace-1",
		DID:         did,
		StableID:    awid.ComputeStableID(pub),
		Address:     "demo/eve",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		SigningKey:  priv,
	})
	writeKnownAgentPinForTest(t, tmp, "acme/researcher", registryServer.URL)

	// Use --to with a full address (contains /). Should auto-detect as address
	// and route to the identity messaging endpoint, not the team-scoped alias endpoint.
	run := exec.CommandContext(ctx, bin, "mail", "send", "--to", "acme/researcher", "--body", "hello auto-detect", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/api/v1/messages" {
		t.Fatalf("path=%s, want /api/v1/messages (identity endpoint)", gotPath)
	}
	if gotBody["to_address"] != "acme/researcher" {
		t.Fatalf("to_address=%v, want acme/researcher", gotBody["to_address"])
	}
	if gotBody["to_alias"] != nil {
		t.Fatalf("to_alias should be absent for address target, got %v", gotBody["to_alias"])
	}
}

func TestMailSendPlainAliasRoutesToOSSEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			gotPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":   "oss-msg-1",
				"status":       "sent",
				"delivered_at": "2026-02-06T00:00:00Z",
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "mail", "send", "--to", "bob", "--body", "hello local", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/v1/messages" {
		t.Fatalf("path=%s", gotPath)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["message_id"] != "oss-msg-1" {
		t.Fatalf("message_id=%v", got["message_id"])
	}
}

func TestChatSendNetworkAddressUsesUnifiedEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/chat/sessions":
			gotPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":        "net-sess-1",
				"message_id":        "net-msg-1",
				"participants":      []map[string]string{{"agent_id": "a1", "alias": "me"}, {"agent_id": "a2", "alias": "acme/bot"}},
				"targets_connected": []string{},
				"targets_left":      []string{},
			})
		case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	writeNetworkWorkspace(t, tmp, server.URL+"/api", "eve", "acme")

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "acme/bot", "hello network", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/api/v1/chat/sessions" {
		t.Fatalf("path=%s", gotPath)
	}
	addrs, ok := gotBody["to_addresses"].([]any)
	if !ok || len(addrs) != 1 || addrs[0] != "acme/bot" {
		t.Fatalf("to_addresses=%v", gotBody["to_addresses"])
	}
	if aliases, ok := gotBody["to_aliases"].([]any); ok && len(aliases) != 0 {
		t.Fatalf("to_aliases=%v, want empty", gotBody["to_aliases"])
	}
	if gotBody["message"] != "hello network" {
		t.Fatalf("message=%v", gotBody["message"])
	}
	if gotBody["leaving"] != true {
		t.Fatalf("leaving=%v", gotBody["leaving"])
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["session_id"] != "net-sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}
}

func TestChatSendNetworkTarget404ShowsAgentNotFound(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/chat/sessions":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"detail": "Target not found",
			})
		case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	writeNetworkWorkspace(t, tmp, server.URL+"/api", "eve", "acme")

	run := exec.CommandContext(ctx, bin, "chat", "send-and-wait", "--start-conversation", "aweb/merlin", "hello")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success: %s", out)
	}
	output := string(out)
	if !strings.Contains(output, "aweb/merlin") {
		t.Fatalf("error should mention target address, got: %s", output)
	}
	if !strings.Contains(strings.ToLower(output), "not found") {
		t.Fatalf("error should say not found, got: %s", output)
	}
}

func TestMailSendNetworkTarget404ShowsAgentNotFound(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/messages":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"detail": "Target not found",
			})
		case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL+"/api")

	run := exec.CommandContext(ctx, bin, "mail", "send", "--to", "aweb/merlin", "--body", "hello", "--subject", "test")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success: %s", out)
	}
	output := string(out)
	if !strings.Contains(output, "aweb/merlin") {
		t.Fatalf("error should mention target address, got: %s", output)
	}
	if !strings.Contains(strings.ToLower(output), "not found") {
		t.Fatalf("error should say not found, got: %s", output)
	}
}

func TestDirectorySearch(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/network/directory":
			if r.URL.Query().Get("capability") != "translate" {
				t.Fatalf("capability=%s", r.URL.Query().Get("capability"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agents": []map[string]any{{
					"org_slug":     "acme",
					"org_name":     "Acme Corp",
					"alias":        "translator",
					"capabilities": []string{"translate"},
					"description":  "Translates things",
				}},
				"total": 1,
			})
		case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL+"/api")

	run := exec.CommandContext(ctx, bin, "directory", "--capability", "translate", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["total"] != float64(1) {
		t.Fatalf("total=%v", got["total"])
	}
	agents := got["agents"].([]any)
	first := agents[0].(map[string]any)
	if first["alias"] != "translator" {
		t.Fatalf("alias=%v", first["alias"])
	}
}

func TestDirectoryGetByAddress(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/network/directory/acme/researcher":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_slug":     "acme",
				"org_name":     "Acme Corp",
				"alias":        "researcher",
				"capabilities": []string{"research"},
				"description":  "Research agent",
			})
		case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL+"/api")

	run := exec.CommandContext(ctx, bin, "directory", "acme/researcher", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["alias"] != "researcher" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if got["org_slug"] != "acme" {
		t.Fatalf("org_slug=%v", got["org_slug"])
	}
}
