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
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func writeNetworkWorkspace(t *testing.T, workingDir, serverURL, handle, namespace string) string {
	t.Helper()
	if strings.TrimSpace(namespace) == "" {
		namespace = "demo"
	}
	state := workspaceBinding(serverURL, "backend:"+namespace, handle, "workspace-1")
	activeMembership := activeMembershipForTest(t, &state)
	writeTeamCertificateWorkspaceForTest(t, workingDir, state, &testSelectionFixture{
		TeamID:        activeMembership.TeamID,
		Alias:         activeMembership.Alias,
		WorkspaceID:   activeMembership.WorkspaceID,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     "2026-04-04T00:00:00Z",
	})
	return writeWorkspaceBindingForTest(t, workingDir, state)
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
		case "/api/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
		case "/api/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
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

	buildAwBinary(t, ctx, bin)

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:       server.URL + "/api",
		TeamID:        "backend:demo",
		Alias:         "eve",
		WorkspaceID:   "workspace-1",
		DID:           did,
		StableID:      awid.ComputeStableID(pub),
		Address:       "demo/eve",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   registryServer.URL,
		SigningKey:    priv,
	})
	writeKnownAgentPinForTest(t, tmp, "acme.example/researcher", registryServer.URL)

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext", "--to-address", "acme.example/researcher", "--body", "hello network", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/api/v1/messages" {
		t.Fatalf("path=%s", gotPath)
	}
	if gotBody["to_address"] != "acme.example/researcher" {
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
		case "/api/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
		case "/api/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
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

	buildAwBinary(t, ctx, bin)

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:       server.URL + "/api",
		TeamID:        "backend:demo",
		Alias:         "eve",
		WorkspaceID:   "workspace-1",
		DID:           did,
		StableID:      awid.ComputeStableID(pub),
		Address:       "demo/eve",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   registryServer.URL,
		SigningKey:    priv,
	})
	writeKnownAgentPinForTest(t, tmp, "acme.example/researcher", registryServer.URL)

	// Use --to with a full address (contains /). Should auto-detect as address
	// and route to the identity messaging endpoint, not the team-scoped alias endpoint.
	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext", "--to", "acme.example/researcher", "--body", "hello auto-detect", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/api/v1/messages" {
		t.Fatalf("path=%s, want /api/v1/messages (identity endpoint)", gotPath)
	}
	if gotBody["to_address"] != "acme.example/researcher" {
		t.Fatalf("to_address=%v, want acme.example/researcher", gotBody["to_address"])
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
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{Agents: []awid.AgentView{}})
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

	buildAwBinary(t, ctx, bin)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext", "--to", "bob", "--body", "hello local", "--json")
	run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL=http://127.0.0.1:1")
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
		case "/api/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		case "/api/v1/chat/sessions":
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{}})
				return
			}
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

	buildAwBinary(t, ctx, bin)

	writeNetworkWorkspace(t, tmp, server.URL+"/api", "eve", "acme")

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "--plaintext", "acme/bot", "hello network", "--json")
	run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL=http://127.0.0.1:1")
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
		case "/api/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		case "/api/v1/chat/sessions":
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{}})
				return
			}
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

	buildAwBinary(t, ctx, bin)

	writeNetworkWorkspace(t, tmp, server.URL+"/api", "eve", "acme")

	run := exec.CommandContext(ctx, bin, "chat", "send-and-wait", "--plaintext", "--start-conversation", "aweb.example/merlin", "hello")
	run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL=http://127.0.0.1:1")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success: %s", out)
	}
	output := string(out)
	if !strings.Contains(output, "aweb.example/merlin") {
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
		case "/v1/namespaces/aweb/addresses/merlin":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Target not found"})
		case "/api/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
		case "/api/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		case "/api/v1/messages":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"detail": "Target not found",
			})
		case "/api/v1/agents":
			// AWID has no aweb/merlin, so the sender's own team is asked next;
			// merlin is not on it either.
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "backend:aweb", Agents: []awid.AgentView{}})
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

	buildAwBinary(t, ctx, bin)

	// Pin resolution to the disposable registry as well as the service.
	writeNetworkWorkspace(t, tmp, server.URL+"/api", "eve", "aweb")

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext", "--to", "aweb/merlin", "--body", "hello", "--subject", "test")
	run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL, "HTTPS_PROXY=http://127.0.0.1:1", "HTTP_PROXY=http://127.0.0.1:1", "NO_PROXY=127.0.0.1,localhost")
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

// The server's typed recipient refusals reach the person as plain text,
// keyed on the stable reason; any other 404 keeps the generic text.
func TestNetworkErrorMapsTypedRecipientRefusals(t *testing.T) {
	t.Parallel()
	typed := func(reason string) error {
		return &awid.APIError{StatusCode: http.StatusNotFound, Body: `{"detail":"` + reason + `","reason":"` + reason + `","retryable":false,"correlation_id":"5836a664-515f-4ce7-a53e-def8406fa5f2"}`}
	}
	for _, tc := range []struct {
		name, target string
		err          error
		want         string
	}{
		{"typo in the team", "local/bbo", typed("recipient_identity_not_found"),
			"local/bbo is not a member of your team or a registered address. Check the name with `aw workspace status`."},
		{"local identity in another team", "acme.test/grace", typed("local_recipient_route_missing"),
			awid.UnreachableAddressText("acme.test/grace")},
		{"other 404", "aweb/merlin", &awid.APIError{StatusCode: http.StatusNotFound, Body: `{"detail":"Target not found"}`},
			"agent not found: aweb/merlin"},
	} {
		if got := networkError(tc.err, tc.target); got == nil || got.Error() != tc.want {
			t.Fatalf("%s: got %v, want %q", tc.name, got, tc.want)
		}
	}
}

// Plain mail to an address the server refuses with a typed reason prints the
// mapped text after one POST, with no retry and no raw body.
func TestMailSendToAddressPrintsTheTypedRefusal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ target, reason, want string }{
		{"local/bbo", "recipient_identity_not_found", "local/bbo is not a member of your team or a registered address."},
		{"acme.test/grace", "local_recipient_route_missing", "acme.test/grace has no registered address. A local identity has no address and is reachable only from inside its own team, by alias"},
	} {
		var posts atomic.Int32
		server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/conversations":
				_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
			case "/api/v1/messages/inbox":
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
			case "/api/v1/messages":
				posts.Add(1)
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": tc.reason, "reason": tc.reason, "retryable": false, "correlation_id": "0b780fbf-f248-4a15-89c1-25dbbd719cd1"})
			case "/api/v1/agents/heartbeat":
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		tmp := t.TempDir()
		bin := filepath.Join(tmp, "aw")
		buildAwBinary(t, ctx, bin)
		writeNetworkWorkspace(t, tmp, server.URL+"/api", "alice", "local")
		run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext", "--to-address", tc.target, "--body", "hi", "--subject", "hi")
		run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL, "HTTPS_PROXY=http://127.0.0.1:1", "HTTP_PROXY=http://127.0.0.1:1", "NO_PROXY=127.0.0.1,localhost")
		run.Dir = tmp
		out, err := run.CombinedOutput()
		cancel()
		if err == nil {
			t.Fatalf("%s: expected error, got success: %s", tc.target, out)
		}
		output := string(out)
		if !strings.Contains(output, tc.want) || strings.Contains(output, tc.reason) || strings.Contains(output, "agent not found") {
			t.Fatalf("%s: want %q without the raw reason, got:\n%s", tc.target, tc.want, output)
		}
		if n := posts.Load(); n != 1 {
			t.Fatalf("%s: %d POSTs, want 1", tc.target, n)
		}
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

	buildAwBinary(t, ctx, bin)

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

	buildAwBinary(t, ctx, bin)

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
