package wake

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	awid "github.com/awebai/aw/awid"
)

func TestChannelCoreRunnerReportsMissingSystemNode(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := NewChannelCoreRunner(store)
	t.Setenv("PATH", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	child := runner.StartChild(ctx, Registration{Home: t.TempDir()}, channelCoreChildConfig{AdmissionSize: 1})
	defer child.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := child.Status()
		if strings.Contains(status.LastError, "system Node executable not found") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("status did not report missing node: %#v", child.Status())
}

func TestBundledGrantMailReadOnlyUsesManualAckAndDeliveryStore(t *testing.T) {
	if _, err := os.Stat("channel_core_runner_bundle.mjs"); err != nil {
		t.Skipf("bundle unavailable: %v", err)
	}
	root := t.TempDir()
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	oats := writeFakeOATS(t, root, inputPath)
	var mu sync.Mutex
	acks := 0
	fetches := 0
	fetchAuth := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox":
			fetches++
			fetchAuth = r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{{
				"message_id": "mail-1", "conversation_id": "conv-1", "from_agent_id": "agent-bob", "from_alias": "bob", "subject": "hello", "body": "grant mail", "priority": "normal", "created_at": "2026-01-01T00:00:00Z",
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages/mail-1/ack":
			acks++
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read"})
	reg := Registration{Home: filepath.Join(root, "terminal"), IdentityHome: grantHome, Delivery: DeliverySession}
	if err := os.MkdirAll(reg.Home, 0o700); err != nil {
		t.Fatal(err)
	}

	runner := NewChannelCoreRunner(store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	child := runner.StartChild(ctx, reg, channelCoreChildConfig{OatsBin: oats, AWCommand: writeFakeAW(t, root, ""), Coalesce: time.Millisecond, RateLimit: time.Millisecond, InspectDelay: time.Millisecond})
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running && st.LastError == "" })
	child.Offer(reg.ReceiveBindings()[0], awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-1", ConversationID: "conv-1"})
	waitForFileContains(t, inputPath, "grant mail")
	waitForFileContains(t, filepath.Join(grantHome, "channel-delivered-ids-backend_acme.com.json"), "mail-1")
	child.Stop()

	mu.Lock()
	gotAuth, gotAcks := fetchAuth, acks
	mu.Unlock()
	if !strings.HasPrefix(gotAuth, "AWEB-Grant DIDKey ") {
		t.Fatalf("fetch auth=%q, want grant auth", gotAuth)
	}
	if gotAcks != 0 {
		t.Fatalf("read-only grant mail acked %d times", gotAcks)
	}

	before, _ := os.ReadFile(inputPath)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	child2 := runner.StartChild(ctx2, reg, channelCoreChildConfig{OatsBin: oats, AWCommand: writeFakeAW(t, root, ""), Coalesce: time.Millisecond, RateLimit: time.Millisecond, InspectDelay: time.Millisecond})
	waitForStatus(t, child2, func(st ChannelCoreStatus) bool { return st.Running && st.LastError == "" })
	child2.Offer(reg.ReceiveBindings()[0], awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-1", ConversationID: "conv-1"})
	waitForStatus(t, child2, func(st ChannelCoreStatus) bool {
		return st.TraceStage == "lane_job_completed" && st.TraceMessageID == "mail-1"
	})
	child2.Stop()
	after, _ := os.ReadFile(inputPath)
	if string(after) != string(before) {
		t.Fatalf("delivery store did not suppress restart re-presentation\nbefore=%q\nafter=%q", before, after)
	}
}

func TestBundledReadinessStatusReportsWaitingReason(t *testing.T) {
	if _, err := os.Stat("channel_core_runner_bundle.mjs"); err != nil {
		t.Skipf("bundle unavailable: %v", err)
	}
	root := t.TempDir()
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	failPath := filepath.Join(root, "inspect-fails")
	if err := os.WriteFile(failPath, []byte("fail"), 0o600); err != nil {
		t.Fatal(err)
	}
	oats := writeFailingThenIdleOATS(t, root, inputPath, failPath)
	server := mailServer(t, "ready mail")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	reg := Registration{Home: filepath.Join(root, "terminal"), IdentityHome: grantHome, Delivery: DeliverySession}
	if err := os.MkdirAll(reg.Home, 0o700); err != nil {
		t.Fatal(err)
	}
	child := NewChannelCoreRunner(store).StartChild(context.Background(), reg, channelCoreChildConfig{OatsBin: oats, AWCommand: writeFakeAW(t, root, ""), Coalesce: time.Millisecond, RateLimit: time.Millisecond, InspectDelay: 25 * time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running && st.LastError == "" })
	child.Offer(reg.ReceiveBindings()[0], awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-wait", ConversationID: "conv"})
	waitForStatus(t, child, func(st ChannelCoreStatus) bool {
		return st.TraceStage == "lane_job_started" && st.ReadinessWaiting == "inspect_error" && strings.Contains(st.ReadinessError, "inspect unavailable")
	})
	waitForStatus(t, child, func(st ChannelCoreStatus) bool {
		return st.ReadinessWaiting == "inspect_start" && strings.Contains(st.ReadinessError, "inspect unavailable")
	})
	if err := os.Remove(failPath); err != nil {
		t.Fatal(err)
	}
	waitForFileContains(t, inputPath, "ready mail")
	waitForStatus(t, child, func(st ChannelCoreStatus) bool {
		return st.TraceStage == "lane_job_completed" && st.ReadinessState == "idle" && st.ReadinessError == "" && st.ReadinessWaiting == "ready"
	})
}

func TestChannelCoreRestartReportsExitAndClearsPerRunStatus(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "crashed-once")
	writeFakeNode(t, root, "#!/bin/sh\nif [ ! -f "+shellQuoteForTest(marker)+" ]; then\n  printf '{\"type\":\"status\",\"ready\":true,\"trace_stage\":\"lane_job_started\",\"trace_message_id\":\"dead\",\"readiness_waiting\":\"inspect_start\",\"readiness_error\":\"dead readiness\",\"ambient_queued\":7,\"ambient_dropped\":8}\n'\n  printf 'uncaught Error: write EPIPE\n' >&2\n  printf x > "+shellQuoteForTest(marker)+"\n  exit 42\nfi\nprintf '{\"type\":\"status\",\"ready\":true}\n'\nwhile IFS= read -r line; do :; done\n")
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: filepath.Join(root, "terminal")}, channelCoreChildConfig{})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool {
		return st.Running && st.RestartCount == 1 && strings.Contains(st.LastExit, "exit status 42") && strings.Contains(st.LastExit, "write EPIPE")
	})
	st := child.Status()
	if st.TraceStage != "" || st.TraceMessageID != "" || st.ReadinessWaiting != "" || st.ReadinessError != "" || st.AmbientQueued != 0 || st.AmbientDropped != 0 {
		t.Fatalf("stale per-run status survived restart: %#v", st)
	}
}

func TestBundledGrantChatReadMarksReadWithGrantAuth(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(filepath.Join(root, "state"))
	inputPath := filepath.Join(root, "input.txt")
	oats := writeFakeOATS(t, root, inputPath)
	var mu sync.Mutex
	readAuth := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions/sess-1/messages":
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{{
				"message_id": "chat-1", "conversation_id": "conv-1", "from_agent": "bob", "body": "grant chat", "timestamp": "2026-01-01T00:00:00Z", "sender_leaving": false,
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions/sess-1/read":
			mu.Lock()
			readAuth = r.Header.Get("Authorization")
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "chat.read"})
	reg := Registration{Home: filepath.Join(root, "terminal"), IdentityHome: grantHome, Delivery: DeliverySession}
	_ = os.MkdirAll(reg.Home, 0o700)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), reg, channelCoreChildConfig{OatsBin: oats, AWCommand: writeFakeAW(t, root, ""), Coalesce: time.Millisecond, RateLimit: time.Millisecond, InspectDelay: time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running && st.LastError == "" })
	child.Offer(reg.ReceiveBindings()[0], awid.AgentEvent{Type: awid.AgentEventActionableChat, MessageID: "chat-1", SessionID: "sess-1", ConversationID: "conv-1"})
	waitForFileContains(t, inputPath, "grant chat")
	waitForCond(t, "grant chat markRead", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.HasPrefix(readAuth, "AWEB-Grant DIDKey ")
	})
}

func TestChannelCoreControlBypassesEventEviction(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "stdin.log")
	writeFakeNode(t, root, "#!/bin/sh\nprintf '{\"type\":\"status\",\"ready\":true}\\n'\nwhile IFS= read -r line; do printf '%s\\n' \"$line\" >> "+shellQuoteForTest(logPath)+"; done\n")
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: filepath.Join(root, "terminal")}, channelCoreChildConfig{AdmissionSize: 1})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running })
	for i := 0; i < 100; i++ {
		child.Offer(ReceiveIdentity{IdentityHome: root, TeamID: "team"}, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail"})
	}
	child.Pause(true)
	waitForFileContains(t, logPath, `"type":"pause"`)
}

func TestChannelCorePauseSurvivesChildRestartWithoutNewEvent(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "stdin.log")
	countPath := filepath.Join(root, "count")
	writeFakeNode(t, root, "#!/bin/sh\nn=0; [ -f "+shellQuoteForTest(countPath)+" ] && read -r n < "+shellQuoteForTest(countPath)+"; n=$((n+1)); printf '%s' \"$n\" > "+shellQuoteForTest(countPath)+"\nprintf '{\"type\":\"status\",\"ready\":true}\\n'\nIFS= read -r line || exit 0\nprintf '%s\\n' \"$line\" >> "+shellQuoteForTest(logPath)+"\nif [ \"$n\" -eq 1 ]; then exit 0; fi\nwhile IFS= read -r line; do printf '%s\\n' \"$line\" >> "+shellQuoteForTest(logPath)+"; done\n")
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: filepath.Join(root, "terminal")}, channelCoreChildConfig{})
	defer child.Stop()
	child.Pause(true)
	waitForCond(t, "child restart", func() bool {
		data, _ := os.ReadFile(countPath)
		return strings.TrimSpace(string(data)) == "2"
	})
	waitForCond(t, "paused init after restart", func() bool {
		data, _ := os.ReadFile(logPath)
		return strings.Count(string(data), `"paused":true`) >= 2
	})
}

func TestChannelCoreStatusPreservesBindingErrorsAndZeroQueueCounts(t *testing.T) {
	root := t.TempDir()
	writeFakeNode(t, root, "#!/bin/sh\nprintf '{\"type\":\"status\",\"ambient_queued\":5,\"ambient_dropped\":3,\"binding_id\":\"b1\",\"error\":\"first\"}\\n'\nprintf '{\"type\":\"status\",\"ambient_queued\":0,\"ambient_dropped\":0,\"binding_id\":\"b2\",\"error\":\"second\"}\\n'\nwhile IFS= read -r line; do :; done\n")
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: filepath.Join(root, "terminal")}, channelCoreChildConfig{})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool {
		return st.AmbientQueued == 0 && st.AmbientDropped == 0 && st.BindingErrors["b1"] == "first" && st.BindingErrors["b2"] == "second"
	})
}

func TestChannelCoreBindingErrorClearsOnlyOnCompletedTrace(t *testing.T) {
	reader, writer := io.Pipe()
	child := &ChannelCoreChild{done: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		child.readStatus(reader, make(chan struct{}))
		close(done)
	}()
	writeLine := func(line string) {
		t.Helper()
		if _, err := writer.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	writeLine(`{"type":"status","binding_id":"b1","error":"boom"}`)
	waitForCond(t, "binding error recorded", func() bool { return child.Status().BindingErrors["b1"] == "boom" })
	writeLine(`{"type":"status","binding_id":"b1","trace_stage":"lane_job_started","trace_message_id":"m1"}`)
	time.Sleep(50 * time.Millisecond)
	if got := child.Status().BindingErrors["b1"]; got != "boom" {
		t.Fatalf("lane_job_started cleared error: %q", got)
	}
	writeLine(`{"type":"status","binding_id":"b1","trace_stage":"lane_job_completed","trace_message_id":"m1"}`)
	waitForCond(t, "binding error cleared", func() bool { _, ok := child.Status().BindingErrors["b1"]; return !ok })
	_ = writer.Close()
	<-done
}

func TestBundledEncryptedSecondaryRootUsesBindingIdentityForDecrypt(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(filepath.Join(root, "state"))
	inputPath := filepath.Join(root, "input.txt")
	oats := writeFakeOATS(t, root, inputPath)
	awLog := filepath.Join(root, "aw.log")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{{
			"message_id": "mail-enc", "conversation_id": "conv-1", "from_agent_id": "agent-bob", "from_alias": "bob", "subject": "encrypted", "body": "", "priority": "normal", "created_at": "2026-01-01T00:00:00Z", "content_mode": "encrypted_v2", "message_version": 2, "encrypted_envelope": map[string]any{},
		}}})
	}))
	defer server.Close()
	terminalHome := filepath.Join(root, "terminal")
	secondary := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read"})
	reg := Registration{Home: terminalHome, Delivery: DeliverySession, RuntimeDelivery: RuntimeDeliveryExternalSession, ReceiveIdentities: []ReceiveIdentity{{IdentityHome: secondary, TeamID: "backend:acme.com", DeliveryOwner: ReceiveOwnerSessionHints, Controls: true}}}
	_ = os.MkdirAll(terminalHome, 0o700)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), reg, channelCoreChildConfig{OatsBin: oats, AWCommand: writeFakeAW(t, root, awLog), Coalesce: time.Millisecond, RateLimit: time.Millisecond, InspectDelay: time.Millisecond})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running && st.LastError == "" })
	child.Offer(reg.ReceiveBindings()[0], awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-enc", ConversationID: "conv-1"})
	waitForFileContains(t, inputPath, "decrypted: false")
	if data, _ := os.ReadFile(inputPath); !strings.Contains(string(data), "local aw") {
		t.Fatalf("encrypted failure did not come from local aw decrypt path: %s", data)
	}
	canonicalSecondary, _ := filepath.EvalSymlinks(secondary)
	waitForFileContains(t, awLog, "--identity-home "+canonicalSecondary)
	if data, _ := os.ReadFile(awLog); strings.Contains(string(data), terminalHome+"/.aw") {
		t.Fatalf("decrypt leaked terminal default identity: %s", data)
	}
}

func writeGrantHome(t *testing.T, root, serverURL string, scopes []string) string {
	t.Helper()
	home := filepath.Join(root, "grant-"+strings.ReplaceAll(strings.Join(scopes, "-"), ".", "_"))
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.GrantHomeSigningKeyPath(home), key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(home), &awconfig.GrantHome{Version: awconfig.GrantHomeSchemaVersion, GrantID: "99999999-9999-4999-8999-999999999999", TeamID: "backend:acme.com", Subject: awconfig.GrantSubject{DIDAW: "did:aw:alice", DIDKey: "did:key:zSubjectRoot", Address: "acme.com/alice", Alias: "alice"}, Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), AwebURL: serverURL}); err != nil {
		t.Fatal(err)
	}
	return home
}

func writeFakeNode(t *testing.T, root, script string) string {
	t.Helper()
	path := filepath.Join(root, "node")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeOATS(t *testing.T, root, inputPath string) string {
	t.Helper()
	return writeStateOATS(t, root, inputPath, "idle")
}

func writeStateOATS(t *testing.T, root, inputPath, state string) string {
	t.Helper()
	path := filepath.Join(root, "oats")
	script := "#!/bin/sh\nif [ \"$1 $2\" = \"session inspect\" ]; then printf '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"" + state + "\"}}\\n'; exit 0; fi\nif [ \"$1 $2\" = \"session input\" ]; then cat >> " + shellQuoteForTest(inputPath) + "; printf '{\"ok\":true,\"result\":{\"submitted\":true}}\\n'; exit 0; fi\nprintf '{\"ok\":false,\"error\":{\"message\":\"bad oats\"}}\\n'; exit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFailingThenIdleOATS(t *testing.T, root, inputPath, failPath string) string {
	t.Helper()
	path := filepath.Join(root, "oats")
	script := "#!/bin/sh\nif [ \"$1 $2\" = \"session inspect\" ]; then if [ -f " + shellQuoteForTest(failPath) + " ]; then printf '{\"ok\":false,\"error\":{\"message\":\"inspect unavailable\"}}\\n'; exit 1; fi; printf '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"idle\"}}\\n'; exit 0; fi\nif [ \"$1 $2\" = \"session input\" ]; then cat >> " + shellQuoteForTest(inputPath) + "; printf '{\"ok\":true,\"result\":{\"submitted\":true}}\\n'; exit 0; fi\nprintf '{\"ok\":false,\"error\":{\"message\":\"bad oats\"}}\\n'; exit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeAW(t *testing.T, root, logPath string) string {
	t.Helper()
	path := filepath.Join(root, "aw")
	logLine := ""
	if logPath != "" {
		logLine = "printf '%s\\n' \"$*\" >> " + shellQuoteForTest(logPath) + "\n"
	}
	script := "#!/bin/sh\n" + logLine + "printf '{\"messages\":[]}\\n'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellQuoteForTest(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func waitForStatus(t *testing.T, child *ChannelCoreChild, cond func(ChannelCoreStatus) bool) {
	t.Helper()
	waitForCond(t, "channel-core status", func() bool { return cond(child.Status()) })
}

func waitForFileContains(t *testing.T, path, needle string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, _ = os.ReadFile(path)
		if strings.Contains(string(data), needle) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to contain %q; content=%q", path, needle, string(data))
}

func waitForCond(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
