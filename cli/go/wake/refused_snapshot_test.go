package wake

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake/session"
)

func TestRefusedMessageReturnsFromFreshSnapshot(t *testing.T) {
	for _, refusal := range []string{"paused", "shell"} {
		t.Run(refusal, func(t *testing.T) {
			root, _ := filepath.EvalSymlinks(t.TempDir())
			store, err := NewStore(filepath.Join(root, "state"))
			if err != nil {
				t.Fatal(err)
			}
			inputPath := filepath.Join(root, "input.txt")
			statePath := filepath.Join(root, "inspect.json")
			setState := func(state string) {
				t.Helper()
				if err := os.WriteFile(statePath, []byte(`{"ok":true,"result":{"present":true,"state":"`+state+`"}}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			setState("working")
			if refusal == "shell" {
				setState("shell")
			}
			oats := filepath.Join(root, "oats")
			script := "#!/bin/sh\nif [ \"$1 $2\" = \"session inspect\" ]; then cat " + shellQuoteForTest(statePath) + "; else cat >> " + shellQuoteForTest(inputPath) + "; printf '{\"ok\":true,\"result\":{\"submitted\":true}}'; fi\n"
			if err := os.WriteFile(oats, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			var fetches atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodGet {
					fetches.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{{"message_id": "mail-1", "from_alias": "bob", "body": "snapshot recovery mail", "created_at": "2026-01-01T00:00:00Z"}}})
				} else {
					_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
				}
			}))
			defer server.Close()
			identity := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
			home := filepath.Join(root, "terminal")
			_ = os.MkdirAll(home, 0700)
			if err := store.SaveRegistration(Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession}); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveInstance(InstanceState{Home: home, Paused: refusal == "paused"}); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var opens []time.Time
			openCount := func() int { mu.Lock(); defer mu.Unlock(); return len(opens) }
			broker, cancel := liveBroker(t, Config{Store: store, Session: &session.ExecClient{Bin: oats}, ChannelCore: NewChannelCoreRunner(store), OpenStream: func(string, string) (run.EventStreamOpener, error) {
				return func(context.Context, time.Time) (awid.EventSource, error) {
					mu.Lock()
					opens = append(opens, time.Now())
					mu.Unlock()
					return &oneEventSource{event: awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-1", ConversationID: "conv-1"}}, nil
				}, nil
			}})
			defer cancel()
			waitForInstance(t, broker, home, func(st InstanceStatus) bool { return st.ChannelCore.TraceStage == "lane_job_failed" })
			assertFileNotContains(t, inputPath, "snapshot recovery mail")
			{
				deadline := time.Now().Add(8 * time.Second)
				for openCount() < 2 && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if openCount() != 2 {
					t.Fatalf("refused snapshot reopen count=%d, want2", openCount())
				}
				mu.Lock()
				gap := opens[1].Sub(opens[0])
				mu.Unlock()
				if gap < 5*time.Second {
					t.Fatalf("persistent refusal reopened too fast: %s", gap)
				}
				waitForCond(t, "second snapshot exhausted four fetches", func() bool { return fetches.Load() >= 8 })
				waitForInstance(t, broker, home, func(st InstanceStatus) bool { return st.ChannelCore.TraceStage == "lane_job_failed" })
				assertFileNotContains(t, inputPath, "snapshot recovery mail")
			}
			if refusal == "shell" {
				setState("working")
			} else {
				if err := broker.SetPaused(home, false); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			deadline := start.Add(8 * time.Second)
			for time.Now().Before(deadline) {
				data, _ := os.ReadFile(inputPath)
				if len(data) > 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			data, _ := os.ReadFile(inputPath)
			if len(data) == 0 {
				t.Fatalf("no automatic re-offer after %s; opens=%d", time.Since(start), openCount())
			}
			if refusal == "paused" && time.Since(start) > 3*time.Second {
				t.Fatalf("resume recovery took %s", time.Since(start))
			}
			if openCount() > 3 {
				t.Fatalf("snapshot storm: %d opens", openCount())
			}
		})
	}
}
