package wake

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake/session"
)

func TestRefusedMessageReturnsFromFreshSnapshot(t *testing.T) {
	for _, tc := range []struct {
		refusal              string
		initialSnapshotDelay time.Duration
	}{
		{refusal: "paused"}, {refusal: "shell"}, {refusal: "blocked"},
		{refusal: "prelaunch-not-launched"}, {refusal: "prelaunch-stopped"},
		// Registration age is not snapshot age: slow startup must not spend
		// the delivery budget before the refusal backoff has elapsed.
		{refusal: "prelaunch-not-launched-delayed", initialSnapshotDelay: 3 * time.Second},
	} {
		t.Run(tc.refusal, func(t *testing.T) {
			refusal := strings.TrimSuffix(tc.refusal, "-delayed")
			root, _ := filepath.EvalSymlinks(t.TempDir())
			store, err := NewStore(filepath.Join(root, "state"))
			if err != nil {
				t.Fatal(err)
			}
			inputPath := filepath.Join(root, "input.txt")
			statePath := filepath.Join(root, "inspect.json")
			prelaunch := strings.HasPrefix(refusal, "prelaunch-")
			setState := func(state string) {
				t.Helper()
				if err := os.WriteFile(statePath, []byte(fmt.Sprintf(`{"ok":true,"result":{"present":%t,"state":%q}}`, state != "not-launched" && state != "stopped", state)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			setState("working")
			if refusal == "shell" || refusal == "blocked" {
				setState(refusal)
			}
			if prelaunch {
				setState(strings.TrimPrefix(refusal, "prelaunch-"))
			}
			oats := filepath.Join(root, "oats")
			script := "#!/bin/sh\nif [ \"$1 $2\" = \"session inspect\" ]; then cat " + shellQuoteForTest(statePath) + "; else cat >> " + shellQuoteForTest(inputPath) + "; printf '{\"ok\":true,\"result\":{\"submitted\":true}}'; fi\n"
			if err := os.WriteFile(oats, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			var fetches atomic.Int32
			var acks atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodGet {
					fetches.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{{"message_id": "mail-1", "from_alias": "bob", "body": "snapshot recovery mail", "created_at": "2026-01-01T00:00:00Z"}}})
				} else {
					acks.Add(1)
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
			thirdSnapshot := make(chan time.Time, 1)
			openCount := func() int { mu.Lock(); defer mu.Unlock(); return len(opens) }
			registeredAt := time.Now()
			broker, cancel := liveBroker(t, Config{Store: store, Session: &session.ExecClient{Bin: oats}, ChannelCore: NewChannelCoreRunner(store), OpenStream: func(string, string) (run.EventStreamOpener, error) {
				return func(ctx context.Context, _ time.Time) (awid.EventSource, error) {
					mu.Lock()
					openedAt := time.Now()
					opens = append(opens, openedAt)
					count := len(opens)
					mu.Unlock()
					if count == 3 {
						thirdSnapshot <- openedAt
					}
					if count == 1 && !sleepCtx(ctx, tc.initialSnapshotDelay) {
						return nil, ctx.Err()
					}
					return &oneEventSource{event: awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-1", ConversationID: "conv-1"}}, nil
				}, nil
			}})
			defer cancel()
			// The retained trace name and HTTP fetch count do not identify
			// completion of a particular delivery cycle. Wait for the broker
			// to consume that cycle's exhausted-retry request and arm its timer.
			waitForBackoff := func(next time.Duration) {
				t.Helper()
				waitForCond(t, "exhausted refusal scheduled its snapshot", func() bool {
					broker.mu.Lock()
					defer broker.mu.Unlock()
					if len(broker.streams) != 1 {
						return false
					}
					for _, stream := range broker.streams {
						stream.mu.Lock()
						scheduled := stream.snapshotTimer != nil && stream.snapshotBackoff == next
						stream.mu.Unlock()
						if !scheduled {
							return false
						}
					}
					return true
				})
			}
			waitForBackoff(2 * snapshotBackoffMin)
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
				waitForBackoff(4 * snapshotBackoffMin)
				if got := fetches.Load(); got != 8 {
					t.Fatalf("fetches=%d, want two exhausted four-attempt cycles", got)
				}
				assertFileNotContains(t, inputPath, "snapshot recovery mail")
			}
			if acks.Load() != 0 {
				t.Fatal("refused message was acknowledged")
			}
			if data, _ := os.ReadFile(filepath.Join(identity, "channel-delivered-ids-backend_acme.com.json")); strings.Contains(string(data), "mail-1") {
				t.Fatal("refused message was marked delivered")
			}
			if prelaunch {
				// The ordinary spawn order registers before launching. Keep the
				// home absent for ten seconds and never register it again.
				for time.Since(registeredAt) < 10*time.Second {
					if inst := instanceByHome(t, broker, home); inst.Phase == PhaseInactive {
						t.Fatal("prelaunch registration became inactive")
					}
					time.Sleep(10 * time.Millisecond)
				}
				inst := instanceByHome(t, broker, home)
				if inst.Phase != PhasePending || !inst.ChannelCore.Running {
					t.Fatalf("prelaunch status=%#v", inst)
				}
				if data, err := os.ReadFile(inputPath); err == nil {
					t.Fatalf("input before launch: %s", data)
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if acks.Load() != 0 {
					t.Fatal("prelaunch message was acknowledged")
				}
				setState("working")
			} else if refusal == "shell" || refusal == "blocked" {
				if inst := instanceByHome(t, broker, home); inst.Phase == PhaseInactive {
					t.Fatal("shell became inactive")
				}
				setState("idle")
			} else {
				if err := broker.SetPaused(home, false); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			if refusal != "paused" {
				// Becoming live does not reset refusal backoff. Observe the
				// automatic third snapshot before starting the input budget;
				// no registration, new event or manual snapshot is supplied.
				select {
				case openedAt := <-thirdSnapshot:
					mu.Lock()
					gap := openedAt.Sub(opens[1])
					mu.Unlock()
					if gap < 2*snapshotBackoffMin {
						t.Fatalf("second refusal reopened too fast: %s", gap)
					}
				case <-time.After(2*snapshotBackoffMin + 5*time.Second):
					t.Fatal("scheduled third snapshot did not open")
				}
			}
			deadline := time.Now().Add(8 * time.Second)
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
			if !strings.Contains(string(data), "snapshot recovery mail") {
				t.Fatalf("missing full content: %s", data)
			}
			waitForCond(t, "accepted input acknowledged", func() bool { return acks.Load() == 1 })
			waitForCond(t, "accepted input resets refusal backoff", func() bool {
				broker.mu.Lock()
				defer broker.mu.Unlock()
				for _, stream := range broker.streams {
					stream.mu.Lock()
					backoff := stream.snapshotBackoff
					stream.mu.Unlock()
					if backoff != 0 {
						return false
					}
				}
				return true
			})
			if prelaunch {
				t.Logf("launch after %s; snapshot delivery after launch=%s; opens=%d", start.Sub(registeredAt), time.Since(start), openCount())
			}
			if openCount() > 3 {
				t.Fatalf("snapshot storm: %d opens", openCount())
			}
		})
	}
}
