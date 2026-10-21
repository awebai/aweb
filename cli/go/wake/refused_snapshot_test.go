package wake

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
		slowRefusalCycle     bool
		slowFinalInspect     bool
	}{
		{refusal: "paused"}, {refusal: "shell"}, {refusal: "blocked"},
		{refusal: "prelaunch-not-launched"}, {refusal: "prelaunch-stopped"},
		// Registration age is not snapshot age: slow startup must not spend
		// the delivery budget before the refusal backoff has elapsed. The final
		// inspection also exceeds the idle handoff budget while still in flight.
		{refusal: "prelaunch-not-launched-delayed", initialSnapshotDelay: 3 * time.Second, slowFinalInspect: true},
		// A loaded host can make one refused-delivery cycle take longer than a
		// fixed wall-clock bound while the broker behaves correctly. Every
		// terminal inspection of the second cycle is slow.
		{refusal: "shell-slow-cycle", slowRefusalCycle: true},
	} {
		t.Run(tc.refusal, func(t *testing.T) {
			refusal := strings.TrimSuffix(strings.TrimSuffix(tc.refusal, "-delayed"), "-slow-cycle")
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
			slowInspect := filepath.Join(root, "slow-inspect")
			oneSlowInspect := filepath.Join(root, "one-slow-inspect")
			script := "#!/bin/sh\nif [ \"$1 $2\" = \"session inspect\" ]; then if [ -f " + shellQuoteForTest(slowInspect) + " ]; then sleep 1.5; fi; if [ -f " + shellQuoteForTest(oneSlowInspect) + " ]; then rm " + shellQuoteForTest(oneSlowInspect) + "; sleep 6; fi; cat " + shellQuoteForTest(statePath) + "; else cat >> " + shellQuoteForTest(inputPath) + "; printf '{\"ok\":true,\"result\":{\"submitted\":true}}'; fi\n"
			if err := os.WriteFile(oats, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			var fetches atomic.Int32
			var acks atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodGet {
					n := fetches.Add(1)
					if tc.slowFinalInspect && n == 4 {
						if err := os.WriteFile(oneSlowInspect, nil, 0600); err != nil {
							t.Error(err)
						}
					}
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
			var traceMu sync.Mutex
			var trace []string
			record := func(format string, args ...any) {
				traceMu.Lock()
				defer traceMu.Unlock()
				trace = append(trace, time.Now().Format("15:04:05.000")+" "+fmt.Sprintf(format, args...))
			}
			broker, cancel := liveBroker(t, Config{Log: record, Store: store, Session: &session.ExecClient{Bin: oats}, ChannelCore: NewChannelCoreRunner(store), OpenStream: func(string, string) (run.EventStreamOpener, error) {
				return func(ctx context.Context, _ time.Time) (awid.EventSource, error) {
					mu.Lock()
					openedAt := time.Now()
					opens = append(opens, openedAt)
					count := len(opens)
					mu.Unlock()
					context.AfterFunc(ctx, func() { record("snapshot %d context cancelled", count) })
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
			// On failure, report what the broker and the channel-core child were
			// doing, so a timeout says whether a delivery cycle was slow, its
			// snapshot request was lost, or the child restarted.
			sampling := make(chan struct{})
			go func() {
				last := ""
				for {
					select {
					case <-sampling:
						return
					case <-time.After(20 * time.Millisecond):
					}
					for _, inst := range broker.Status().Instances {
						if inst.Home != home {
							continue
						}
						cc := inst.ChannelCore
						now := fmt.Sprintf("child stage=%s running=%t restarts=%d readiness=%s/%s error=%q", cc.TraceStage, cc.Running, cc.RestartCount, cc.ReadinessState, cc.ReadinessWaiting, cc.LastError)
						if now != last {
							record("%s", now)
							last = now
						}
					}
				}
			}()
			defer func() {
				close(sampling)
				if !t.Failed() {
					return
				}
				broker.mu.Lock()
				for key, stream := range broker.streams {
					stream.mu.Lock()
					t.Logf("stream %s: timer=%t backoff=%s live=%t phase=%s", key, stream.snapshotTimer != nil, stream.snapshotBackoff, stream.streamCancel != nil, stream.phase)
					stream.mu.Unlock()
				}
				broker.mu.Unlock()
				mu.Lock()
				t.Logf("snapshot opens=%v fetches=%d acks=%d", opens, fetches.Load(), acks.Load())
				stacks := make([]byte, 1<<20)
				t.Logf("goroutines at failure:\n%s", stacks[:runtime.Stack(stacks, true)])
				mu.Unlock()
				traceMu.Lock()
				for _, line := range trace {
					t.Logf("trace %s", line)
				}
				traceMu.Unlock()
			}()
			// The retained trace name and HTTP fetch count do not identify
			// completion of a particular delivery cycle. Wait for the broker
			// to consume that cycle's exhausted-retry request and arm its timer.
			scheduled := func(next time.Duration) bool {
				broker.mu.Lock()
				defer broker.mu.Unlock()
				if len(broker.streams) != 1 {
					return false
				}
				for _, stream := range broker.streams {
					stream.mu.Lock()
					// Backoff records scheduling even after the timer fires. A
					// loaded observer must not miss that transient armed window.
					armed := stream.snapshotBackoff >= next
					stream.mu.Unlock()
					if !armed {
						return false
					}
				}
				return true
			}
			// The cycle runs in the channel-core child: inbox fetches and
			// terminal inspections whose duration depends on the host. Its
			// progress is the fetch count and the child's delivery stage.
			cycleProgress := func() (string, bool) {
				progress := fmt.Sprintf("fetches=%d", fetches.Load())
				exhausted := false
				for _, inst := range broker.Status().Instances {
					if inst.Home == home {
						cc := inst.ChannelCore
						progress += fmt.Sprintf(" stage=%s readiness=%s error=%q", cc.TraceStage, cc.ReadinessWaiting, cc.LastError)
						exhausted = cc.TraceStage == "lane_job_failed"
					}
				}
				return progress, exhausted
			}
			// Delivery includes real subprocess inspections with their own
			// deadlines. A repeated stage name is not evidence that one is stuck.
			// Keep the existing whole-cycle limit, then give the broker the
			// existing five seconds to schedule after this cycle has exhausted.
			waitForBackoff := func(next time.Duration, cycleFetches int32) {
				t.Helper()
				const stalled = 5 * time.Second
				const limit = 2 * time.Minute
				start := time.Now()
				var exhaustedAt time.Time
				var last string
				for !scheduled(next) {
					var exhausted bool
					last, exhausted = cycleProgress()
					if exhausted && fetches.Load() >= cycleFetches && exhaustedAt.IsZero() {
						exhaustedAt = time.Now()
					}
					if (!exhaustedAt.IsZero() && time.Since(exhaustedAt) > stalled) || time.Since(start) > limit {
						t.Fatalf("timed out waiting for exhausted refusal scheduled its snapshot (last progress %s)", last)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			waitForBackoff(2*snapshotBackoffMin, 4)
			if tc.slowRefusalCycle {
				if err := os.WriteFile(slowInspect, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
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
				waitForBackoff(4*snapshotBackoffMin, 8)
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
