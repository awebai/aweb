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

func TestPersistentRefusalBacksOffAndResumeRecovers(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	oats := writeStateOATS(t, root, inputPath, "shell")
	var acks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{{"message_id": "mail-1", "from_alias": "bob", "body": "persistent refusal mail", "created_at": "2026-01-01T00:00:00Z"}}})
		} else {
			acks.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		}
	}))
	defer server.Close()
	identity := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRegistration(Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var opens []time.Time
	broker, cancel := liveBroker(t, Config{Store: store, Session: &session.ExecClient{Bin: oats}, ChannelCore: NewChannelCoreRunner(store), OpenStream: func(string, string) (run.EventStreamOpener, error) {
		return func(context.Context, time.Time) (awid.EventSource, error) {
			mu.Lock()
			opens = append(opens, time.Now())
			mu.Unlock()
			return &oneEventSource{event: awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-1"}}, nil
		}, nil
	}})
	defer cancel()
	waitForInstance(t, broker, home, func(st InstanceStatus) bool { return st.ChannelCore.TraceStage == "lane_job_failed" })
	// Measure a full minute with one unread message and persistent refusal.
	<-time.After(time.Minute)
	mu.Lock()
	observed := append([]time.Time(nil), opens...)
	mu.Unlock()
	var offsets []time.Duration
	for _, at := range observed {
		offsets = append(offsets, at.Sub(observed[0]))
	}
	t.Logf("persistent shell60s: opens=%d offsets=%v", len(observed), offsets)
	if acks.Load() != 0 {
		t.Fatal("refused input was acknowledged")
	}
	if data, err := os.ReadFile(inputPath); err == nil {
		t.Fatalf("input into shell: %s", data)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(observed) > 4 {
		t.Fatalf("persistent refusal opened %d streams in60s, want at most4", len(observed))
	}
	if len(observed) < 4 {
		t.Fatalf("backoff did not make three recovery attempts: %d opens", len(observed))
	}
	for i, minimum := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second} {
		if gap := observed[i+1].Sub(observed[i]); gap < minimum {
			t.Fatalf("reopen gap%d=%s want >=%s", i, gap, minimum)
		}
	}
	writeStateOATS(t, root, inputPath, "working")
	if err := broker.SetPaused(home, true); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := broker.SetPaused(home, false); err != nil {
		t.Fatal(err)
	}
	waitForFileContains(t, inputPath, "persistent refusal mail")
	waitForCond(t, "resumed input acknowledged", func() bool { return acks.Load() == 1 })
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("resume waited for backoff: %s", elapsed)
	}
}

func TestRefusalBackoffCapsCoalescesAndResets(t *testing.T) {
	stream := &streamRunner{streamCancel: func() {}}
	defer func() { stream.mu.Lock(); stream.clearSnapshotLocked(); stream.mu.Unlock() }()
	snapshot := func() (*time.Timer, time.Duration) {
		stream.mu.Lock()
		defer stream.mu.Unlock()
		return stream.snapshotTimer, stream.snapshotBackoff
	}
	for _, wantNext := range []time.Duration{10, 20, 40, 80, 160, 300, 300, 300} {
		stream.requestSnapshot(5 * time.Second)
		timer, _ := snapshot()
		for i := 0; i < 10; i++ {
			stream.requestSnapshot(5 * time.Second)
		}
		if gotTimer, next := snapshot(); gotTimer != timer || next != wantNext*time.Second {
			t.Fatalf("coalesced next delay=%s want=%s", next, wantNext*time.Second)
		}
		// Simulate the attempt ending and reopening. Transport reconnects must
		// not clear refusal backoff; stop each owned timer without waiting5min.
		stream.mu.Lock()
		stream.clearSnapshotLocked()
		stream.streamCancel = func() {}
		stream.mu.Unlock()
	}
	stream.resetSnapshotBackoff()
	stream.requestSnapshot(5 * time.Second)
	if _, next := snapshot(); next != 10*time.Second {
		t.Fatalf("input did not restore5s window: next=%s", next)
	}
	// An accepted input must also shorten an already queued long recovery.
	stream.mu.Lock()
	stream.snapshotBackoff = 5 * time.Minute
	oldTimer := stream.snapshotTimer
	stream.mu.Unlock()
	stream.resetSnapshotBackoff()
	if timer, next := snapshot(); timer == oldTimer || next != 10*time.Second {
		t.Fatal("accepted input retained the long pending recovery")
	}
	var cancelled atomic.Bool
	stream.mu.Lock()
	stream.streamCancel = func() { cancelled.Store(true) }
	stream.mu.Unlock()
	stream.requestSnapshot(0)
	if timer, next := snapshot(); !cancelled.Load() || timer != nil || next != 0 {
		t.Fatal("resume did not reset and reopen immediately")
	}
}
