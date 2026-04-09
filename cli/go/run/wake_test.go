package run

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

func TestEventBusRetriesEarlyEOF(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		if n == 1 {
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		_, _ = w.Write([]byte("event: actionable_chat\ndata: {\"message_id\":\"m1\",\"from_alias\":\"mia\",\"session_id\":\"s1\",\"wake_mode\":\"prompt\",\"unread_count\":1,\"sender_waiting\":true}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	t.Cleanup(server.Close)

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	bus := NewEventBus(EventBusConfig{
		Stream: NewEventStreamOpener(client),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case <-bus.Queue().Ready():
		evt, ok := bus.Queue().Pop()
		if !ok {
			t.Fatal("expected queued event")
		}
		if evt.Event.Type != awid.AgentEventActionableChat || evt.Event.FromAlias != "mia" {
			t.Fatalf("unexpected event: %#v", evt.Event)
		}
		if requests.Load() < 2 {
			t.Fatalf("expected at least 2 stream attempts, got %d", requests.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
	cancel()
	bus.Stop()
}

func TestEventBusRetriesTransientOpenError(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		if n == 1 {
			http.Error(w, `{"detail":"temporary"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: actionable_mail\ndata: {\"message_id\":\"m2\",\"from_alias\":\"alice\",\"subject\":\"test\",\"wake_mode\":\"prompt\",\"unread_count\":1}\n\n"))
	}))
	t.Cleanup(server.Close)

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	bus := NewEventBus(EventBusConfig{
		Stream: NewEventStreamOpener(client),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case <-bus.Queue().Ready():
		evt, ok := bus.Queue().Pop()
		if !ok {
			t.Fatal("expected queued event")
		}
		if evt.Event.Type != awid.AgentEventActionableMail || evt.Event.FromAlias != "alice" {
			t.Fatalf("unexpected event: %#v", evt.Event)
		}
		if requests.Load() < 2 {
			t.Fatalf("expected retry after transient failure, got %d requests", requests.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
	cancel()
	bus.Stop()
}

func TestEventBusFailsFastOnClientError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	bus := NewEventBus(EventBusConfig{
		Stream: NewEventStreamOpener(client),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	// Should disconnect quickly on 401.
	select {
	case <-bus.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bus to stop on 401")
	}

	if bus.State() != ConnDisconnected {
		t.Fatalf("expected disconnected on 401, got %s", bus.State())
	}

	cancel()
	bus.Stop()
}
