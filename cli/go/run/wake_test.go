package run

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-bus.Queue().Ready():
			for {
				evt, ok := bus.Queue().Pop()
				if !ok {
					break
				}
				if evt.Event.Type == awid.AgentEventActionableChat {
					if evt.Event.FromAlias != "mia" {
						t.Fatalf("unexpected event: %#v", evt.Event)
					}
					if requests.Load() < 2 {
						t.Fatalf("expected at least 2 stream attempts, got %d", requests.Load())
					}
					goto received
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for chat event")
		}
	}
received:
	cancel()
	bus.Stop()
}

func TestEventBusQueuesAppEventWakeFromSSE(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: app_event\ndata: {\"event_id\":\"evt-1\",\"app_id\":\"folio\",\"app_event_type\":\"folio/doc.changed\",\"resource_ref\":\"pitch\",\"delivery_intent\":\"wake\",\"producer_delivery_intent\":\"ambient\",\"payload\":{\"title\":\"Pitch\"}}\n\n"))
	}))
	t.Cleanup(server.Close)

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	bus := NewEventBus(EventBusConfig{Stream: NewEventStreamOpener(client)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case <-bus.Queue().Ready():
		evt, ok := bus.Queue().Pop()
		if !ok {
			t.Fatal("expected queued event")
		}
		if evt.Event.Type != awid.AgentEventAppEvent || evt.Event.EventID != "evt-1" || evt.Event.AppID != "folio" || evt.Event.AppEventType != "folio/doc.changed" || evt.Event.DeliveryIntent != "wake" {
			t.Fatalf("unexpected app_event: %#v", evt.Event)
		}
		if evt.Event.Payload["title"] != "Pitch" {
			t.Fatalf("payload not parsed: %#v", evt.Event.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for app_event wake")
	}
	cancel()
	bus.Stop()
}

func TestEventBusRetriesTransientOpenError(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		if n <= 2 {
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
	notices := make(chan string, 8)
	bus.onConnectionNotice = func(message string) { notices <- message }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	deadline := time.After(2 * time.Second)
	sawRecovery, sawMail := false, false
	for !sawMail {
		select {
		case <-bus.Queue().Ready():
			for {
				evt, ok := bus.Queue().Pop()
				if !ok {
					break
				}
				switch evt.Event.Type {
				case awid.AgentEventChannelReconnected:
					sawRecovery = true
				case awid.AgentEventActionableMail:
					if evt.Event.FromAlias != "alice" {
						t.Fatalf("unexpected event: %#v", evt.Event)
					}
					sawMail = true
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for recovery and mail events")
		}
	}
	cancel()
	bus.Stop()
	if !sawRecovery {
		t.Fatal("recovery did not enqueue a catch-up event")
	}
	if requests.Load() < 3 {
		t.Fatalf("expected retries after transient failures, got %d requests", requests.Load())
	}
	var gotNotices []string
	for {
		select {
		case notice := <-notices:
			gotNotices = append(gotNotices, notice)
		default:
			goto noticesDone
		}
	}
noticesDone:
	if len(gotNotices) < 2 || !strings.HasPrefix(gotNotices[0], "aweb: event stream disconnected (network unavailable)") || gotNotices[1] != "aweb: event stream reconnected; catching up" {
		t.Fatalf("connection notices=%v", gotNotices)
	}
	if strings.Contains(strings.Join(gotNotices, "\n"), "TypeError") {
		t.Fatalf("raw error leaked in notices: %v", gotNotices)
	}
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
