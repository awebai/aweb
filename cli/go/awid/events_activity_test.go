package awid

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A consumer of events never sees a heartbeat comment or a partial frame, so
// the stream reports them itself: every read that returned bytes, and every
// comment line.
func TestAgentEventStreamReportsReadsBelowEvents(t *testing.T) {
	reader, writer := io.Pipe()
	stream := newAgentEventStream(reader)
	var reads, comments atomic.Int32
	stream.OnRead(func() { reads.Add(1) })
	stream.OnComment(func() { comments.Add(1) })

	events := make(chan *AgentEvent, 1)
	go func() {
		ev, err := stream.Next(context.Background())
		if err != nil {
			t.Errorf("Next: %v", err)
		}
		events <- ev
	}()

	write := func(payload string) {
		t.Helper()
		if _, err := io.WriteString(writer, payload); err != nil {
			t.Fatal(err)
		}
	}
	reported := func(what string, counter *atomic.Int32, want int32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for counter.Load() < want && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := counter.Load(); got != want {
			t.Fatalf("%s reported=%d, want %d", what, got, want)
		}
	}
	write(": keepalive\n\n")
	reported("reads after a comment", &reads, 1)
	reported("comments", &comments, 1)
	write("event: conn")
	reported("reads after a partial frame", &reads, 2)
	write("ected\n")
	reported("reads after the rest of the line", &reads, 3)
	select {
	case ev := <-events:
		t.Fatalf("a comment and a partial frame produced an event: %+v", ev)
	case <-time.After(20 * time.Millisecond):
	}

	write("data: {\"agent_id\":\"a\"}\n\n")
	select {
	case ev := <-events:
		if ev == nil || ev.Type != AgentEventConnected {
			t.Fatalf("event=%+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event was not delivered")
	}
	if got := comments.Load(); got != 1 {
		t.Fatalf("comments reported=%d after an event, want 1", got)
	}
	reported("reads after the event", &reads, 4)
	_ = writer.Close()
}

// A read that returns no bytes is not activity.
func TestAgentEventStreamDoesNotReportAnEmptyRead(t *testing.T) {
	reader, writer := io.Pipe()
	stream := newAgentEventStream(reader)
	var reads atomic.Int32
	stream.OnRead(func() { reads.Add(1) })
	_ = writer.Close()
	if _, err := stream.Next(context.Background()); err != io.EOF {
		t.Fatalf("err=%v, want io.EOF", err)
	}
	if got := reads.Load(); got != 0 {
		t.Fatalf("reads reported=%d for a stream that ended without bytes", got)
	}
}

// The answer to a failed open carries Retry-After as the server sent it.
func TestEventStreamOpenErrorCarriesRetryAfter(t *testing.T) {
	for _, header := range []string{"", "17", "Wed, 21 Oct 2026 07:28:00 GMT"} {
		t.Run(header, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if header != "" {
					w.Header().Set("Retry-After", header)
				}
				http.Error(w, `{"detail":"slow down"}`, http.StatusTooManyRequests)
			}))
			t.Cleanup(server.Close)
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.EventStream(context.Background(), time.Now().Add(time.Minute))
			if code, ok := HTTPStatusCode(err); !ok || code != http.StatusTooManyRequests {
				t.Fatalf("err=%v", err)
			}
			got, ok := HTTPRetryAfter(err)
			if got != header || ok != (header != "") {
				t.Fatalf("HTTPRetryAfter=%q, %t; want %q", got, ok, header)
			}
		})
	}
	if _, ok := HTTPRetryAfter(io.EOF); ok {
		t.Fatal("an error that is not an HTTP answer reported Retry-After")
	}
}
