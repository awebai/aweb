package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// streamOpens records the query of every stream open the client makes.
type streamOpens struct {
	mu      sync.Mutex
	queries []map[string]string
}

func (s *streamOpens) record(r *http.Request) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, map[string]string{
		"after":     r.URL.Query().Get("after"),
		"after_seq": r.URL.Query().Get("after_seq"),
	})
	return len(s.queries)
}

func (s *streamOpens) all() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]string(nil), s.queries...)
}

func writeSSE(w http.ResponseWriter, event string, payload map[string]any) {
	data, _ := json.Marshal(payload)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// The server ends a chat stream at its lifetime cap (300 s) with no event. A
// wait that is still running reopens the stream after the last number it saw,
// so the reply that arrives later still ends the wait.
func TestSendWaitContinuesAcrossTheServerStreamCap(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	opens := &streamOpens{}
	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{SessionID: "s1", MessageID: sentMsgID, SSEURL: "/v1/chat/sessions/s1/stream"})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			switch opens.record(r) {
			case 1:
				writeSSE(w, "message", map[string]any{"type": "message", "seq": 7, "message_id": sentMsgID, "from_agent": "alice", "body": "hello"})
				writeSSE(w, "read_receipt", map[string]any{"type": "read_receipt", "seq": 8, "reader_alias": "bob", "extends_wait_seconds": 300})
				// The stream reaches its cap and closes.
			default:
				writeSSE(w, "message", map[string]any{"type": "message", "seq": 9, "message_id": "msg-reply", "from_agent": "bob", "body": "the answer"})
			}
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := Send(ctx, mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" || result.Reply != "the answer" {
		t.Fatalf("status=%s reply=%q, want the reply that arrived after the stream cap", result.Status, result.Reply)
	}
	got := opens.all()
	if len(got) != 2 {
		t.Fatalf("stream opens=%v, want the capped stream reopened once", got)
	}
	if got[1]["after_seq"] != "8" || got[1]["after"] != "" {
		t.Fatalf("reopen query=%v, want after_seq=8 (the last number seen) and no timestamp", got[1])
	}
}

// A listener that saw nothing before the cap reopens from when it began, so a
// message committed while the stream was closing is not lost.
func TestListenWaitContinuesAcrossTheServerStreamCap(t *testing.T) {
	t.Parallel()

	opens := &streamOpens{}
	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{{SessionID: "s1", Participants: []string{"alice", "bob"}}}})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			if opens.record(r) == 1 {
				fmt.Fprintf(w, ": keepalive\n\n")
				return
			}
			writeSSE(w, "message", map[string]any{"type": "message", "seq": 3, "message_id": "msg-1", "from_agent": "bob", "body": "are you there?"})
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	began := time.Now()
	result, err := Listen(ctx, mustClient(t, server.URL), "bob", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" || result.Reply != "are you there?" {
		t.Fatalf("status=%s reply=%q, want the message that arrived after the stream cap", result.Status, result.Reply)
	}
	got := opens.all()
	if len(got) != 2 {
		t.Fatalf("stream opens=%v, want the capped stream reopened once", got)
	}
	if got[0]["after"] != "" || got[0]["after_seq"] != "" {
		t.Fatalf("first open query=%v, want a live start", got[0])
	}
	after, err := time.Parse(time.RFC3339, got[1]["after"])
	if err != nil || got[1]["after_seq"] != "" {
		t.Fatalf("reopen query=%v, want a timestamp replay from when the wait began", got[1])
	}
	if after.After(began) || began.Sub(after) > 3*time.Second {
		t.Fatalf("reopen replays after %s, want just before the wait began at %s", after, began)
	}
}

// The local wait still bounds the call: a server that keeps closing the stream
// does not keep the caller past its wait, and is not reopened in a tight loop.
func TestWaitReopenStopsAtTheLocalDeadline(t *testing.T) {
	t.Parallel()

	opens := &streamOpens{}
	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{{SessionID: "s1", Participants: []string{"alice", "bob"}}}})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			opens.record(r)
			w.Header().Set("Content-Type", "text/event-stream")
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	began := time.Now()
	result, err := Listen(ctx, mustClient(t, server.URL), "bob", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(began)
	if result.Status != "timeout" || took < 2*time.Second || took > 4*time.Second {
		t.Fatalf("status=%s after %s, want timeout at the 2 s wait", result.Status, took)
	}
	if n := len(opens.all()); n < 2 || n > 4 {
		t.Fatalf("stream opened %d times in a 2 s wait, want one reopen per second at most", n)
	}
}

// A server before session numbers (server < 1.27.50) sends no seq, so a reopen
// replays by timestamp and presents earlier messages again. A message already
// seen is not presented twice: a replayed hang-on does not extend the wait
// again.
func TestWaitReopenAgainstAServerWithoutSeqPresentsEachMessageOnce(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	opens := &streamOpens{}
	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{SessionID: "s1", MessageID: sentMsgID, SSEURL: "/v1/chat/sessions/s1/stream"})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			opens.record(r)
			w.Header().Set("Content-Type", "text/event-stream")
			// Every open replays everything since the send.
			writeSSE(w, "message", map[string]any{"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello"})
			writeSSE(w, "message", map[string]any{"type": "message", "message_id": "msg-hangon", "from_agent": "bob", "body": "thinking...", "hang_on": true, "extends_wait_seconds": 2})
		},
	})
	t.Cleanup(server.Close)

	var extensions []string
	callback := func(kind, msg string) {
		if kind == "wait_extended" {
			extensions = append(extensions, msg)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	began := time.Now()
	result, err := Send(ctx, mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 1}, callback)
	if err != nil {
		t.Fatalf("err=%v after %s, want a timeout once the one extension ran out", err, time.Since(began))
	}
	if result.Status != "timeout" || len(extensions) != 1 {
		t.Fatalf("status=%s extensions=%v, want one extension then timeout", result.Status, extensions)
	}
	if len(opens.all()) < 2 {
		t.Fatalf("stream opened %d times, want it reopened while the extended wait ran", len(opens.all()))
	}
	hangOns := 0
	for _, ev := range result.Events {
		if ev.MessageID == "msg-hangon" {
			hangOns++
		}
	}
	if hangOns != 1 {
		t.Fatalf("hang-on presented %d times in events, want once", hangOns)
	}
}
