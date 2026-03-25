// ABOUTME: Tests for the chat protocol layer.
// ABOUTME: Uses httptest mock servers to test protocol functions.

package chat

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// mockHandler dispatches requests to registered handlers by exact method+path match.
type mockHandler struct {
	handlers map[string]http.HandlerFunc
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	if h, ok := m.handlers[key]; ok {
		h(w, r)
		return
	}
	http.NotFound(w, r)
}

func newMockServer(handlers map[string]http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(&mockHandler{handlers: handlers})
}

func mustClient(t *testing.T, url string) *awid.Client {
	t.Helper()
	c, err := awid.New(url)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestPending(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, LastMessage: "hi", LastFrom: "bob", UnreadCount: 1},
				},
				MessagesWaiting: 2,
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Pending(context.Background(), mustClient(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pending) != 1 {
		t.Fatalf("pending=%d", len(result.Pending))
	}
	if result.Pending[0].SessionID != "s1" {
		t.Fatalf("session_id=%s", result.Pending[0].SessionID)
	}
	if result.MessagesWaiting != 2 {
		t.Fatalf("messages_waiting=%d", result.MessagesWaiting)
	}
}

func TestPendingReturnsConversations(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, UnreadCount: 1},
				},
				MessagesWaiting: 1,
			})
		},
		// No /v1/network/chat/pending handler — returns 404.
	})
	t.Cleanup(server.Close)

	result, err := Pending(context.Background(), mustClient(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pending) != 1 {
		t.Fatalf("pending=%d, want 1 (local only, network gracefully skipped)", len(result.Pending))
	}
	if result.Pending[0].SessionID != "s1" {
		t.Fatalf("session_id=%s", result.Pending[0].SessionID)
	}
	if result.MessagesWaiting != 1 {
		t.Fatalf("messages_waiting=%d, want 1", result.MessagesWaiting)
	}
}

func TestExtendWait(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"POST /v1/chat/sessions/s1/messages": func(w http.ResponseWriter, r *http.Request) {
			var req awid.ChatSendMessageRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if !req.ExtendWait {
				t.Error("expected extend_wait=true")
			}
			jsonResponse(w, awid.ChatSendMessageResponse{
				MessageID:          "msg-1",
				Delivered:          true,
				ExtendsWaitSeconds: 300,
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := ExtendWait(context.Background(), mustClient(t, server.URL), "bob", "thinking...")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "s1" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
	if result.ExtendsWaitSeconds != 300 {
		t.Fatalf("extends_wait_seconds=%d", result.ExtendsWaitSeconds)
	}
}

func TestOpen(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, SenderWaiting: true},
				},
			})
		},
		"GET /v1/chat/sessions/s1/messages": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{MessageID: "m1", FromAgent: "bob", Body: "hello", Timestamp: "2025-01-01T00:00:00Z"},
					{MessageID: "m2", FromAgent: "bob", Body: "are you there?", Timestamp: "2025-01-01T00:00:01Z"},
				},
			})
		},
		"POST /v1/chat/sessions/s1/read": func(w http.ResponseWriter, r *http.Request) {
			var req awid.ChatMarkReadRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.UpToMessageID != "m2" {
				t.Errorf("up_to_message_id=%s", req.UpToMessageID)
			}
			jsonResponse(w, awid.ChatMarkReadResponse{
				Success:        true,
				MessagesMarked: 2,
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Open(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "s1" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
	if len(result.Messages) != 2 {
		t.Fatalf("messages=%d", len(result.Messages))
	}
	if result.MarkedRead != 2 {
		t.Fatalf("marked_read=%d", result.MarkedRead)
	}
	if !result.SenderWaiting {
		t.Fatal("sender_waiting=false")
	}
}

func TestOpenFallbackToListSessions(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatListSessionsResponse{
				Sessions: []awid.ChatSessionItem{
					{SessionID: "s2", Participants: []string{"alice", "bob"}, CreatedAt: "2025-01-01T00:00:00Z"},
				},
			})
		},
		"GET /v1/chat/sessions/s2/messages": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatHistoryResponse{Messages: []awid.ChatMessage{}})
		},
	})
	t.Cleanup(server.Close)

	result, err := Open(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "s2" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
	if !result.UnreadWasEmpty {
		t.Fatal("expected unread_was_empty=true")
	}
}

func TestHistory(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/messages": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{MessageID: "m1", FromAgent: "alice", Body: "hello", Timestamp: "2025-01-01T00:00:00Z"},
					{MessageID: "m2", FromAgent: "bob", Body: "hi!", Timestamp: "2025-01-01T00:00:01Z"},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := History(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "s1" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
	if len(result.Messages) != 2 {
		t.Fatalf("messages=%d", len(result.Messages))
	}
}

func TestShowPending(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, LastMessage: "help!", LastFrom: "bob", SenderWaiting: true},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := ShowPending(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pending" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "help!" {
		t.Fatalf("reply=%s", result.Reply)
	}
	if !result.SenderWaiting {
		t.Fatal("sender_waiting=false")
	}
}

func TestSendWithLeaving(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, r *http.Request) {
			var req awid.ChatCreateSessionRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if !req.Leaving {
				t.Error("expected leaving=true")
			}
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1", MessageID: "m1",
				SSEURL: "/v1/chat/sessions/s1/stream",
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "goodbye", SendOptions{Leaving: true, Wait: 60}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSendNoWait(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1", MessageID: "m1",
				SSEURL: "/v1/chat/sessions/s1/stream",
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "fire and forget", SendOptions{Wait: 0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSendTargetsLeft(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID:   "s1",
				MessageID:   "m1",
				SSEURL:      "/v1/chat/sessions/s1/stream",
				TargetsLeft: []string{"bob"},
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 60}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "targets_left" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSendWithReply(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Replay: our sent message
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Reply from bob
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply-1", "from_agent": "bob", "body": "hi back!",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "hi back!" {
		t.Fatalf("reply=%s", result.Reply)
	}
}

func TestSendWithReplySuppressesEphemeralContactTag(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/agents/resolve/architect": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, map[string]any{
				"did":         "did:key:z6MkSender",
				"identity_id": "identity-uuid-1",
				"address":     "myteam/architect",
				"lifetime":    "ephemeral",
				"custody":     "self",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "implementer", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			replyData, _ := json.Marshal(map[string]any{
				"type":       "message",
				"message_id": "msg-reply-1",
				"from_agent": "architect",
				"body":       "hi back!",
				"from_did":   "did:key:z6MkSender",
				"is_contact": false,
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	client := mustClient(t, server.URL)
	client.SetAddress("myteam/implementer")
	client.SetResolver(&awid.ServerResolver{Client: client})

	result, err := Send(context.Background(), client, "implementer", []string{"architect"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "hi back!" {
		t.Fatalf("reply=%s", result.Reply)
	}
	if len(result.Events) != 1 {
		t.Fatalf("events=%d, want 1", len(result.Events))
	}
	if result.Events[0].IsContact != nil {
		t.Fatalf("ephemeral SSE sender should suppress contact tag, got %v", *result.Events[0].IsContact)
	}
}

func TestSendWithTimeout(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Replay our sent message, then hang (no reply)
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Block until client disconnects
			<-time.After(10 * time.Second)
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Send(ctx, mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" {
		t.Fatalf("status=%s (expected sent after timeout)", result.Status)
	}
	if result.WaitedSeconds < 1 {
		t.Fatalf("waited_seconds=%d", result.WaitedSeconds)
	}
}

func TestSendWithExtendWaitReceived(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	var callbackCalls []string

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Our sent message
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Bob sends extend-wait
			hangOnData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-hangon", "from_agent": "bob",
				"body": "thinking...", "hang_on": true, "extends_wait_seconds": 300,
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", hangOnData)
			if flusher != nil {
				flusher.Flush()
			}

			// Bob sends actual reply
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "here's my answer",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	callback := func(kind, msg string) {
		callbackCalls = append(callbackCalls, kind+": "+msg)
	}

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "here's my answer" {
		t.Fatalf("reply=%s", result.Reply)
	}

	// Verify callbacks were called for extend_wait and wait_extended
	foundExtendWait := false
	foundExtended := false
	for _, c := range callbackCalls {
		if strings.HasPrefix(c, "extend_wait:") {
			foundExtendWait = true
		}
		if strings.HasPrefix(c, "wait_extended:") {
			foundExtended = true
		}
	}
	if !foundExtendWait {
		t.Fatal("missing extend_wait callback")
	}
	if !foundExtended {
		t.Fatal("missing wait_extended callback")
	}
}

func TestSendWithReadReceipt(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	var callbackKinds []string

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Our sent message
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Read receipt from bob with 300s extension (matches server behavior)
			rrData, _ := json.Marshal(map[string]any{
				"type": "read_receipt", "reader_alias": "bob", "extends_wait_seconds": 300,
			})
			fmt.Fprintf(w, "event: read_receipt\ndata: %s\n\n", rrData)
			if flusher != nil {
				flusher.Flush()
			}

			// Reply from bob
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "got it",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	callback := func(kind, _ string) {
		callbackKinds = append(callbackKinds, kind)
	}

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}

	foundReadReceipt := false
	foundWaitExtended := false
	for _, k := range callbackKinds {
		if k == "read_receipt" {
			foundReadReceipt = true
		}
		if k == "wait_extended" {
			foundWaitExtended = true
		}
	}
	if !foundReadReceipt {
		t.Fatal("missing read_receipt callback")
	}
	if !foundWaitExtended {
		t.Fatal("missing wait_extended callback from read receipt")
	}
}

func TestSendStreamDeadlineExceedsWait(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	var capturedDeadline time.Time

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			// Capture the deadline query parameter sent to the server.
			deadlineStr := r.URL.Query().Get("deadline")
			if deadlineStr != "" {
				capturedDeadline, _ = time.Parse(time.RFC3339Nano, deadlineStr)
			}

			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Send our message then reply immediately.
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "hi",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	before := time.Now()
	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}

	// The stream deadline should be at least maxStreamDeadline from now,
	// not just the wait timeout (5s).
	if capturedDeadline.IsZero() {
		t.Fatal("server did not receive deadline parameter")
	}
	minExpected := before.Add(maxStreamDeadline - 1*time.Second)
	if capturedDeadline.Before(minExpected) {
		t.Fatalf("stream deadline %v is too close to now; expected at least %v from request time", capturedDeadline, maxStreamDeadline)
	}
}

func TestDefaultWaitIs120(t *testing.T) {
	t.Parallel()

	if DefaultWait != 120 {
		t.Fatalf("DefaultWait=%d, want 120", DefaultWait)
	}
}

func TestMaxSendTimeoutIs16Min(t *testing.T) {
	t.Parallel()

	if MaxSendTimeout != 16*time.Minute {
		t.Fatalf("MaxSendTimeout=%v, want 16m", MaxSendTimeout)
	}
}

func TestFindSessionFallback(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatListSessionsResponse{
				Sessions: []awid.ChatSessionItem{
					{SessionID: "s-fallback", Participants: []string{"alice", "bob"}},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	sessionID, senderWaiting, err := findSession(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "s-fallback" {
		t.Fatalf("session_id=%s", sessionID)
	}
	if senderWaiting {
		t.Fatal("sender_waiting=true (expected false from fallback)")
	}
}

func TestFindSessionNotFound(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{}})
		},
	})
	t.Cleanup(server.Close)

	_, _, err := findSession(context.Background(), mustClient(t, server.URL), "nobody")
	if err == nil {
		t.Fatal("expected error for missing session")
	}
	if !strings.Contains(err.Error(), "no conversation found") {
		t.Fatalf("err=%s", err)
	}
}

func TestParseSSEEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event awid.SSEEvent
		check func(t *testing.T, ev Event)
	}{
		{
			name: "message event",
			event: awid.SSEEvent{
				Event: "message",
				Data:  `{"session_id":"s1","message_id":"m1","from_agent":"bob","body":"hello","sender_leaving":false,"hang_on":false,"extends_wait_seconds":0}`,
			},
			check: func(t *testing.T, ev Event) {
				if ev.Type != "message" {
					t.Fatalf("type=%s", ev.Type)
				}
				if ev.FromAgent != "bob" {
					t.Fatalf("from_agent=%s", ev.FromAgent)
				}
				if ev.Body != "hello" {
					t.Fatalf("body=%s", ev.Body)
				}
			},
		},
		{
			name: "read receipt event",
			event: awid.SSEEvent{
				Event: "read_receipt",
				Data:  `{"type":"read_receipt","reader_alias":"bob","extends_wait_seconds":60}`,
			},
			check: func(t *testing.T, ev Event) {
				if ev.Type != "read_receipt" {
					t.Fatalf("type=%s", ev.Type)
				}
				if ev.ReaderAlias != "bob" {
					t.Fatalf("reader_alias=%s", ev.ReaderAlias)
				}
				if ev.ExtendsWaitSeconds != 60 {
					t.Fatalf("extends_wait_seconds=%d", ev.ExtendsWaitSeconds)
				}
			},
		},
		{
			name: "extend wait event",
			event: awid.SSEEvent{
				Event: "message",
				Data:  `{"type":"message","from_agent":"bob","body":"thinking...","hang_on":true,"extends_wait_seconds":300}`,
			},
			check: func(t *testing.T, ev Event) {
				if !ev.ExtendWait {
					t.Fatal("extend_wait=false")
				}
				if ev.ExtendsWaitSeconds != 300 {
					t.Fatalf("extends_wait_seconds=%d", ev.ExtendsWaitSeconds)
				}
			},
		},
		{
			name: "from fallback",
			event: awid.SSEEvent{
				Event: "message",
				Data:  `{"from":"bob","body":"legacy"}`,
			},
			check: func(t *testing.T, ev Event) {
				if ev.FromAgent != "bob" {
					t.Fatalf("from_agent=%s (expected fallback from 'from')", ev.FromAgent)
				}
			},
		},
		{
			name: "invalid JSON",
			event: awid.SSEEvent{
				Event: "message",
				Data:  "not json",
			},
			check: func(t *testing.T, ev Event) {
				if ev.Type != "message" {
					t.Fatalf("type=%s (should preserve event type)", ev.Type)
				}
				if ev.FromAgent != "" {
					t.Fatalf("from_agent=%s (should be empty on parse error)", ev.FromAgent)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseSSEEvent(&tt.event)
			tt.check(t, ev)
		})
	}
}

func TestStreamToChannelCleansUpOnCancel(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	stream := awid.NewSSEStream(pr)
	defer pw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	events, cleanup := streamToChannel(ctx, stream)
	_ = events

	cancel()

	// cleanup must return (not hang), proving the goroutine exited.
	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not return — goroutine leaked")
	}
}

func TestStreamToChannelCleansUpWhileBlockedOnNext(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	stream := awid.NewSSEStream(pr)

	ctx, cancel := context.WithCancel(context.Background())
	events, cleanup := streamToChannel(ctx, stream)
	_ = events

	// Don't write anything — goroutine is blocked inside stream.Next().
	time.Sleep(50 * time.Millisecond)

	cancel()

	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()

	select {
	case <-done:
		// OK — goroutine unblocked from stream.Next() and exited.
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not return — goroutine stuck in stream.Next()")
	}

	pw.Close()
}

func TestStreamToChannelCleansUpWhenBufferFull(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	stream := awid.NewSSEStream(pr)

	// Write enough events to fill the channel buffer (capacity 10).
	go func() {
		for i := 0; i < 15; i++ {
			fmt.Fprintf(pw, "event: message\ndata: {\"i\":%d}\n\n", i)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	events, cleanup := streamToChannel(ctx, stream)
	_ = events // deliberately don't read

	// Give goroutine time to fill the buffer.
	time.Sleep(100 * time.Millisecond)

	cancel()

	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()

	select {
	case <-done:
		// OK — goroutine cleaned up even with full channel buffer.
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not return — goroutine leaked with full channel buffer")
	}

	pw.Close()
}

// --- Fix 1: WaitExplicit prevents sentinel upgrade ---

func TestSendStartConversationRespectsExplicitWait(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Reply immediately so we can check the timer was set to DefaultWait, not 300.
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "hi",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	// StartConversation=true, Wait=DefaultWait, WaitExplicit=true
	// Should wait DefaultWait seconds, NOT 300s.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Send(ctx, mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{
		Wait:              DefaultWait,
		WaitExplicit:      true,
		StartConversation: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSendStartConversationUpgradesWhenNotExplicit(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			<-time.After(10 * time.Second)
		},
	})
	t.Cleanup(server.Close)

	// Wait=1 with WaitExplicit=false + StartConversation=true should upgrade to 300s.
	// Without the upgrade the wait timer would fire at 1s and return "sent".
	// With the upgrade the wait is 300s, so the 2s context expires first.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := Send(ctx, mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{
		Wait:              1,
		WaitExplicit:      false,
		StartConversation: true,
	}, nil)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded (proving wait was upgraded past 1s), got %v", err)
	}
}

// --- Fix 2: Listen() ---

func TestListen(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, SenderWaiting: true},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Message from bob
			msgData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-1", "from_agent": "bob", "body": "are you there?",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msgData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Listen(ctx, mustClient(t, server.URL), "bob", DefaultWait, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "are you there?" {
		t.Fatalf("reply=%s", result.Reply)
	}
	if result.SessionID != "s1" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
}

func TestListenTimeout(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Send nothing, just keep connection open
			fmt.Fprintf(w, ": keepalive\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			<-time.After(10 * time.Second)
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Listen(ctx, mustClient(t, server.URL), "bob", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "timeout" {
		t.Fatalf("status=%s (expected 'timeout')", result.Status)
	}
	if result.WaitedSeconds < 1 {
		t.Fatalf("waited_seconds=%d", result.WaitedSeconds)
	}
}

func TestListenNoSession(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{}})
		},
	})
	t.Cleanup(server.Close)

	_, err := Listen(context.Background(), mustClient(t, server.URL), "nobody", DefaultWait, nil)
	if err == nil {
		t.Fatal("expected error for missing session")
	}
	if !strings.Contains(err.Error(), "no conversation found") {
		t.Fatalf("err=%s", err)
	}
}

func TestListenWithExtendWait(t *testing.T) {
	t.Parallel()

	var callbackCalls []string

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Extend-wait from bob
			hangOnData, _ := json.Marshal(map[string]any{
				"type": "message", "from_agent": "bob",
				"body": "thinking...", "hang_on": true, "extends_wait_seconds": 300,
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", hangOnData)
			if flusher != nil {
				flusher.Flush()
			}

			// Actual reply from bob
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "from_agent": "bob", "body": "here's my answer",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	callback := func(kind, msg string) {
		callbackCalls = append(callbackCalls, kind+": "+msg)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Listen(ctx, mustClient(t, server.URL), "bob", 5, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "here's my answer" {
		t.Fatalf("reply=%s", result.Reply)
	}

	foundExtendWait := false
	foundExtended := false
	for _, c := range callbackCalls {
		if strings.HasPrefix(c, "extend_wait:") {
			foundExtendWait = true
		}
		if strings.HasPrefix(c, "wait_extended:") {
			foundExtended = true
		}
	}
	if !foundExtendWait {
		t.Fatal("missing extend_wait callback")
	}
	if !foundExtended {
		t.Fatal("missing wait_extended callback")
	}
}

func TestExtendWaitWithoutExtensionFiresOneCallback(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	var callbackCalls []string

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Extend-wait without extension
			hangOnData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-hangon", "from_agent": "bob",
				"body": "working on it", "hang_on": true,
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", hangOnData)
			if flusher != nil {
				flusher.Flush()
			}

			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "done",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	callback := func(kind, msg string) {
		callbackCalls = append(callbackCalls, kind+": "+msg)
	}

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}

	// Should get exactly one extend_wait callback with the body, not a redundant second one
	extendWaitCount := 0
	for _, c := range callbackCalls {
		if strings.HasPrefix(c, "extend_wait:") {
			extendWaitCount++
		}
	}
	if extendWaitCount != 1 {
		t.Fatalf("expected exactly 1 extend_wait callback, got %d: %v", extendWaitCount, callbackCalls)
	}
}

func TestListenReturnsAnyMessage(t *testing.T) {
	t.Parallel()

	// In a multi-party session [alice, bob, charlie], listening for "bob"
	// should return when charlie sends a message (not filtered by target).
	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob", "charlie"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			msgData, _ := json.Marshal(map[string]any{
				"type": "message", "from_agent": "charlie", "body": "hello everyone",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msgData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Listen(ctx, mustClient(t, server.URL), "bob", DefaultWait, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "hello everyone" {
		t.Fatalf("reply=%s (expected message from charlie, not filtered)", result.Reply)
	}
}

// --- Fix 3: findSession prefers smallest matching session ---

func TestFindSessionPrefersSmallestPending(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s-group", Participants: []string{"alice", "bob", "charlie"}},
					{SessionID: "s-pair", Participants: []string{"alice", "bob"}},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	sessionID, _, err := findSession(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "s-pair" {
		t.Fatalf("session_id=%s, want s-pair (smallest matching session)", sessionID)
	}
}

func TestFindSessionPrefersSmallestFallback(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatListSessionsResponse{
				Sessions: []awid.ChatSessionItem{
					{SessionID: "s-group", Participants: []string{"alice", "bob", "charlie"}},
					{SessionID: "s-pair", Participants: []string{"alice", "bob"}},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	sessionID, _, err := findSession(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "s-pair" {
		t.Fatalf("session_id=%s, want s-pair (smallest matching session)", sessionID)
	}
}

func TestParseSSEEventSenderWaiting(t *testing.T) {
	t.Parallel()

	ev := parseSSEEvent(&awid.SSEEvent{
		Event: "message",
		Data:  `{"type":"message","from_agent":"bob","body":"hello","sender_waiting":true}`,
	})
	if !ev.SenderWaiting {
		t.Fatal("sender_waiting=false, want true")
	}

	// false when absent
	ev2 := parseSSEEvent(&awid.SSEEvent{
		Event: "message",
		Data:  `{"type":"message","from_agent":"bob","body":"hello"}`,
	})
	if ev2.SenderWaiting {
		t.Fatal("sender_waiting=true, want false when absent")
	}
}

func TestSendPropagatesSenderWaitingFromReply(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob",
				"body": "what do you think?", "sender_waiting": true,
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if !result.SenderWaiting {
		t.Fatal("result.SenderWaiting=false, want true from reply event")
	}
}

// --- SSE after parameter and events filtering ---

func TestSendPassesAfterParam(t *testing.T) {
	t.Parallel()

	var receivedAfter string
	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			receivedAfter = r.URL.Query().Get("after")
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply-1", "from_agent": "bob", "body": "hi back!",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	beforeSend := time.Now()
	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if receivedAfter == "" {
		t.Fatal("stream URL missing 'after' query parameter")
	}
	afterTime, err := time.Parse(time.RFC3339, receivedAfter)
	if err != nil {
		t.Fatalf("invalid after timestamp (want RFC3339): %s", receivedAfter)
	}
	// after is truncated to seconds and shifted back 1s, so allow 2s tolerance.
	if afterTime.Before(beforeSend.Add(-2 * time.Second)) {
		t.Fatalf("after=%s is too old (before send at %s)", afterTime, beforeSend)
	}
}

func TestListenNoAfterParam(t *testing.T) {
	t.Parallel()

	var receivedAfter string

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			receivedAfter = r.URL.Query().Get("after")
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			msgData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-1", "from_agent": "bob", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msgData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	result, err := Listen(context.Background(), mustClient(t, server.URL), "bob", DefaultWait, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if receivedAfter != "" {
		t.Fatalf("Listen should not pass 'after' param, got: %s", receivedAfter)
	}
}

func TestSendSkippedEventsNotInResult(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Replay: old message (before our sent message — will be skipped)
			oldData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "old-msg", "from_agent": "charlie", "body": "old stuff",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", oldData)

			// Replay: our sent message (will be skipped)
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)

			// Reply from bob (accepted)
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply-1", "from_agent": "bob", "body": "hi back!",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	// Only the reply should be in events, not the skipped replay messages
	if len(result.Events) != 1 {
		t.Fatalf("events count=%d, expected 1 (only the reply)", len(result.Events))
	}
	if result.Events[0].MessageID != "msg-reply-1" {
		t.Fatalf("event[0].message_id=%s, expected msg-reply-1", result.Events[0].MessageID)
	}
}

// TestSendAfterParameterUsesSecondPrecision verifies that the SSE stream
// after parameter is truncated to second precision (minus one second) so the
// server's replay query (WHERE created_at > $after) always includes the sent
// message. Without this, the sequential gate in the acceptor never opens.
func TestSendAfterParameterUsesSecondPrecision(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	var afterParam string

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, awid.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			afterParam = r.URL.Query().Get("after")

			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// With truncated after, the sent message IS in the replay.
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)

			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply-1", "from_agent": "bob", "body": "hi back!",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s, want replied", result.Status)
	}
	if result.Reply != "hi back!" {
		t.Fatalf("reply=%q, want %q", result.Reply, "hi back!")
	}

	// Verify the after parameter has second precision (no sub-second digits).
	if afterParam == "" {
		t.Fatal("after query parameter was empty")
	}
	if strings.Contains(afterParam, ".") {
		t.Errorf("after param %q has sub-second precision; want second precision", afterParam)
	}
	// Must parse as valid RFC3339.
	if _, err := time.Parse(time.RFC3339, afterParam); err != nil {
		t.Errorf("after param %q is not valid RFC3339: %v", afterParam, err)
	}
}

func TestParseSSEEventIdentityFields(t *testing.T) {
	t.Parallel()

	// Generate a real keypair to produce a valid signature.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	env := &awid.MessageEnvelope{
		From:    "alice",
		FromDID: did,
		Type:    "chat",
		Body:    "signed hello",
	}
	env.Timestamp = "2026-01-01T00:00:00Z"
	sig, err := awid.SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}

	data := fmt.Sprintf(`{"from_agent":"alice","body":"signed hello","from_did":%q,"signature":%q,"signing_key_id":%q,"timestamp":"2026-01-01T00:00:00Z"}`, did, sig, did)

	ev := parseSSEEvent(&awid.SSEEvent{
		Event: "message",
		Data:  data,
	})

	if ev.FromDID != did {
		t.Fatalf("from_did=%s", ev.FromDID)
	}
	if ev.Signature != sig {
		t.Fatalf("signature=%s", ev.Signature)
	}
	if ev.SigningKeyID != did {
		t.Fatalf("signing_key_id=%s", ev.SigningKeyID)
	}
	if ev.VerificationStatus != awid.Verified {
		t.Fatalf("verification_status=%s", ev.VerificationStatus)
	}
}

func TestParseSSEEventNoIdentityUnverified(t *testing.T) {
	t.Parallel()

	ev := parseSSEEvent(&awid.SSEEvent{
		Event: "message",
		Data:  `{"from_agent":"bob","body":"unsigned hello"}`,
	})

	if ev.FromDID != "" {
		t.Fatalf("from_did=%s", ev.FromDID)
	}
	if ev.VerificationStatus != awid.Unverified {
		t.Fatalf("verification_status=%s, want %s", ev.VerificationStatus, awid.Unverified)
	}
}

func TestParseSSEEventUsesFromAddressForVerification(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	// Sign with full address.
	env := &awid.MessageEnvelope{
		From:      "myco/alice",
		FromDID:   did,
		Type:      "chat",
		Body:      "signed hello",
		Timestamp: "2026-01-01T00:00:00Z",
	}
	sig, err := awid.SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}

	// SSE data has from_agent="alice" (alias-only) but from_address="myco/alice".
	data := fmt.Sprintf(`{"from_agent":"alice","from_address":"myco/alice","body":"signed hello","from_did":%q,"signature":%q,"signing_key_id":%q,"timestamp":"2026-01-01T00:00:00Z"}`, did, sig, did)

	ev := parseSSEEvent(&awid.SSEEvent{
		Event: "message",
		Data:  data,
	})

	if ev.FromAddress != "myco/alice" {
		t.Fatalf("from_address=%q, want myco/alice", ev.FromAddress)
	}
	// Verification should succeed because From in envelope uses from_address.
	if ev.VerificationStatus != awid.Verified {
		t.Fatalf("verification_status=%s, want verified (from_address should be used)", ev.VerificationStatus)
	}
}

func TestParseSSEEventWiresIsContact(t *testing.T) {
	t.Parallel()

	data := `{"from_agent":"alice","body":"hi","timestamp":"2025-01-01T00:00:00Z","is_contact":true}`
	ev := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: data})
	if ev.IsContact == nil || !*ev.IsContact {
		t.Fatalf("IsContact=%v, want ptr to true", ev.IsContact)
	}

	// false case
	data2 := `{"from_agent":"bob","body":"hey","timestamp":"2025-01-01T00:00:00Z","is_contact":false}`
	ev2 := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: data2})
	if ev2.IsContact == nil || *ev2.IsContact {
		t.Fatalf("IsContact=%v, want ptr to false", ev2.IsContact)
	}

	// absent case
	data3 := `{"from_agent":"carol","body":"yo","timestamp":"2025-01-01T00:00:00Z"}`
	ev3 := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: data3})
	if ev3.IsContact != nil {
		t.Fatalf("IsContact=%v, want nil", ev3.IsContact)
	}
}

func TestBuildMessagesWiresIsContact(t *testing.T) {
	t.Parallel()

	yes := true
	msgs := []awid.ChatMessage{
		{MessageID: "m1", FromAgent: "alice", Body: "hi", IsContact: &yes},
		{MessageID: "m2", FromAgent: "bob", Body: "hey", IsContact: nil},
	}
	events := buildMessages(msgs)
	if events[0].IsContact == nil || !*events[0].IsContact {
		t.Fatalf("events[0].IsContact=%v, want ptr to true", events[0].IsContact)
	}
	if events[1].IsContact != nil {
		t.Fatalf("events[1].IsContact=%v, want nil", events[1].IsContact)
	}
}
