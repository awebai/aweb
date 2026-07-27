package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func chatMarkReadTestIDs() []string {
	return []string{
		"00000000-0000-4000-8000-000000000001",
		"00000000-0000-4000-8000-000000000002",
		"00000000-0000-4000-8000-000000000003",
	}
}

func TestChatMarkReadFallsBackToOldServerWatermarkSemantics(t *testing.T) {
	available := chatMarkReadTestIDs()
	presented := []string{available[0], available[2]}
	read := map[string]bool{}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if calls == 1 {
			var got []string
			if err := json.Unmarshal(body["message_ids"], &got); err != nil {
				t.Fatalf("decode message_ids: %v", err)
			}
			if !reflect.DeepEqual(got, presented) {
				t.Fatalf("message_ids=%v, want %v", got, presented)
			}
			if _, exists := body["up_to_message_id"]; exists {
				t.Fatal("exact request unexpectedly included up_to_message_id")
			}
			http.Error(w, "old validation shape", http.StatusUnprocessableEntity)
			return
		}

		if _, exists := body["message_ids"]; exists {
			t.Fatal("fallback unexpectedly included message_ids")
		}
		var watermark string
		if err := json.Unmarshal(body["up_to_message_id"], &watermark); err != nil {
			t.Fatalf("decode up_to_message_id: %v", err)
		}
		if watermark != presented[len(presented)-1] {
			t.Fatalf("watermark=%q, want newest presented %q", watermark, presented[len(presented)-1])
		}
		for _, messageID := range available {
			read[messageID] = true
			if messageID == watermark {
				break
			}
		}
		_ = json.NewEncoder(w).Encode(ChatMarkReadResponse{Success: true, MessagesMarked: len(read)})
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.ChatMarkRead(context.Background(), "session-old", &ChatMarkReadRequest{MessageIDs: presented})
	if err != nil {
		t.Fatalf("old-server fallback must succeed after the exact request is rejected: %v", err)
	}
	if calls != 2 {
		t.Fatalf("requests=%d, want exact request plus one fallback", calls)
	}
	if response.MessagesMarked != 3 {
		t.Fatalf("messages_marked=%d, want watermark range of 3", response.MessagesMarked)
	}
	if !read[available[1]] {
		t.Fatal("unpresented gap was not marked: old-server watermark semantics were not reproduced")
	}
}

func TestChatMarkReadUsesOneExactRequestOnNewServer(t *testing.T) {
	ids := chatMarkReadTestIDs()[:2]
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		var got []string
		if err := json.Unmarshal(body["message_ids"], &got); err != nil {
			t.Fatalf("decode message_ids: %v", err)
		}
		if !reflect.DeepEqual(got, ids) {
			t.Fatalf("message_ids=%v, want %v", got, ids)
		}
		if _, exists := body["up_to_message_id"]; exists {
			t.Fatal("new-server request unexpectedly included watermark")
		}
		_ = json.NewEncoder(w).Encode(ChatMarkReadResponse{Success: true, MessagesMarked: len(got)})
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.ChatMarkRead(context.Background(), "session-new", &ChatMarkReadRequest{MessageIDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("requests=%d, want exactly one", calls)
	}
	if response.MessagesMarked != len(ids) {
		t.Fatalf("messages_marked=%d, want %d", response.MessagesMarked, len(ids))
	}
}

func TestChatMarkReadMalformedIDReachesServerWithoutFallback(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "authoritative malformed uuid", http.StatusUnprocessableEntity)
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ChatMarkRead(context.Background(), "session-bad", &ChatMarkReadRequest{MessageIDs: []string{"not-a-uuid"}})
	if err == nil || !strings.Contains(err.Error(), "authoritative malformed uuid") {
		t.Fatalf("error=%v, want original server validation error", err)
	}
	if calls != 1 {
		t.Fatalf("requests=%d, want exactly one authoritative request", calls)
	}
}

func TestChatMarkReadFailedFallbackPreservesOriginal4xx(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "original permission error", http.StatusForbidden)
			return
		}
		http.Error(w, "fallback failed", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ChatMarkRead(context.Background(), "session-denied", &ChatMarkReadRequest{MessageIDs: chatMarkReadTestIDs()[:1]})
	if err == nil {
		t.Fatal("expected original 4xx")
	}
	status, ok := HTTPStatusCode(err)
	if !ok || status != http.StatusForbidden {
		t.Fatalf("status=(%d,%v), want original 403", status, ok)
	}
	if !strings.Contains(err.Error(), "original permission error") || strings.Contains(err.Error(), "fallback failed") {
		t.Fatalf("error=%q, want only original failure", err)
	}
	if calls != 2 {
		t.Fatalf("requests=%d, want one exact request and one fallback", calls)
	}
}
