package awid

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

type stubIdentityResolver struct {
	resolve func(context.Context, string) (*ResolvedIdentity, error)
	verify  func(context.Context, string, string) *StableIdentityVerification
}

func (r stubIdentityResolver) Resolve(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	if r.resolve == nil {
		return nil, context.Canceled
	}
	return r.resolve(ctx, identifier)
}

func (r stubIdentityResolver) VerifyStableIdentity(ctx context.Context, address, stableID string) *StableIdentityVerification {
	if r.verify == nil {
		return nil
	}
	return r.verify(ctx, address, stableID)
}

func TestCertAuthSignPayloadDoesNotHTMLEscapeAndPreservesUnicode(t *testing.T) {
	t.Parallel()

	body := []byte(`{"ok":true}`)
	timestamp := "2026-04-07T12:00:00Z"
	teamID := "backend:tést.example/<a&b>"

	got := string(certAuthSignPayload(teamID, timestamp, body))

	h := sha256.Sum256(body)
	want := `{"body_sha256":"` + hex.EncodeToString(h[:]) + `","team_id":"backend:tést.example/<a&b>","timestamp":"2026-04-07T12:00:00Z"}`
	if got != want {
		t.Fatalf("got:  %s\nwant: %s", got, want)
	}
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u003e`) || strings.Contains(got, `\u0026`) {
		t.Fatalf("payload still HTML-escaped: %s", got)
	}
}

func TestChatStreamRequestsEventStream(t *testing.T) {
	t.Parallel()

	var gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message\ndata: {\"ok\":true}\n\n"))
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := c.ChatStream(context.Background(), "sess", time.Now().Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	if gotAccept != "text/event-stream" {
		t.Fatalf("accept=%q", gotAccept)
	}

	ev, err := stream.Next()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "message" {
		t.Fatalf("event=%q", ev.Event)
	}
	if !strings.Contains(ev.Data, "\"ok\":true") {
		t.Fatalf("data=%q", ev.Data)
	}
}

func TestChatCreateSessionSignsDeterministicTo(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody ChatCreateSessionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/chat/sessions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(ChatCreateSessionResponse{
			SessionID:        "sess-1",
			MessageID:        "msg-1",
			Participants:     []ChatParticipant{{AgentID: "a", Alias: "agent"}, {AgentID: "b", Alias: "bob"}},
			SSEURL:           "/v1/chat/sessions/sess-1/stream",
			TargetsConnected: []string{"bob"},
			TargetsLeft:      []string{},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{
		ToAliases: []string{"bob", "ann"},
		Message:   "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody.Signature == "" || gotBody.Timestamp == "" || gotBody.MessageID == "" {
		t.Fatalf("missing identity fields in request: %+v", gotBody)
	}

	env := &MessageEnvelope{
		From:      "agent",
		FromDID:   did,
		To:        "ann,bob",
		Type:      "chat",
		Body:      "hello",
		Timestamp: gotBody.Timestamp,
		MessageID: gotBody.MessageID,
		Signature: gotBody.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatCreateSessionSignsLocalAliases(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody ChatCreateSessionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(ChatCreateSessionResponse{SessionID: "sess-1", MessageID: "msg-1"})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{
		ToAliases: []string{"bob", "ann"},
		Message:   "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	env := &MessageEnvelope{
		From:      "agent",
		FromDID:   did,
		To:        "ann,bob",
		Type:      "chat",
		Body:      "hello",
		Timestamp: gotBody.Timestamp,
		MessageID: gotBody.MessageID,
		Signature: gotBody.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatCreateSessionDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/sessions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ChatCreateSessionResponse{
			SessionID:        "sess-1",
			MessageID:        "msg-1",
			TargetsConnected: []string{"bob"},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	req := &ChatCreateSessionRequest{
		ToAliases: []string{"bob"},
		Message:   "hello",
	}
	_, err = c.ChatCreateSession(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	if req.FromDID != "" || req.Signature != "" || req.MessageID != "" || req.Timestamp != "" {
		t.Fatalf("input request was mutated: %+v", req)
	}
	if len(req.ToAliases) != 1 || req.ToAliases[0] != "bob" {
		t.Fatalf("to_aliases changed: %+v", req.ToAliases)
	}
}

func TestChatSendMessageSignsDeterministicTo(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotSend ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{
					{SessionID: "sess-1", Participants: []string{"agent", "ann", "bob"}, CreatedAt: "2026-02-01T00:00:00Z"},
				},
			})
		case "/v1/chat/sessions/sess-1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotSend); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
				MessageID:          "msg-2",
				Delivered:          true,
				ExtendsWaitSeconds: 0,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{Body: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	if gotSend.Signature == "" || gotSend.Timestamp == "" || gotSend.MessageID == "" {
		t.Fatalf("missing identity fields in request: %+v", gotSend)
	}

	env := &MessageEnvelope{
		From:      "agent",
		FromDID:   did,
		To:        "ann,bob",
		Type:      "chat",
		Body:      "ping",
		Timestamp: gotSend.Timestamp,
		MessageID: gotSend.MessageID,
		Signature: gotSend.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatSendMessageSignsLocalAliases(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotSend ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{
					{SessionID: "sess-1", Participants: []string{"ann", "bob"}, CreatedAt: "2026-02-01T00:00:00Z"},
				},
			})
		case "/v1/chat/sessions/sess-1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotSend); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
				MessageID: "msg-2",
				Delivered: true,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{Body: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	env := &MessageEnvelope{
		From:      "agent",
		FromDID:   did,
		To:        "ann,bob",
		Type:      "chat",
		Body:      "ping",
		Timestamp: gotSend.Timestamp,
		MessageID: gotSend.MessageID,
		Signature: gotSend.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatSendMessagePrefersParticipantAddressesForDeterministicTo(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotSend ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{
					{
						SessionID:            "sess-1",
						Participants:         []string{"monitor"},
						ParticipantAddresses: []string{"otherco/monitor"},
						CreatedAt:            "2026-02-01T00:00:00Z",
					},
				},
			})
		case "/v1/chat/sessions/sess-1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotSend); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
				MessageID:          "msg-2",
				Delivered:          true,
				ExtendsWaitSeconds: 0,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("example.com/rose")

	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{Body: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	env := &MessageEnvelope{
		From:      "rose",
		FromDID:   did,
		To:        "otherco/monitor",
		Type:      "chat",
		Body:      "ping",
		Timestamp: gotSend.Timestamp,
		MessageID: gotSend.MessageID,
		Signature: gotSend.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatSendMessageUsesParticipantStableDIDsForDeterministicTo(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotSend ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{
					{
						SessionID:       "sess-1",
						Participants:    []string{""},
						ParticipantDIDs: []string{"did:aw:monitor"},
						CreatedAt:       "2026-02-01T00:00:00Z",
					},
				},
			})
		case "/v1/chat/sessions/sess-1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotSend); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
				MessageID:          "msg-2",
				Delivered:          true,
				ExtendsWaitSeconds: 0,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("example.com/rose")

	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{Body: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	env := &MessageEnvelope{
		From:      "rose",
		FromDID:   did,
		To:        "did:aw:monitor",
		Type:      "chat",
		Body:      "ping",
		Timestamp: gotSend.Timestamp,
		MessageID: gotSend.MessageID,
		Signature: gotSend.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatSendMessageRemovesOneSelfStableDIDFromDeterministicTo(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	var gotSend ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{
					{
						SessionID:       "sess-1",
						Participants:    []string{"", ""},
						ParticipantDIDs: []string{stableID, "did:aw:monitor"},
						CreatedAt:       "2026-02-01T00:00:00Z",
					},
				},
			})
		case "/v1/chat/sessions/sess-1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotSend); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
				MessageID:          "msg-2",
				Delivered:          true,
				ExtendsWaitSeconds: 0,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetStableID(stableID)
	c.SetAddress("example.com/rose")

	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{Body: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	env := &MessageEnvelope{
		From:         "rose",
		FromDID:      did,
		FromStableID: stableID,
		To:           "did:aw:monitor",
		Type:         "chat",
		Body:         "ping",
		Timestamp:    gotSend.Timestamp,
		MessageID:    gotSend.MessageID,
		Signature:    gotSend.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified (self stable DID should be removed from deterministic To)", status)
	}
}

func TestChatSendMessageRemovesOneSelfCurrentDIDFromDeterministicTo(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	var gotSend ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{
					{
						SessionID:       "sess-1",
						Participants:    []string{"", ""},
						ParticipantDIDs: []string{did, "did:aw:monitor"},
						CreatedAt:       "2026-02-01T00:00:00Z",
					},
				},
			})
		case "/v1/chat/sessions/sess-1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotSend); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
				MessageID:          "msg-2",
				Delivered:          true,
				ExtendsWaitSeconds: 0,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetStableID(stableID)
	c.SetAddress("example.com/rose")

	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{Body: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	env := &MessageEnvelope{
		From:         "rose",
		FromDID:      did,
		FromStableID: stableID,
		To:           "did:aw:monitor",
		Type:         "chat",
		Body:         "ping",
		Timestamp:    gotSend.Timestamp,
		MessageID:    gotSend.MessageID,
		Signature:    gotSend.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified (self current DID should be removed from deterministic To)", status)
	}
}

func TestChatSendMessageRemovesOneSelfAddressFromDeterministicTo(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotSend ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{
					{
						SessionID:            "sess-1",
						Participants:         []string{"", ""},
						ParticipantAddresses: []string{"example.com/rose", "otherco/monitor"},
						CreatedAt:            "2026-02-01T00:00:00Z",
					},
				},
			})
		case "/v1/chat/sessions/sess-1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotSend); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
				MessageID:          "msg-2",
				Delivered:          true,
				ExtendsWaitSeconds: 0,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("example.com/rose")

	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{Body: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	env := &MessageEnvelope{
		From:      "rose",
		FromDID:   did,
		To:        "otherco/monitor",
		Type:      "chat",
		Body:      "ping",
		Timestamp: gotSend.Timestamp,
		MessageID: gotSend.MessageID,
		Signature: gotSend.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified (self address should be removed from deterministic To)", status)
	}
}

func TestChatSendMessageRetainsForeignParticipantWithSameAliasAsSelf(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotSend ChatSendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{
					{
						SessionID:    "sess-1",
						Participants: []string{"rose", "rose"},
						CreatedAt:    "2026-02-01T00:00:00Z",
					},
				},
			})
		case "/v1/chat/sessions/sess-1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotSend); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
				MessageID: "msg-2",
				Delivered: true,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("example.com/rose")

	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{Body: "ping"})
	if err != nil {
		t.Fatal(err)
	}

	env := &MessageEnvelope{
		From:      "rose",
		FromDID:   did,
		To:        "rose",
		Type:      "chat",
		Body:      "ping",
		Timestamp: gotSend.Timestamp,
		MessageID: gotSend.MessageID,
		Signature: gotSend.Signature,
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified (foreign same-alias participant should remain in deterministic To)", status)
	}
}

func TestChatSendMessageDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
				Sessions: []ChatSessionItem{{SessionID: "sess-1", Participants: []string{"agent", "bob"}}},
			})
		case "/v1/chat/sessions/sess-1/messages":
			_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{MessageID: "msg-2", Delivered: true})
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	req := &ChatSendMessageRequest{Body: "ping", ExtendWait: true}
	_, err = c.ChatSendMessage(context.Background(), "sess-1", req)
	if err != nil {
		t.Fatal(err)
	}
	if req.FromDID != "" || req.Signature != "" || req.MessageID != "" || req.Timestamp != "" {
		t.Fatalf("input request was mutated: %+v", req)
	}
	if !req.ExtendWait {
		t.Fatal("extend_wait flag changed on input")
	}
}

func TestChatSendMessage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/chat/sessions/test-session/messages" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		var body ChatSendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Body != "hello" {
			t.Fatalf("body=%q", body.Body)
		}
		_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
			MessageID:          "msg-1",
			Delivered:          true,
			ExtendsWaitSeconds: 0,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatSendMessage(context.Background(), "test-session", &ChatSendMessageRequest{Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.MessageID != "msg-1" {
		t.Fatalf("message_id=%s", resp.MessageID)
	}
	if !resp.Delivered {
		t.Fatal("delivered=false")
	}
}

func TestChatSendMessageExtendWait(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body ChatSendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !body.ExtendWait {
			t.Fatal("expected extend_wait=true")
		}
		_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
			MessageID:          "msg-2",
			Delivered:          true,
			ExtendsWaitSeconds: 300,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatSendMessage(context.Background(), "test-session", &ChatSendMessageRequest{
		Body:       "thinking...",
		ExtendWait: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ExtendsWaitSeconds != 300 {
		t.Fatalf("extends_wait_seconds=%d", resp.ExtendsWaitSeconds)
	}
}

func TestChatListSessions(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/chat/sessions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
			Sessions: []ChatSessionItem{
				{SessionID: "s1", Participants: []string{"alice", "bob"}, CreatedAt: "2025-01-01T00:00:00Z"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Sessions) != 1 {
		t.Fatalf("sessions=%d", len(resp.Sessions))
	}
	if resp.Sessions[0].SessionID != "s1" {
		t.Fatalf("session_id=%s", resp.Sessions[0].SessionID)
	}
	if len(resp.Sessions[0].Participants) != 2 {
		t.Fatalf("participants=%d", len(resp.Sessions[0].Participants))
	}
}

func TestChatPendingItemNullTimeRemaining(t *testing.T) {
	t.Parallel()

	raw := `{"session_id":"s1","participants":["a","b"],"last_message":"hi","last_from":"a","unread_count":1,"last_activity":"2025-01-01T00:00:00Z","sender_waiting":false,"time_remaining_seconds":null}`
	var item ChatPendingItem
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		t.Fatal(err)
	}
	if item.TimeRemainingSeconds != nil {
		t.Fatalf("expected nil, got %d", *item.TimeRemainingSeconds)
	}

	raw2 := `{"session_id":"s1","participants":["a","b"],"last_message":"hi","last_from":"a","unread_count":1,"last_activity":"2025-01-01T00:00:00Z","sender_waiting":true,"time_remaining_seconds":42}`
	var item2 ChatPendingItem
	if err := json.Unmarshal([]byte(raw2), &item2); err != nil {
		t.Fatal(err)
	}
	if item2.TimeRemainingSeconds == nil || *item2.TimeRemainingSeconds != 42 {
		t.Fatalf("expected 42, got %v", item2.TimeRemainingSeconds)
	}
}

func TestHTTPStatusHelpers(t *testing.T) {
	t.Parallel()

	err := &APIError{StatusCode: 404, Body: "not found"}
	status, ok := HTTPStatusCode(err)
	if !ok || status != 404 {
		t.Fatalf("status=(%d,%v)", status, ok)
	}
	body, ok := HTTPErrorBody(err)
	if !ok || body != "not found" {
		t.Fatalf("body=(%q,%v)", body, ok)
	}

	status, ok = HTTPStatusCode(context.DeadlineExceeded)
	if ok || status != 0 {
		t.Fatalf("non-api status=(%d,%v)", status, ok)
	}
	body, ok = HTTPErrorBody(context.Canceled)
	if ok || body != "" {
		t.Fatalf("non-api body=(%q,%v)", body, ok)
	}
}

func TestNewWithIdentitySetsFields(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	c, err := NewWithIdentity("http://localhost:8000", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	if c.SigningKey() == nil {
		t.Fatal("SigningKey is nil")
	}
	if !c.SigningKey().Equal(priv) {
		t.Fatal("SigningKey does not match")
	}
	if c.DID() != did {
		t.Fatalf("DID=%q, want %q", c.DID(), did)
	}
}

func TestNewWithIdentityValidation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	if _, err := NewWithIdentity("http://localhost:8000", nil, did); err == nil {
		t.Fatal("expected error for nil signingKey")
	}
	if _, err := NewWithIdentity("http://localhost:8000", priv, ""); err == nil {
		t.Fatal("expected error for empty did")
	}
	if _, err := NewWithIdentity("http://localhost:8000", priv, "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"); err == nil {
		t.Fatal("expected error for mismatched did")
	}
}

func TestNewLeavesIdentityNil(t *testing.T) {
	t.Parallel()

	c, err := New("http://localhost:8000")
	if err != nil {
		t.Fatal(err)
	}
	if c.SigningKey() != nil {
		t.Fatal("expected nil SigningKey for unsigned client")
	}
	if c.DID() != "" {
		t.Fatalf("expected empty DID for unsigned client, got %q", c.DID())
	}
}

func TestPutHelper(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]string
	if err := c.Put(context.Background(), "/v1/agents/me/rotate", map[string]string{"key": "val"}, &out); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method=%s, want PUT", gotMethod)
	}
	if gotPath != "/v1/agents/me/rotate" {
		t.Fatalf("path=%s", gotPath)
	}
	if out["status"] != "ok" {
		t.Fatalf("status=%q", out["status"])
	}
	if gotBody["key"] != "val" {
		t.Fatalf("body key=%q, want %q", gotBody["key"], "val")
	}
}

func TestDeregister(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Deregister(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method=%s, want DELETE", gotMethod)
	}
	if gotPath != "/v1/agents/me" {
		t.Fatalf("path=%s, want /v1/agents/me", gotPath)
	}
}

func TestDeregisterAgent(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeregisterAgent(context.Background(), "mycompany", "researcher"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method=%s, want DELETE", gotMethod)
	}
	if gotPath != "/v1/agents/mycompany/researcher" {
		t.Fatalf("path=%s, want /v1/agents/mycompany/researcher", gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("auth=%q", gotAuth)
	}
}

func TestSendMessageSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	resp, err := c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Subject: "task complete",
		Body:    "results attached",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.MessageID != "msg-1" {
		t.Fatalf("MessageID=%q", resp.MessageID)
	}

	// Verify identity fields are present.
	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v, want %s", gotBody["from_did"], did)
	}
	if ts, ok := gotBody["timestamp"].(string); !ok || ts == "" {
		t.Fatal("timestamp missing or empty")
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing or empty")
	}

	// Verify using signed_payload from the request body.
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing or empty in request body")
	}
	status, err := VerifySignedPayload(sp, sig, did, did)
	if err != nil {
		t.Fatalf("VerifySignedPayload: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

// TestSendMessageIncludesSignedPayload verifies that self-custodial messages
// include the signed_payload field, and that verification succeeds using it
// even when from_address differs from the signed from.
func TestSendMessageIncludesSignedPayload(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-03-17T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myteam.aweb.ai/alice")
	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "myteam.aweb.ai/bob",
		Subject: "hello",
		Body:    "world",
	})
	if err != nil {
		t.Fatal(err)
	}

	// signed_payload must be present in the request body.
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing or empty in request body")
	}

	// Verify using signed_payload directly — even though from_address
	// would be different (server would return "alice" not "myteam.aweb.ai/alice").
	sig := gotBody["signature"].(string)
	status, err := VerifySignedPayload(sp, sig, did, did)
	if err != nil {
		t.Fatalf("VerifySignedPayload: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

// TestSendMessageSignsCanonicalToForPlainAlias verifies that same-project local
// mail signs plain local names rather than external namespace addresses.
func TestSendMessageSignsCanonicalToForPlainAlias(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "monitor",
		Subject: "task complete",
		Body:    "results attached",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Same-project local delivery verifies against the signed_payload returned
	// by the client (which contains the canonical envelope JSON).
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing or empty in request body")
	}
	sig := gotBody["signature"].(string)
	status, verifyErr := VerifySignedPayload(sp, sig, did, did)
	if verifyErr != nil {
		t.Fatalf("VerifySignedPayload: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified (plain alias 'monitor' should be signed as local 'monitor')", status)
	}
}

func TestSendMessageSignsLocalAlias(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "monitor",
		Subject: "task complete",
		Body:    "results attached",
	})
	if err != nil {
		t.Fatal(err)
	}

	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing or empty in request body")
	}
	sig := gotBody["signature"].(string)
	status, verifyErr := VerifySignedPayload(sp, sig, did, did)
	if verifyErr != nil {
		t.Fatalf("VerifySignedPayload: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestSendMessageNoSignatureWithoutIdentity(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Identity fields should not be present.
	if _, exists := gotBody["from_did"]; exists {
		t.Fatal("from_did should not be set for unsigned client")
	}
	if _, exists := gotBody["signature"]; exists {
		t.Fatal("signature should not be set for unsigned client")
	}
	if _, exists := gotBody["signing_key_id"]; exists {
		t.Fatal("signing_key_id should not be set for unsigned client")
	}
}

func TestSendMessageSignsWithToAgentID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAgentID: "agent-uuid-123",
		Subject:   "task complete",
		Body:      "results attached",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify using signed_payload from the request body.
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing or empty in request body")
	}
	sig := gotBody["signature"].(string)
	status, err := VerifySignedPayload(sp, sig, did, did)
	if err != nil {
		t.Fatalf("VerifySignedPayload: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestSendMessageByIdentityUsesToDID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	recipientDID := "did:aw:recipient-123"

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-04-10T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	c.SetStableID(stableID)

	_, err = c.SendMessageByIdentity(context.Background(), &SendMessageRequest{
		ToDID: recipientDID,
		Body:  "hello direct",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["to_did"] != recipientDID {
		t.Fatalf("to_did=%v", gotBody["to_did"])
	}
	if gotBody["to_address"] != nil {
		t.Fatalf("to_address should be absent, got %v", gotBody["to_address"])
	}
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing")
	}
	sig := gotBody["signature"].(string)
	status, err := VerifySignedPayload(sp, sig, did, did)
	if err != nil {
		t.Fatalf("VerifySignedPayload: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestSendMessageByIdentityStableTargetSignsResolvedRecipientBinding(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	recipientStableID := "did:aw:recipient-123"
	recipientCurrentDID := "did:key:z6MkrRecipientCurrent"

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-04-10T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	c.SetStableID(stableID)
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			if identifier != recipientStableID {
				t.Fatalf("resolve identifier=%q", identifier)
			}
			return &ResolvedIdentity{
				DID:      recipientCurrentDID,
				StableID: recipientStableID,
			}, nil
		},
	})

	_, err = c.SendMessageByIdentity(context.Background(), &SendMessageRequest{
		ToDID: recipientStableID,
		Body:  "hello direct",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["to_did"] != recipientStableID {
		t.Fatalf("wire to_did=%v, want stable target %q", gotBody["to_did"], recipientStableID)
	}
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing")
	}
	var env MessageEnvelope
	if err := json.Unmarshal([]byte(sp), &env); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	if env.ToDID != recipientCurrentDID {
		t.Fatalf("signed payload to_did=%q, want resolved current did %q", env.ToDID, recipientCurrentDID)
	}
	if env.ToStableID != recipientStableID {
		t.Fatalf("signed payload to_stable_id=%q, want %q", env.ToStableID, recipientStableID)
	}
}

func TestSendMessageByIdentityStableTargetWithoutResolverOmitsCurrentRecipientBinding(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	recipientStableID := "did:aw:recipient-123"

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-04-10T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	c.SetStableID(stableID)

	_, err = c.SendMessageByIdentity(context.Background(), &SendMessageRequest{
		ToDID: recipientStableID,
		Body:  "hello direct",
	})
	if err != nil {
		t.Fatal(err)
	}

	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing")
	}
	var env MessageEnvelope
	if err := json.Unmarshal([]byte(sp), &env); err != nil {
		t.Fatalf("unmarshal signed_payload: %v", err)
	}
	if env.ToDID != "" {
		t.Fatalf("signed payload to_did=%q, want empty without resolver", env.ToDID)
	}
	if env.ToStableID != recipientStableID {
		t.Fatalf("signed payload to_stable_id=%q, want %q", env.ToStableID, recipientStableID)
	}
}

func TestSendMessageByIdentityUsesToAddress(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-04-10T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.SendMessageByIdentity(context.Background(), &SendMessageRequest{
		ToAddress: "otherco/monitor",
		Body:      "hello address",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["to_address"] != "otherco/monitor" {
		t.Fatalf("to_address=%v", gotBody["to_address"])
	}
}

func TestSendMessageDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	req := &SendMessageRequest{
		ToAlias:  "bob",
		Subject:  "hi",
		Body:     "there",
		Priority: PriorityHigh,
	}
	_, err = c.SendMessage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if req.FromDID != "" || req.Signature != "" || req.MessageID != "" {
		t.Fatalf("input request was mutated: %+v", req)
	}
	if req.ToAlias != "bob" || req.Subject != "hi" || req.Body != "there" {
		t.Fatalf("input request fields changed: %+v", req)
	}
}

func TestChatCreateSessionSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session_id": "sess-1",
			"message_id": "msg-1",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{
		ToAliases: []string{"otherco/monitor"},
		Message:   "hey",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v", gotBody["from_did"])
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing")
	}

	// Verify the signature using signed_payload from the request body.
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing or empty in request body")
	}
	status, err := VerifySignedPayload(sp, sig, did, did)
	if err != nil {
		t.Fatalf("VerifySignedPayload: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatCreateSessionSupportsIdentityTargets(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session_id": "sess-1",
			"message_id": "msg-1",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{
		ToDIDs:  []string{"did:aw:b", "did:aw:a"},
		Message: "hello direct chat",
	})
	if err != nil {
		t.Fatal(err)
	}

	dids, ok := gotBody["to_dids"].([]any)
	if !ok || len(dids) != 2 {
		t.Fatalf("to_dids=%v", gotBody["to_dids"])
	}
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing")
	}
	sig := gotBody["signature"].(string)
	status, err := VerifySignedPayload(sp, sig, did, did)
	if err != nil {
		t.Fatalf("VerifySignedPayload: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatSendMessageSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message_id": "msg-1",
			"delivered":  true,
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{
		Body: "message in chat",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v", gotBody["from_did"])
	}
	if gotBody["signature"] == nil || gotBody["signature"] == "" {
		t.Fatal("signature missing")
	}
}

func TestInboxVerifiesSignedMessages(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	// Build a valid signed envelope.
	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		To:        "otherco/monitor",
		Type:      "mail",
		Subject:   "hello",
		Body:      "world",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-1",
	}
	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent_id":  "agent-uuid",
				"from_alias":     "myco/agent",
				"to_alias":       "otherco/monitor",
				"subject":        "hello",
				"body":           "world",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       did,
				"to_did":         "",
				"signature":      sig,
				"signing_key_id": did,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("len=%d", len(resp.Messages))
	}
	msg := resp.Messages[0]
	if msg.VerificationStatus != Verified {
		t.Fatalf("VerificationStatus=%q, want verified", msg.VerificationStatus)
	}
}

func TestInboxUnverifiedWithoutDID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":    "msg-1",
				"from_agent_id": "agent-uuid",
				"from_alias":    "myco/agent",
				"subject":       "hello",
				"body":          "world",
				"priority":      "normal",
				"created_at":    "2026-02-22T00:00:00Z",
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	msg := resp.Messages[0]
	if msg.VerificationStatus != Unverified {
		t.Fatalf("VerificationStatus=%q, want unverified", msg.VerificationStatus)
	}
}

func TestInboxFailedBadSignature(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent_id":  "agent-uuid",
				"from_alias":     "myco/agent",
				"subject":        "hello",
				"body":           "world",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       did,
				"signature":      "dGhpcyBpcyBhIGJhZCBzaWduYXR1cmU", // invalid sig
				"signing_key_id": did,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	msg := resp.Messages[0]
	if msg.VerificationStatus != Failed {
		t.Fatalf("VerificationStatus=%q, want failed", msg.VerificationStatus)
	}
}

func TestChatHistoryVerifiesSignedMessages(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		To:        "",
		Type:      "chat",
		Subject:   "",
		Body:      "hello chat",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-1",
	}
	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent":     "myco/agent",
				"body":           "hello chat",
				"timestamp":      "2026-02-22T00:00:00Z",
				"from_did":       did,
				"signature":      sig,
				"signing_key_id": did,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatHistory(context.Background(), ChatHistoryParams{SessionID: "sess-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("len=%d", len(resp.Messages))
	}
	msg := resp.Messages[0]
	if msg.VerificationStatus != Verified {
		t.Fatalf("VerificationStatus=%q, want verified", msg.VerificationStatus)
	}
}

func TestRotateKeySendsSignedRequest(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(pub)

	newPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/agents/me/rotate" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":         "rotated",
			"old_did":        oldDID,
			"new_did":        newDID,
			"new_public_key": gotBody["new_public_key"].(string),
			"custody":        CustodySelf,
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, oldDID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.RotateKey(context.Background(), &RotateKeyRequest{
		NewDID:       newDID,
		NewPublicKey: newPub,
		Custody:      CustodySelf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.OldDID != oldDID {
		t.Fatalf("OldDID=%q", resp.OldDID)
	}
	if resp.NewDID != newDID {
		t.Fatalf("NewDID=%q", resp.NewDID)
	}
	if resp.Status != "rotated" {
		t.Fatalf("Status=%q", resp.Status)
	}
	if resp.Custody != CustodySelf {
		t.Fatalf("Custody=%q", resp.Custody)
	}
	if resp.NewPublicKey == "" {
		t.Fatal("NewPublicKey empty")
	}

	// Verify request fields.
	if gotBody["new_did"] != newDID {
		t.Fatalf("new_did=%v", gotBody["new_did"])
	}
	if gotBody["custody"] != CustodySelf {
		t.Fatalf("custody=%v", gotBody["custody"])
	}
	// Verify rotation_signature is present.
	rotSig, ok := gotBody["rotation_signature"].(string)
	if !ok || rotSig == "" {
		t.Fatal("rotation_signature missing")
	}
	if gotBody["new_public_key"] == nil || gotBody["new_public_key"] == "" {
		t.Fatal("new_public_key missing")
	}
	// Verify new_public_key is base64url encoded.
	npk := gotBody["new_public_key"].(string)
	if _, err := base64.RawURLEncoding.DecodeString(npk); err != nil {
		t.Fatalf("new_public_key not base64url: %v", err)
	}

	// Verify the rotation signature using the old public key.
	status, err := VerifyRotationSignature(pub, oldDID, newDID, gotBody["timestamp"].(string), rotSig)
	if err != nil {
		t.Fatalf("VerifyRotationSignature: %v", err)
	}
	if !status {
		t.Fatal("rotation signature invalid")
	}
}

func TestRotateKeyCustodialOmitsKeyMaterial(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "rotated",
			"new_did": "did:key:z6MkServerGenerated",
			"custody": CustodyCustodial,
		})
	}))
	t.Cleanup(server.Close)

	// Custodial client: no signing key.
	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.RotateKeyCustodial(context.Background(), &RotateKeyCustodialRequest{
		Custody: CustodyCustodial,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify key material is absent.
	if _, ok := gotBody["new_did"]; ok {
		t.Fatal("custodial rotation should not include new_did")
	}
	if _, ok := gotBody["new_public_key"]; ok {
		t.Fatal("custodial rotation should not include new_public_key")
	}
	if _, ok := gotBody["rotation_signature"]; ok {
		t.Fatal("custodial rotation should not include rotation_signature")
	}
	if gotBody["custody"] != CustodyCustodial {
		t.Fatalf("custody=%v", gotBody["custody"])
	}
	if gotBody["timestamp"] == nil || gotBody["timestamp"] == "" {
		t.Fatal("timestamp missing")
	}

	if resp.Status != "rotated" {
		t.Fatalf("Status=%q", resp.Status)
	}
	if resp.Custody != CustodyCustodial {
		t.Fatalf("Custody=%q", resp.Custody)
	}
}

func TestRotateKeyRequiresIdentity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server")
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RotateKey(context.Background(), &RotateKeyRequest{
		NewDID:  "did:key:z6MkTest",
		Custody: CustodySelf,
	})
	if err == nil {
		t.Fatal("expected error for unsigned client")
	}
}

func TestAgentLogSelf(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/agents/me/log" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("auth=%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{
				{
					"operation": "create",
					"did":       "did:key:z6MkOldKey",
					"timestamp": "2026-03-15T10:00:00Z",
					"signed_by": "did:key:z6MkOldKey",
				},
				{
					"operation": "rotate",
					"old_did":   "did:key:z6MkOldKey",
					"new_did":   "did:key:z6MkNewKey",
					"timestamp": "2026-06-01T12:00:00Z",
					"signed_by": "did:key:z6MkOldKey",
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.AgentLog(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("entries=%d", len(resp.Entries))
	}
	if resp.Entries[0].Operation != "create" {
		t.Fatalf("entry[0].operation=%s", resp.Entries[0].Operation)
	}
	if resp.Entries[0].DID != "did:key:z6MkOldKey" {
		t.Fatalf("entry[0].did=%s", resp.Entries[0].DID)
	}
	if resp.Entries[1].Operation != "rotate" {
		t.Fatalf("entry[1].operation=%s", resp.Entries[1].Operation)
	}
	if resp.Entries[1].OldDID != "did:key:z6MkOldKey" {
		t.Fatalf("entry[1].old_did=%s", resp.Entries[1].OldDID)
	}
	if resp.Entries[1].NewDID != "did:key:z6MkNewKey" {
		t.Fatalf("entry[1].new_did=%s", resp.Entries[1].NewDID)
	}
	if resp.Entries[1].SignedBy != "did:key:z6MkOldKey" {
		t.Fatalf("entry[1].signed_by=%s", resp.Entries[1].SignedBy)
	}
}

func TestAgentLogPeer(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/agents/acme/bot/log" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{
				{
					"operation": "create",
					"did":       "did:key:z6MkPeer",
					"timestamp": "2026-01-01T00:00:00Z",
					"signed_by": "did:key:z6MkPeer",
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.AgentLog(context.Background(), "acme/bot")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("entries=%d", len(resp.Entries))
	}
	if resp.Entries[0].DID != "did:key:z6MkPeer" {
		t.Fatalf("entry[0].did=%s", resp.Entries[0].DID)
	}
}

func TestSendMessageIncludesMessageID(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(priv.Public().(ed25519.PublicKey))

	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"message_id": "server-returned-id"})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/bot",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// message_id should be a valid UUID v4 generated by signEnvelope.
	msgID := gotBody["message_id"]
	if msgID == "" {
		t.Fatal("message_id is empty")
	}
	uuidRE := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRE.MatchString(msgID) {
		t.Fatalf("message_id=%q is not a valid UUID v4", msgID)
	}
}

func TestSendMessageNoMessageIDWithoutIdentity(t *testing.T) {
	t.Parallel()

	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"message_id": "server-generated"})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/bot",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Without identity, message_id should be empty (server generates it).
	if gotBody["message_id"] != "" {
		t.Fatalf("message_id=%q, expected empty for custodial client", gotBody["message_id"])
	}
}

func TestSendMessageResolvesRecipientDID(t *testing.T) {
	t.Parallel()

	// Sender identity.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	// Recipient identity.
	recipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := ComputeDIDKey(recipientPub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/messages":
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			if identifier != "otherco/monitor" {
				t.Fatalf("identifier=%q", identifier)
			}
			return &ResolvedIdentity{DID: recipientDID, Address: identifier}, nil
		},
	})

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = recipientDID

	// Verify the signature using signed_payload from the request body.
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing or empty in request body")
	}
	sig := gotBody["signature"].(string)
	status, verifyErr := VerifySignedPayload(sp, sig, did, did)
	if verifyErr != nil {
		t.Fatalf("VerifySignedPayload: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestSendMessageUsesIdentityAuthHeadersWithoutTeamCert(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := "did:aw:test-alice"

	var gotAuth string
	var gotTimestamp string
	var gotStableID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = strings.TrimSpace(r.Header.Get("Authorization"))
		gotTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		gotStableID = strings.TrimSpace(r.Header.Get("X-AWEB-DID-AW"))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetStableID(stableID)
	c.SetAddress("myco/agent")

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotAuth == "" {
		t.Fatal("missing Authorization header")
	}
	if gotTimestamp == "" {
		t.Fatal("missing X-AWEB-Timestamp header")
	}
	if gotStableID != stableID {
		t.Fatalf("X-AWEB-DID-AW=%q want %q", gotStableID, stableID)
	}
}

func TestInboxUsesIdentityAuthHeadersWithoutTeamCert(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := "did:aw:test-alice"

	var gotAuth string
	var gotTimestamp string
	var gotStableID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = strings.TrimSpace(r.Header.Get("Authorization"))
		gotTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		gotStableID = strings.TrimSpace(r.Header.Get("X-AWEB-DID-AW"))
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{}})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetStableID(stableID)

	_, err = c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}

	if gotAuth == "" {
		t.Fatal("missing Authorization header")
	}
	if gotTimestamp == "" {
		t.Fatal("missing X-AWEB-Timestamp header")
	}
	if gotStableID != stableID {
		t.Fatalf("X-AWEB-DID-AW=%q want %q", gotStableID, stableID)
	}
}

func TestInboxRecipientBindingMismatch(t *testing.T) {
	t.Parallel()

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	// Message signed with wrong to_did (not the receiver's DID).
	wrongRecipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongRecipientDID := ComputeDIDKey(wrongRecipientPub)

	// The receiver's actual DID.
	receiverPub, receiverPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverDID := ComputeDIDKey(receiverPub)
	_ = receiverPriv // not used for signing, only for identity

	env := &MessageEnvelope{
		From:      "sender/agent",
		FromDID:   senderDID,
		To:        "receiver/agent",
		ToDID:     wrongRecipientDID,
		Type:      "mail",
		Subject:   "test",
		Body:      "misrouted",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent_id":  "agent-uuid",
				"from_alias":     "sender/agent",
				"to_alias":       "receiver/agent",
				"subject":        "test",
				"body":           "misrouted",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       senderDID,
				"to_did":         wrongRecipientDID,
				"signature":      sig,
				"signing_key_id": senderDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	// Create receiver client with identity — to_did won't match.
	c, err := NewWithIdentity(server.URL, receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("len=%d", len(resp.Messages))
	}
	// Signature is valid but to_did doesn't match receiver → IdentityMismatch.
	msg := resp.Messages[0]
	if msg.VerificationStatus != IdentityMismatch {
		t.Fatalf("VerificationStatus=%q, want identity_mismatch", msg.VerificationStatus)
	}
}

func TestSendMessageNoResolverLeavesToDIDEmpty(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	// No resolver set — to_did should remain empty.

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify to_did is absent on the wire.
	if v, ok := gotBody["to_did"]; ok {
		t.Fatalf("to_did should be absent on wire, got %v", v)
	}

	// Verify signature is valid without to_did, using signed_payload from request.
	sp, ok := gotBody["signed_payload"].(string)
	if !ok || sp == "" {
		t.Fatal("signed_payload missing or empty in request body")
	}
	sig := gotBody["signature"].(string)
	status, verifyErr := VerifySignedPayload(sp, sig, did, did)
	if verifyErr != nil {
		t.Fatalf("VerifySignedPayload: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestInboxTOFUPinFirstContact(t *testing.T) {
	t.Parallel()

	// Generate sender identity and sign a message.
	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   senderDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "hello",
		Body:      "first contact",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-tofu-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:    "msg-tofu-1",
				FromAgentID:  "agent-1",
				FromAlias:    "otherco/sender",
				ToAlias:      "myco/agent",
				Subject:      "hello",
				Body:         "first contact",
				CreatedAt:    env.Timestamp,
				FromDID:      senderDID,
				Signature:    sig,
				SigningKeyID: senderDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("status=%s, want verified", resp.Messages[0].VerificationStatus)
	}

	// Pin should have been created.
	if _, ok := ps.Pins[senderDID]; !ok {
		t.Fatal("pin should have been created for sender DID")
	}
	if ps.Addresses["otherco/sender"] != senderDID {
		t.Fatalf("address reverse index should map to sender DID, got %q", ps.Addresses["otherco/sender"])
	}
	firstSeen := ps.Pins[senderDID].FirstSeen

	// Second contact — same sender, same DID → should stay Verified and update last_seen.
	resp, err = c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("returning contact: status=%s, want verified", resp.Messages[0].VerificationStatus)
	}
	if ps.Pins[senderDID].FirstSeen != firstSeen {
		t.Fatal("first_seen should not change on returning contact")
	}
}

func TestInboxTOFUPinMismatch(t *testing.T) {
	t.Parallel()

	// Original sender.
	senderPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	originalDID := ComputeDIDKey(senderPub)

	// Impostor with different key claiming same address.
	impostorPub, impostorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	impostorDID := ComputeDIDKey(impostorPub)

	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   impostorDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "hello",
		Body:      "impostor message",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-impostor-1",
	}
	sig, err := SignMessage(impostorPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:    "msg-impostor-1",
				FromAgentID:  "agent-1",
				FromAlias:    "otherco/sender",
				ToAlias:      "myco/agent",
				Subject:      "hello",
				Body:         "impostor message",
				CreatedAt:    env.Timestamp,
				FromDID:      impostorDID,
				Signature:    sig,
				SigningKeyID: impostorDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-pin the original DID for this address.
	ps := NewPinStore()
	ps.StorePin(originalDID, "otherco/sender", "", "")

	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}
	// Signature is valid for impostorDID, but TOFU pin expects originalDID → mismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch", resp.Messages[0].VerificationStatus)
	}
}

func TestInboxRotationAnnouncementAccepted(t *testing.T) {
	t.Parallel()

	// Old key (currently pinned).
	oldPub, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)

	// New key (sender has rotated to this).
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	// Create the rotation announcement: old key signs {new_did, old_did, timestamp}.
	rotationTS := time.Now().UTC().Format(time.RFC3339)
	rotationPayload := CanonicalRotationJSON(oldDID, newDID, rotationTS)
	rotationSig := ed25519.Sign(oldPriv, []byte(rotationPayload))
	rotationSigStr := base64.RawStdEncoding.EncodeToString(rotationSig)

	// Message signed by the new key.
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   newDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "post-rotation",
		Body:      "hello after rotation",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-rotated-1",
	}
	sig, err := SignMessage(newPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:    "msg-rotated-1",
				FromAgentID:  "agent-1",
				FromAlias:    "otherco/sender",
				ToAlias:      "myco/agent",
				Subject:      "post-rotation",
				Body:         "hello after rotation",
				CreatedAt:    env.Timestamp,
				FromDID:      newDID,
				Signature:    sig,
				SigningKeyID: newDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          oldDID,
					NewDID:          newDID,
					Timestamp:       rotationTS,
					OldKeySignature: rotationSigStr,
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-pin the old DID.
	ps := NewPinStore()
	ps.StorePin(oldDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// Rotation announcement is valid → message should be accepted as Verified.
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("status=%s, want verified (rotation should be accepted)", resp.Messages[0].VerificationStatus)
	}

	// Pin should be updated to the new DID.
	if ps.Addresses["otherco/sender"] != newDID {
		t.Fatalf("pin should be updated to new DID, got %q", ps.Addresses["otherco/sender"])
	}
	if _, ok := ps.Pins[newDID]; !ok {
		t.Fatal("new DID should be pinned")
	}
	// Old DID's pin entry should be cleaned up.
	if _, ok := ps.Pins[oldDID]; ok {
		t.Fatal("old DID pin entry should be removed after rotation")
	}
}

func TestInboxRotationAnnouncementInvalid(t *testing.T) {
	t.Parallel()

	// Old key (currently pinned).
	oldPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)

	// New key (sender claims rotation).
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	// Forged rotation announcement: new key signs (not old key).
	rotationTS := time.Now().UTC().Format(time.RFC3339)
	rotationPayload := CanonicalRotationJSON(oldDID, newDID, rotationTS)
	forgedSig := ed25519.Sign(newPriv, []byte(rotationPayload)) // Wrong key!
	forgedSigStr := base64.RawStdEncoding.EncodeToString(forgedSig)

	// Message signed by the new key.
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   newDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "forged rotation",
		Body:      "should be rejected",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-forged-rot-1",
	}
	sig, err := SignMessage(newPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:    "msg-forged-rot-1",
				FromAgentID:  "agent-1",
				FromAlias:    "otherco/sender",
				ToAlias:      "myco/agent",
				Subject:      "forged rotation",
				Body:         "should be rejected",
				CreatedAt:    env.Timestamp,
				FromDID:      newDID,
				Signature:    sig,
				SigningKeyID: newDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          oldDID,
					NewDID:          newDID,
					Timestamp:       rotationTS,
					OldKeySignature: forgedSigStr,
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-pin the old DID.
	ps := NewPinStore()
	ps.StorePin(oldDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// Forged announcement → IdentityMismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch (forged rotation)", resp.Messages[0].VerificationStatus)
	}

	// Pin should NOT be updated.
	if ps.Addresses["otherco/sender"] != oldDID {
		t.Fatalf("pin should remain old DID, got %q", ps.Addresses["otherco/sender"])
	}
}

func TestInboxRotationAnnouncementUnrelatedOldDID(t *testing.T) {
	t.Parallel()

	// Pinned key (the real sender).
	pinnedPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pinnedDID := ComputeDIDKey(pinnedPub)

	// Attacker's key (unrelated to the pinned identity).
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	attackerDID := ComputeDIDKey(attackerPriv.Public().(ed25519.PublicKey))

	// New key the attacker wants to rotate to.
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	// Attacker crafts a rotation announcement from their own key (not the pinned one).
	// The signature is valid (attacker signs with their own key), but old_did != pinned DID.
	rotationTS := time.Now().UTC().Format(time.RFC3339)
	rotationPayload := CanonicalRotationJSON(attackerDID, newDID, rotationTS)
	rotationSig := ed25519.Sign(attackerPriv, []byte(rotationPayload))
	rotationSigStr := base64.RawStdEncoding.EncodeToString(rotationSig)

	// Message signed by the new key.
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   newDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "hijack attempt",
		Body:      "attacker tries to take over",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-hijack-1",
	}
	sig, err := SignMessage(newPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:    "msg-hijack-1",
				FromAgentID:  "agent-1",
				FromAlias:    "otherco/sender",
				ToAlias:      "myco/agent",
				Subject:      "hijack attempt",
				Body:         "attacker tries to take over",
				CreatedAt:    env.Timestamp,
				FromDID:      newDID,
				Signature:    sig,
				SigningKeyID: newDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          attackerDID, // NOT the pinned DID!
					NewDID:          newDID,
					Timestamp:       rotationTS,
					OldKeySignature: rotationSigStr,
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	// Pin the REAL sender's DID.
	ps := NewPinStore()
	ps.StorePin(pinnedDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// Rotation announcement has valid signature but old_did != pinned DID → IdentityMismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch (old_did doesn't match pinned DID)", resp.Messages[0].VerificationStatus)
	}

	// Pin must NOT be updated to the attacker's new DID.
	if ps.Addresses["otherco/sender"] != pinnedDID {
		t.Fatalf("pin should remain pinned DID, got %q", ps.Addresses["otherco/sender"])
	}
}

func TestInboxRotationAnnouncementNewDIDMismatch(t *testing.T) {
	t.Parallel()

	// Old key (currently pinned).
	oldPub, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)

	// The DID declared in the rotation announcement (ra.NewDID).
	declaredPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	declaredDID := ComputeDIDKey(declaredPub)

	// The actual sender key (from_did in the message) — differs from ra.NewDID.
	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	// Rotation announcement: old key signs old→declared (not old→sender).
	rotationTS := time.Now().UTC().Format(time.RFC3339)
	rotationPayload := CanonicalRotationJSON(oldDID, declaredDID, rotationTS)
	rotationSig := ed25519.Sign(oldPriv, []byte(rotationPayload))
	rotationSigStr := base64.RawStdEncoding.EncodeToString(rotationSig)

	// Message signed by the actual sender (from_did = senderDID ≠ ra.NewDID).
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   senderDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "mismatch test",
		Body:      "new_did != from_did",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-newdid-mismatch-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:    "msg-newdid-mismatch-1",
				FromAgentID:  "agent-1",
				FromAlias:    "otherco/sender",
				ToAlias:      "myco/agent",
				Subject:      "mismatch test",
				Body:         "new_did != from_did",
				CreatedAt:    env.Timestamp,
				FromDID:      senderDID,
				Signature:    sig,
				SigningKeyID: senderDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          oldDID,
					NewDID:          declaredDID, // Different from from_did!
					Timestamp:       rotationTS,
					OldKeySignature: rotationSigStr,
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	ps := NewPinStore()
	ps.StorePin(oldDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// ra.NewDID != from_did → rotation rejected → IdentityMismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch (ra.NewDID != from_did)", resp.Messages[0].VerificationStatus)
	}
}

func TestInboxRotationAnnouncementEmptyFields(t *testing.T) {
	t.Parallel()

	// Old key (currently pinned).
	oldPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)

	// New key.
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	// Message signed by the new key.
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   newDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "empty fields test",
		Body:      "rotation with missing fields",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-empty-rot-1",
	}
	sig, err := SignMessage(newPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:    "msg-empty-rot-1",
				FromAgentID:  "agent-1",
				FromAlias:    "otherco/sender",
				ToAlias:      "myco/agent",
				Subject:      "empty fields test",
				Body:         "rotation with missing fields",
				CreatedAt:    env.Timestamp,
				FromDID:      newDID,
				Signature:    sig,
				SigningKeyID: newDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          oldDID,
					NewDID:          newDID,
					Timestamp:       "", // Missing timestamp!
					OldKeySignature: "", // Missing signature!
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	ps := NewPinStore()
	ps.StorePin(oldDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// Malformed rotation announcement → IdentityMismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch (empty rotation fields)", resp.Messages[0].VerificationStatus)
	}

	// Pin must NOT be updated.
	if ps.Addresses["otherco/sender"] != oldDID {
		t.Fatalf("pin should remain old DID, got %q", ps.Addresses["otherco/sender"])
	}
}

func TestInboxUsesFromAddressForVerification(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	// Sign envelope with full address (namespace/alias).
	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		To:        "otherco/monitor",
		Type:      "mail",
		Subject:   "hello",
		Body:      "world",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-1",
	}
	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent_id":  "agent-uuid",
				"from_alias":     "agent",
				"to_alias":       "monitor",
				"from_address":   "myco/agent",
				"to_address":     "otherco/monitor",
				"subject":        "hello",
				"body":           "world",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       did,
				"to_did":         "",
				"signature":      sig,
				"signing_key_id": did,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("len=%d", len(resp.Messages))
	}
	msg := resp.Messages[0]
	// Signed with from_address="myco/agent", so verification should succeed
	// only if Inbox uses from_address (not from_alias="agent").
	if msg.VerificationStatus != Verified {
		t.Fatalf("VerificationStatus=%q, want verified (from_address should be used)", msg.VerificationStatus)
	}
}

func TestChatHistoryUsesFromAddressForVerification(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		Type:      "chat",
		Body:      "hi there",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-chat-1",
	}
	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-chat-1",
				"from_agent":     "agent",
				"from_address":   "myco/agent",
				"body":           "hi there",
				"timestamp":      "2026-02-22T00:00:00Z",
				"from_did":       did,
				"signature":      sig,
				"signing_key_id": did,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatHistory(context.Background(), ChatHistoryParams{SessionID: "sess-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("len=%d", len(resp.Messages))
	}
	msg := resp.Messages[0]
	// Signed with from="myco/agent", so verification should succeed
	// only if ChatHistory uses from_address (not from_agent="agent").
	if msg.VerificationStatus != Verified {
		t.Fatalf("VerificationStatus=%q, want verified (from_address should be used)", msg.VerificationStatus)
	}
}

func TestCheckTOFUPinEphemeralSkipsPinning(t *testing.T) {
	t.Parallel()

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	env := &MessageEnvelope{
		From:      "myco/ephemeral-bot",
		FromDID:   senderDID,
		To:        "myco/monitor",
		Type:      "mail",
		Subject:   "hello",
		Body:      "ephemeral message",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-eph-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-eph-1",
				"from_agent_id":  "agent-uuid-1",
				"from_alias":     "myco/ephemeral-bot",
				"from_address":   "myco/ephemeral-bot",
				"to_alias":       "myco/monitor",
				"to_address":     "myco/monitor",
				"subject":        "hello",
				"body":           "ephemeral message",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       senderDID,
				"signature":      sig,
				"signing_key_id": senderDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	ps.StorePin("did:key:stale", "myco/ephemeral-bot", "", "")
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			if identifier != "myco/ephemeral-bot" {
				t.Fatalf("identifier=%q", identifier)
			}
			return &ResolvedIdentity{
				DID:         senderDID,
				Address:     identifier,
				Lifetime:    "ephemeral",
				Custody:     "self",
				ResolvedVia: "registry",
			}, nil
		},
	})

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	inboxMsg := resp.Messages[0]
	if inboxMsg.VerificationStatus != Verified {
		t.Fatalf("VerificationStatus=%q, want verified", inboxMsg.VerificationStatus)
	}
	// Pin should NOT have been created for ephemeral agent.
	if _, ok := ps.Pins[senderDID]; ok {
		t.Fatal("ephemeral agent should not be pinned")
	}
	if _, ok := ps.Addresses["myco/ephemeral-bot"]; ok {
		t.Fatal("ephemeral agent should not remain in address index")
	}
	if _, ok := ps.Pins["did:key:stale"]; ok {
		t.Fatal("stale ephemeral pin should be pruned")
	}
}

func TestCheckTOFUPinCustodialReturnsVerifiedCustodial(t *testing.T) {
	t.Parallel()

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	env := &MessageEnvelope{
		From:      "myco/custodial-bot",
		FromDID:   senderDID,
		To:        "myco/monitor",
		Type:      "mail",
		Subject:   "hello",
		Body:      "custodial message",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-cust-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-cust-1",
				"from_agent_id":  "agent-uuid-2",
				"from_alias":     "myco/custodial-bot",
				"from_address":   "myco/custodial-bot",
				"to_alias":       "myco/monitor",
				"to_address":     "myco/monitor",
				"subject":        "hello",
				"body":           "custodial message",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       senderDID,
				"signature":      sig,
				"signing_key_id": senderDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			if identifier != "myco/custodial-bot" {
				t.Fatalf("identifier=%q", identifier)
			}
			return &ResolvedIdentity{
				DID:         senderDID,
				Address:     identifier,
				Lifetime:    "persistent",
				Custody:     "custodial",
				ResolvedVia: "registry",
			}, nil
		},
	})

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	custMsg := resp.Messages[0]
	if custMsg.VerificationStatus != VerifiedCustodial {
		t.Fatalf("VerificationStatus=%q, want verified_custodial", custMsg.VerificationStatus)
	}
}

func TestCheckTOFUPinResolverCachesResults(t *testing.T) {
	t.Parallel()

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	env := &MessageEnvelope{
		From:      "myco/cached-bot",
		FromDID:   senderDID,
		To:        "myco/monitor",
		Type:      "mail",
		Subject:   "hello",
		Body:      "cached test",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-cache-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	resolveCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-cache-1",
				"from_agent_id":  "agent-uuid-3",
				"from_alias":     "myco/cached-bot",
				"from_address":   "myco/cached-bot",
				"to_alias":       "myco/monitor",
				"to_address":     "myco/monitor",
				"subject":        "hello",
				"body":           "cached test",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       senderDID,
				"signature":      sig,
				"signing_key_id": senderDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			resolveCount++
			if identifier != "myco/cached-bot" {
				t.Fatalf("identifier=%q", identifier)
			}
			return &ResolvedIdentity{
				DID:         senderDID,
				Address:     identifier,
				Lifetime:    "persistent",
				Custody:     "self",
				ResolvedVia: "registry",
			}, nil
		},
	})

	// First call: should resolve.
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("first call: status=%q", resp.Messages[0].VerificationStatus)
	}

	// Second call: should use cache (no additional resolve).
	_, err = c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}

	if resolveCount != 1 {
		t.Fatalf("resolveCount=%d, want 1 (second call should use cache)", resolveCount)
	}
}

func TestCheckTOFUPinResolverFailureNotCached(t *testing.T) {
	t.Parallel()

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	env := &MessageEnvelope{
		From:      "myco/flaky-bot",
		FromDID:   senderDID,
		To:        "myco/monitor",
		Type:      "mail",
		Subject:   "hello",
		Body:      "flaky test",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-flaky-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	resolveCount := 0
	resolverFail := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-flaky-1",
				"from_agent_id":  "agent-uuid-flaky",
				"from_alias":     "myco/flaky-bot",
				"from_address":   "myco/flaky-bot",
				"to_alias":       "myco/monitor",
				"to_address":     "myco/monitor",
				"subject":        "hello",
				"body":           "flaky test",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       senderDID,
				"signature":      sig,
				"signing_key_id": senderDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			resolveCount++
			if identifier != "myco/flaky-bot" {
				t.Fatalf("identifier=%q", identifier)
			}
			if resolverFail {
				return nil, context.DeadlineExceeded
			}
			return &ResolvedIdentity{
				DID:         senderDID,
				Address:     identifier,
				Lifetime:    "persistent",
				Custody:     "custodial",
				ResolvedVia: "registry",
			}, nil
		},
	})

	// First call: resolver fails → status remains verified, and the failure is not cached.
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("first call: status=%q, want verified", resp.Messages[0].VerificationStatus)
	}
	if resolveCount != 1 {
		t.Fatalf("resolveCount=%d after first call", resolveCount)
	}

	// Second call: resolver now succeeds → should retry (failure not cached).
	resolverFail = false
	resp, err = c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if resolveCount != 2 {
		t.Fatalf("resolveCount=%d, want 2 (failure should not be cached)", resolveCount)
	}
	// Now that resolver succeeds, custodial custody should be detected.
	if resp.Messages[0].VerificationStatus != VerifiedCustodial {
		t.Fatalf("second call: status=%q, want verified_custodial", resp.Messages[0].VerificationStatus)
	}
}

func TestInboxCanonicalizesLocalAliasBeforeTOFUPin(t *testing.T) {
	t.Parallel()

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	env := &MessageEnvelope{
		From:      "architect",
		FromDID:   senderDID,
		To:        "implementer",
		Type:      "mail",
		Subject:   "hello",
		Body:      "world",
		Timestamp: "2026-03-24T13:17:17Z",
		MessageID: "msg-local-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	resolvePaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-local-1",
				"from_agent_id":  "identity-uuid-1",
				"from_alias":     "architect",
				"from_address":   "architect",
				"to_alias":       "implementer",
				"to_address":     "implementer",
				"subject":        "hello",
				"body":           "world",
				"priority":       "normal",
				"created_at":     "2026-03-24T13:17:17Z",
				"from_did":       senderDID,
				"signature":      sig,
				"signing_key_id": senderDID,
				"is_contact":     false,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myteam/implementer")
	ps := NewPinStore()
	ps.StorePin("did:aw:old-architect", "architect", "", "")
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			resolvePaths = append(resolvePaths, identifier)
			if identifier != "myteam/architect" {
				return nil, context.Canceled
			}
			return &ResolvedIdentity{
				DID:         senderDID,
				Address:     identifier,
				Lifetime:    "ephemeral",
				Custody:     "self",
				ResolvedVia: "registry",
			}, nil
		},
	})

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("status=%q, want verified", resp.Messages[0].VerificationStatus)
	}
	if resp.Messages[0].IsContact != nil {
		t.Fatalf("ephemeral sender should suppress contact tag, got %v", *resp.Messages[0].IsContact)
	}
	if len(resolvePaths) != 1 || resolvePaths[0] != "myteam/architect" {
		t.Fatalf("resolvePaths=%v, want [myteam/architect]", resolvePaths)
	}
	if _, ok := ps.Addresses["myteam/architect"]; ok {
		t.Fatalf("ephemeral sender should not be pinned under canonical address")
	}
	if _, ok := ps.Addresses["architect"]; ok {
		t.Fatalf("legacy bare alias pin should be pruned for ephemeral sender")
	}
}

func TestChatHistoryCanonicalizesLocalAliasBeforeTOFUPin(t *testing.T) {
	t.Parallel()

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	env := &MessageEnvelope{
		From:      "architect",
		FromDID:   senderDID,
		To:        "implementer",
		Type:      "chat",
		Body:      "hello",
		Timestamp: "2026-03-24T13:12:05Z",
		MessageID: "msg-chat-local-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	resolvePaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-chat-local-1",
				"from_agent":     "architect",
				"from_address":   "architect",
				"to_address":     "implementer",
				"body":           "hello",
				"timestamp":      "2026-03-24T13:12:05Z",
				"from_did":       senderDID,
				"signature":      sig,
				"signing_key_id": senderDID,
				"is_contact":     false,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myteam/implementer")
	ps := NewPinStore()
	ps.StorePin("did:aw:old-architect", "architect", "", "")
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			resolvePaths = append(resolvePaths, identifier)
			if identifier != "myteam/architect" {
				return nil, context.Canceled
			}
			return &ResolvedIdentity{
				DID:         senderDID,
				Address:     identifier,
				Lifetime:    "ephemeral",
				Custody:     "self",
				ResolvedVia: "registry",
			}, nil
		},
	})

	resp, err := c.ChatHistory(context.Background(), ChatHistoryParams{SessionID: "sess-1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("status=%q, want verified", resp.Messages[0].VerificationStatus)
	}
	if resp.Messages[0].IsContact != nil {
		t.Fatalf("ephemeral sender should suppress contact tag, got %v", *resp.Messages[0].IsContact)
	}
	if len(resolvePaths) != 1 || resolvePaths[0] != "myteam/architect" {
		t.Fatalf("resolvePaths=%v, want [myteam/architect]", resolvePaths)
	}
	if _, ok := ps.Addresses["myteam/architect"]; ok {
		t.Fatalf("ephemeral sender should not be pinned under canonical address")
	}
	if _, ok := ps.Addresses["architect"]; ok {
		t.Fatalf("legacy bare alias pin should be pruned for ephemeral sender")
	}
}

func TestCheckTOFUPinUpgradeOnFirstSight(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	c, err := New("http://localhost")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")

	// Step 1: First message without stable_id → pin by did:key (Phase-1).
	status := c.CheckTOFUPin(context.Background(), Verified, "myco/sender", senderDID, "", nil, nil)
	if status != Verified {
		t.Fatalf("step 1: status=%q, want %q", status, Verified)
	}
	if ps.Addresses["myco/sender"] != senderDID {
		t.Fatalf("step 1: address should map to did:key, got %q", ps.Addresses["myco/sender"])
	}

	// Step 2: Next message WITH stable_id and matching did:key → upgrade pin.
	status = c.CheckTOFUPin(context.Background(), Verified, "myco/sender", senderDID, stableID, nil, nil)
	if status != Verified {
		t.Fatalf("step 2: status=%q, want %q", status, Verified)
	}

	// Pin should now be keyed by stable_id.
	if _, ok := ps.Pins[stableID]; !ok {
		t.Fatal("step 2: pin should be upgraded to stable_id key")
	}
	if _, ok := ps.Pins[senderDID]; ok {
		t.Fatal("step 2: old did:key pin should be removed after upgrade")
	}
	if ps.Addresses["myco/sender"] != stableID {
		t.Fatalf("step 2: address should map to stable_id, got %q", ps.Addresses["myco/sender"])
	}
}

func TestCheckTOFUPinAcceptsValidReplacementAnnouncement(t *testing.T) {
	t.Parallel()

	// Setup: old agent pinned at address, new agent with replacement announcement
	oldPub, _, _ := ed25519.GenerateKey(nil)
	newPub, _, _ := ed25519.GenerateKey(nil)
	controllerPub, controllerPriv, _ := ed25519.GenerateKey(nil)

	oldDID := ComputeDIDKey(oldPub)
	newDID := ComputeDIDKey(newPub)
	controllerDID := ComputeDIDKey(controllerPub)
	address := "acme.com/billing"
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Sign the replacement announcement
	payload := CanonicalReplacementJSON(address, controllerDID, oldDID, newDID, timestamp)
	sig := ed25519.Sign(controllerPriv, []byte(payload))
	sigB64 := base64.RawStdEncoding.EncodeToString(sig)

	repl := &ReplacementAnnouncement{
		Address:             address,
		OldDID:              oldDID,
		NewDID:              newDID,
		ControllerDID:       controllerDID,
		Timestamp:           timestamp,
		ControllerSignature: sigB64,
	}

	c, _ := New("http://localhost")
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			if identifier != address {
				t.Fatalf("identifier=%q", identifier)
			}
			return &ResolvedIdentity{DID: newDID, Address: address, ControllerDID: controllerDID}, nil
		},
	})

	// Pin the old DID
	status := c.CheckTOFUPin(context.Background(), Verified, address, oldDID, "", nil, nil)
	if status != Verified {
		t.Fatalf("initial pin: status=%q, want verified", status)
	}

	// Now send a message from the new DID with a valid replacement announcement
	status = c.CheckTOFUPin(context.Background(), Verified, address, newDID, "", nil, repl)
	if status != Verified {
		t.Fatalf("replacement: status=%q, want verified (accepted via controller authorization)", status)
	}

	// Pin should now point to the new DID
	if ps.Addresses[address] != newDID {
		t.Fatalf("pin not updated: address maps to %q, want %q", ps.Addresses[address], newDID)
	}
}

func TestCheckTOFUPinRejectsReplacementWrongController(t *testing.T) {
	t.Parallel()

	oldPub, _, _ := ed25519.GenerateKey(nil)
	newPub, _, _ := ed25519.GenerateKey(nil)
	controllerPub, _, _ := ed25519.GenerateKey(nil)
	wrongPub, wrongPriv, _ := ed25519.GenerateKey(nil)

	oldDID := ComputeDIDKey(oldPub)
	newDID := ComputeDIDKey(newPub)
	controllerDID := ComputeDIDKey(controllerPub)
	wrongDID := ComputeDIDKey(wrongPub)
	address := "acme.com/billing"
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Sign with the WRONG controller key
	payload := CanonicalReplacementJSON(address, wrongDID, oldDID, newDID, timestamp)
	sig := ed25519.Sign(wrongPriv, []byte(payload))
	sigB64 := base64.RawStdEncoding.EncodeToString(sig)

	repl := &ReplacementAnnouncement{
		Address:             address,
		OldDID:              oldDID,
		NewDID:              newDID,
		ControllerDID:       wrongDID,
		Timestamp:           timestamp,
		ControllerSignature: sigB64,
	}

	c, _ := New("http://localhost")
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			if identifier != address {
				t.Fatalf("identifier=%q", identifier)
			}
			return &ResolvedIdentity{DID: newDID, Address: address, ControllerDID: controllerDID}, nil
		},
	})

	// Pin the old DID
	c.CheckTOFUPin(context.Background(), Verified, address, oldDID, "", nil, nil)

	// Replacement with wrong controller should be rejected
	status := c.CheckTOFUPin(context.Background(), Verified, address, newDID, "", nil, repl)
	if status != IdentityMismatch {
		t.Fatalf("wrong controller: status=%q, want identity_mismatch", status)
	}
}

func TestCheckTOFUPinRejectsReplacementBadSignature(t *testing.T) {
	t.Parallel()

	oldPub, _, _ := ed25519.GenerateKey(nil)
	newPub, _, _ := ed25519.GenerateKey(nil)
	controllerPub, _, _ := ed25519.GenerateKey(nil)

	oldDID := ComputeDIDKey(oldPub)
	newDID := ComputeDIDKey(newPub)
	controllerDID := ComputeDIDKey(controllerPub)
	address := "acme.com/billing"

	repl := &ReplacementAnnouncement{
		Address:             address,
		OldDID:              oldDID,
		NewDID:              newDID,
		ControllerDID:       controllerDID,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		ControllerSignature: base64.RawStdEncoding.EncodeToString([]byte("bad-signature-garbage")),
	}

	c, _ := New("http://localhost")
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			if identifier != address {
				t.Fatalf("identifier=%q", identifier)
			}
			return &ResolvedIdentity{DID: newDID, Address: address, ControllerDID: controllerDID}, nil
		},
	})

	c.CheckTOFUPin(context.Background(), Verified, address, oldDID, "", nil, nil)

	status := c.CheckTOFUPin(context.Background(), Verified, address, newDID, "", nil, repl)
	if status != IdentityMismatch {
		t.Fatalf("bad signature: status=%q, want identity_mismatch", status)
	}
}

func TestCheckTOFUPinRejectsReplacementStaleTimestamp(t *testing.T) {
	t.Parallel()

	oldPub, _, _ := ed25519.GenerateKey(nil)
	newPub, _, _ := ed25519.GenerateKey(nil)
	controllerPub, controllerPriv, _ := ed25519.GenerateKey(nil)

	oldDID := ComputeDIDKey(oldPub)
	newDID := ComputeDIDKey(newPub)
	controllerDID := ComputeDIDKey(controllerPub)
	address := "acme.com/billing"
	staleTimestamp := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)

	payload := CanonicalReplacementJSON(address, controllerDID, oldDID, newDID, staleTimestamp)
	sig := ed25519.Sign(controllerPriv, []byte(payload))
	sigB64 := base64.RawStdEncoding.EncodeToString(sig)

	repl := &ReplacementAnnouncement{
		Address:             address,
		OldDID:              oldDID,
		NewDID:              newDID,
		ControllerDID:       controllerDID,
		Timestamp:           staleTimestamp,
		ControllerSignature: sigB64,
	}

	c, _ := New("http://localhost")
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(stubIdentityResolver{
		resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
			if identifier != address {
				t.Fatalf("identifier=%q", identifier)
			}
			return &ResolvedIdentity{DID: newDID, Address: address, ControllerDID: controllerDID}, nil
		},
	})

	c.CheckTOFUPin(context.Background(), Verified, address, oldDID, "", nil, nil)

	status := c.CheckTOFUPin(context.Background(), Verified, address, newDID, "", nil, repl)
	if status != IdentityMismatch {
		t.Fatalf("stale timestamp: status=%q, want identity_mismatch", status)
	}
}

func TestSignEnvelopePopulatesFromStableID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	c, err := NewWithIdentity("http://localhost", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/alice")
	c.SetStableID(stableID)

	env := &MessageEnvelope{
		To:   "otherco/bob",
		Type: "mail",
		Body: "hello",
	}
	sf, err := c.signEnvelope(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	// Verify from_stable_id was set on the envelope (included in signature).
	if env.FromStableID != stableID {
		t.Fatalf("env.FromStableID=%q, want %q", env.FromStableID, stableID)
	}
	// Verify sf.FromStableID carries the value for stamp-back sites.
	if sf.FromStableID != stableID {
		t.Fatalf("sf.FromStableID=%q, want %q", sf.FromStableID, stableID)
	}

	// Verify signature is valid with from_stable_id included.
	env.Signature = sf.Signature
	env.SigningKeyID = sf.SigningKeyID
	status, verErr := VerifyMessage(env)
	if verErr != nil {
		t.Fatalf("VerifyMessage: %v", verErr)
	}
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
}

func TestSignEnvelopeOmitsStableIDWhenNotSet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	c, err := NewWithIdentity("http://localhost", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/alice")
	// No SetStableID call — stableID stays empty.

	env := &MessageEnvelope{
		To:   "otherco/bob",
		Type: "mail",
		Body: "hello",
	}
	_, err = c.signEnvelope(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	if env.FromStableID != "" {
		t.Fatalf("env.FromStableID=%q, want empty (backward compat)", env.FromStableID)
	}
}

func TestLatestClientVersionCapturedFromHeader(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Latest-Client-Version", "v0.99.0")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Before any request, should be empty.
	if v := c.LatestClientVersion(); v != "" {
		t.Fatalf("before request: LatestClientVersion=%q, want empty", v)
	}

	var resp map[string]bool
	if err := c.Get(context.Background(), "/v1/ping", &resp); err != nil {
		t.Fatal(err)
	}

	if v := c.LatestClientVersion(); v != "v0.99.0" {
		t.Fatalf("after request: LatestClientVersion=%q, want v0.99.0", v)
	}
}

func TestLatestClientVersionEmptyWhenNoHeader(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	var resp map[string]bool
	if err := c.Get(context.Background(), "/v1/ping", &resp); err != nil {
		t.Fatal(err)
	}

	if v := c.LatestClientVersion(); v != "" {
		t.Fatalf("LatestClientVersion=%q, want empty", v)
	}
}
