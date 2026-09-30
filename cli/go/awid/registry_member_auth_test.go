package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistryMemberReadAuthentication(t *testing.T) {
	callerPub, callerKey, _ := ed25519.GenerateKey(nil)
	_, outsiderKey, _ := ed25519.GenerateKey(nil)
	recipientPub, _, _ := ed25519.GenerateKey(nil)
	recipientDID := ComputeDIDKey(recipientPub)
	for _, tc := range []struct {
		name, visibility string
		key              ed25519.PrivateKey
		wantStatus       int
	}{
		{"private member", "private", callerKey, 0},
		{"private anonymous", "private", nil, http.StatusForbidden},
		{"private nonmember", "private", outsiderKey, http.StatusForbidden},
		{"public anonymous", "public", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := &teamVisibilityGate{t: t, visibility: tc.visibility, memberDIDs: map[string]bool{ComputeDIDKey(callerPub): true}}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/namespaces/acme.com/teams/backend/members/alice" {
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				requests++
				if !gate.admit(w, r) {
					return
				}
				if requests == 2 && r.Header.Get("Cache-Control") != "no-cache" {
					t.Error("fresh read lost cache bypass")
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"team_id": "backend:acme.com", "member_did_key": recipientDID, "alias": "alice", "identity_scope": "local"})
			}))
			defer server.Close()
			resolver := NewRegistryResolver(server.Client(), nil)
			resolver.TeamReadSigningKey = tc.key
			if err := resolver.SetFallbackRegistryURL(server.URL); err != nil {
				t.Fatal(err)
			}
			for _, fresh := range []bool{false, true} {
				resolve := resolver.Resolve
				if fresh {
					resolve = resolver.ResolveFresh
				}
				identity, err := resolve(context.Background(), "backend:acme.com/alice")
				if tc.wantStatus != 0 {
					if code, ok := HTTPStatusCode(err); !ok || code != tc.wantStatus {
						t.Fatalf("fresh=%v err=%v, want HTTP %d", fresh, err, tc.wantStatus)
					}
				} else if err != nil || identity.DID != recipientDID {
					t.Fatalf("fresh=%v identity=%+v err=%v", fresh, identity, err)
				}
			}
			if requests != 2 {
				t.Fatalf("requests=%d, want2", requests)
			}
			if tc.key == nil && gate.sawAuthorization {
				t.Fatal("anonymous client sent credentials")
			}
		})
	}
}

func TestMailAndChatPrivateTeamRecipientBinding(t *testing.T) {
	callerPub, callerKey, _ := ed25519.GenerateKey(nil)
	recipientPub, _, _ := ed25519.GenerateKey(nil)
	recipientDID := ComputeDIDKey(recipientPub)
	for _, kind := range []string{"mail", "chat"} {
		for _, signed := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: " anonymous", true: " member"}[signed], func(t *testing.T) {
				gate := &teamVisibilityGate{t: t, visibility: "private", memberDIDs: map[string]bool{ComputeDIDKey(callerPub): true}}
				posted := false
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/v1/namespaces/acme.com/teams/backend/members/alice":
						if !gate.admit(w, r) {
							return
						}
						_ = json.NewEncoder(w).Encode(map[string]string{"team_id": "backend:acme.com", "member_did_key": recipientDID, "alias": "alice", "identity_scope": "local"})
					case "/v1/messages", "/v1/chat/sessions":
						posted = true
						var payload struct {
							SignedPayload string `json:"signed_payload"`
						}
						if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
							t.Error(err)
						}
						var envelope MessageEnvelope
						if err := json.Unmarshal([]byte(payload.SignedPayload), &envelope); err != nil {
							t.Error(err)
						}
						if envelope.ToDID != recipientDID {
							t.Errorf("recipient binding=%q, want %q", envelope.ToDID, recipientDID)
						}
						_ = json.NewEncoder(w).Encode(map[string]string{"message_id": "message", "session_id": "session", "status": "delivered"})
					default:
						t.Errorf("unexpected path %s", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				resolver := NewRegistryResolver(server.Client(), nil)
				if signed {
					resolver.TeamReadSigningKey = callerKey
				}
				if err := resolver.SetFallbackRegistryURL(server.URL); err != nil {
					t.Fatal(err)
				}
				client, err := NewWithIdentity(server.URL, callerKey, ComputeDIDKey(callerPub))
				if err != nil {
					t.Fatal(err)
				}
				client.SetAddress("acme.com/sender")
				client.SetResolver(resolver)
				client.SetRequireRecipientBindingForDirectAddresses(true)
				if kind == "mail" {
					_, err = client.SendMessage(context.Background(), &SendMessageRequest{ToAddress: "backend:acme.com/alice", Body: "hello"})
				} else {
					_, err = client.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{ToAddresses: []string{"backend:acme.com/alice"}, Message: "hello"})
				}
				if signed {
					if err != nil || !posted {
						t.Fatalf("signed %s err=%v posted=%v", kind, err, posted)
					}
				} else {
					if code, ok := HTTPStatusCode(err); !ok || code != http.StatusForbidden || posted {
						t.Fatalf("unsigned %s err=%v posted=%v", kind, err, posted)
					}
				}
			})
		}
	}
}
