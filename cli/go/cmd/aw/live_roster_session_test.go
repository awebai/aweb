package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
)

// A chat to a name the team's live roster confirms continues only a session
// with that member's identity: another participant who goes by the same
// name is not the member (chat/IDENTITY_RULES.md:17-19).
func TestChatToALiveRosterMemberSelectsTheSessionByItsDID(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	selfDID := awid.ComputeDIDKey(pub)
	var continued, created []string
	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{Agents: []awid.AgentView{}})
		case r.URL.Path == "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		case r.URL.Path == "/v1/chat/sessions" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{{
				SessionID:            "sess-outsider",
				Participants:         []string{"ada", "grace"},
				ParticipantDIDs:      []string{selfDID, "did:key:outsider-grace"},
				ParticipantAddresses: []string{"demo/ada", "elsewhere/grace"},
				CreatedAt:            "2026-11-18T00:00:00Z",
			}}})
		case r.URL.Path == "/v1/chat/sessions" && r.Method == http.MethodPost:
			created = append(created, r.URL.Path)
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{SessionID: "sess-new", MessageID: "chat-new"})
		case strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/") && r.Method == http.MethodPost:
			continued = append(continued, r.URL.Path)
			_ = json.NewEncoder(w).Encode(awid.ChatSendMessageResponse{MessageID: "chat-continued"})
		default:
			http.NotFound(w, r)
		}
	}))
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/demo/teams/backend/members/grace" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(awid.TeamMemberReference{
			TeamID: "backend:demo", CertificateID: "cert-grace", MemberDIDKey: "did:key:grace",
			Alias: "grace", IdentityScope: awid.IdentityModeLocal, IssuedAt: "2026-06-22T00:00:00Z",
		})
	}))
	t.Setenv("AWID_REGISTRY_URL", registryServer.URL)
	writeSelectionFixtureForTest(t, root, testSelectionFixture{
		AwebURL: apiServer.URL, TeamID: "backend:demo", Alias: "ada", WorkspaceID: "ws-ada",
		DID: selfDID, StableID: awid.ComputeStableID(pub), Address: "demo/ada",
		Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: registryServer.URL, SigningKey: priv,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, _, err := chatSend(ctx, "grace", "hello", chat.SendOptions{Leaving: true}); err != nil {
		t.Fatalf("chat send: %v", err)
	}
	if len(continued) != 0 || len(created) != 1 {
		t.Fatalf("continued=%v created=%v, want a new session with the roster's grace", continued, created)
	}
}
