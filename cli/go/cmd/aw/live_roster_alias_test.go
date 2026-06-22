package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
	"github.com/spf13/cobra"
)

func resetMailSendGlobalsForLiveRosterTest(t *testing.T) {
	t.Helper()
	oldTo := mailSendTo
	oldToDID := mailSendToDID
	oldToAddress := mailSendToAddress
	oldSubject := mailSendSubject
	oldBody := mailSendBody
	oldBodyFile := mailSendBodyFile
	oldPriority := mailSendPriority
	oldConversationID := mailSendConversationID
	oldE2EE := mailSendE2EE
	oldLegacyPlaintext := mailSendLegacyPlaintext
	oldPlaintext := mailSendPlaintext
	oldJSON := jsonFlag
	t.Cleanup(func() {
		mailSendTo = oldTo
		mailSendToDID = oldToDID
		mailSendToAddress = oldToAddress
		mailSendSubject = oldSubject
		mailSendBody = oldBody
		mailSendBodyFile = oldBodyFile
		mailSendPriority = oldPriority
		mailSendConversationID = oldConversationID
		mailSendE2EE = oldE2EE
		mailSendLegacyPlaintext = oldLegacyPlaintext
		mailSendPlaintext = oldPlaintext
		jsonFlag = oldJSON
	})
	mailSendTo = ""
	mailSendToDID = ""
	mailSendToAddress = ""
	mailSendSubject = ""
	mailSendBody = ""
	mailSendBodyFile = ""
	mailSendPriority = ""
	mailSendConversationID = ""
	mailSendE2EE = false
	mailSendLegacyPlaintext = false
	mailSendPlaintext = true
	jsonFlag = false
}

func TestMailSendBareAliasFallsBackToLiveTeamRoster(t *testing.T) {
	resetMailSendGlobalsForLiveRosterTest(t)
	root := t.TempDir()
	t.Chdir(root)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	selfDID := awid.ComputeDIDKey(pub)
	var gotBody map[string]any
	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{Agents: []awid.AgentView{}})
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-live", Status: "sent"})
		default:
			t.Fatalf("unexpected api path %s", r.URL.Path)
		}
	}))
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/demo/teams/backend/members/grace" {
			t.Fatalf("unexpected registry path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(awid.TeamMemberReference{
			TeamID:        "backend:demo",
			CertificateID: "cert-grace",
			MemberDIDKey:  "did:key:grace",
			MemberAddress: "demo/grace",
			Alias:         "grace",
			IdentityScope: awid.IdentityModeLocal,
			IssuedAt:      "2026-06-22T00:00:00Z",
		})
	}))
	writeSelectionFixtureForTest(t, root, testSelectionFixture{
		AwebURL:     apiServer.URL,
		TeamID:      "backend:demo",
		Alias:       "ada",
		WorkspaceID: "ws-ada",
		DID:         selfDID,
		StableID:    awid.ComputeStableID(pub),
		Address:     "demo/ada",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		SigningKey:  priv,
	})
	mailSendTo = "grace"
	mailSendSubject = "review"
	mailSendBody = "please review"

	cmd := &cobra.Command{}
	cmd.Flags().Bool("e2ee", false, "")
	if err := mailSendCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("mail send: %v", err)
	}
	if gotBody["to_did"] != "did:key:grace" {
		t.Fatalf("to_did=%v want did:key:grace; body=%#v", gotBody["to_did"], gotBody)
	}
	if gotBody["to_alias"] != nil && gotBody["to_alias"] != "" {
		t.Fatalf("to_alias=%v want empty; body=%#v", gotBody["to_alias"], gotBody)
	}
}

func TestChatSendBareAliasFallsBackToLiveTeamRoster(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	selfDID := awid.ComputeDIDKey(pub)
	var gotBody awid.ChatCreateSessionRequest
	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{Agents: []awid.AgentView{}})
		case "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		case "/v1/chat/sessions":
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{}})
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{SessionID: "sess-live", MessageID: "chat-live"})
		default:
			t.Fatalf("unexpected api path %s", r.URL.Path)
		}
	}))
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/demo/teams/backend/members/grace" {
			t.Fatalf("unexpected registry path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(awid.TeamMemberReference{
			TeamID:        "backend:demo",
			CertificateID: "cert-grace",
			MemberDIDKey:  "did:key:grace",
			MemberAddress: "demo/grace",
			Alias:         "grace",
			IdentityScope: awid.IdentityModeLocal,
			IssuedAt:      "2026-06-22T00:00:00Z",
		})
	}))
	writeSelectionFixtureForTest(t, root, testSelectionFixture{
		AwebURL:     apiServer.URL,
		TeamID:      "backend:demo",
		Alias:       "ada",
		WorkspaceID: "ws-ada",
		DID:         selfDID,
		StableID:    awid.ComputeStableID(pub),
		Address:     "demo/ada",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		SigningKey:  priv,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, _, err := chatSend(ctx, "grace", "hello", chat.SendOptions{Leaving: true}); err != nil {
		t.Fatalf("chat send: %v", err)
	}
	if len(gotBody.ToDIDs) != 1 || gotBody.ToDIDs[0] != "did:key:grace" {
		t.Fatalf("to_dids=%v want [did:key:grace]; body=%+v", gotBody.ToDIDs, gotBody)
	}
	if len(gotBody.ToAliases) != 0 {
		t.Fatalf("to_aliases=%v want empty", gotBody.ToAliases)
	}
}

func TestLiveTeamRosterFallbackUsesDIDWhenMemberHasNoAddress(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	selfDID := awid.ComputeDIDKey(pub)
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/demo/teams/backend/members/local-reviewer" {
			t.Fatalf("unexpected registry path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(awid.TeamMemberReference{
			TeamID:        "backend:demo",
			CertificateID: "cert-local",
			MemberDIDKey:  "did:key:local-reviewer",
			Alias:         "local-reviewer",
			IdentityScope: awid.IdentityModeLocal,
			IssuedAt:      "2026-06-22T00:00:00Z",
		})
	}))
	writeSelectionFixtureForTest(t, root, testSelectionFixture{
		AwebURL:     "https://aweb.invalid",
		TeamID:      "backend:demo",
		Alias:       "ada",
		WorkspaceID: "ws-ada",
		DID:         selfDID,
		StableID:    awid.ComputeStableID(pub),
		Address:     "demo/ada",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		SigningKey:  priv,
	})
	sel, err := resolveSelectionForDir(root)
	if err != nil {
		t.Fatal(err)
	}
	target, found, err := resolveLiveTeamMemberAliasTarget(context.Background(), sel, "local-reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("member not found")
	}
	kind, value := target.identityTarget()
	if kind != "did" || value != "did:key:local-reviewer" {
		t.Fatalf("target=(%q,%q), want did did:key:local-reviewer", kind, value)
	}
}

func TestLiveTeamRosterFallbackPrefersMembershipRegistryOverIdentityRegistry(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	selfDID := awid.ComputeDIDKey(pub)
	var registryCalls int
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registryCalls++
		if r.URL.Path != "/v1/namespaces/demo/teams/backend/members/grace" {
			t.Fatalf("unexpected registry path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(awid.TeamMemberReference{
			TeamID:        "backend:demo",
			CertificateID: "cert-grace",
			MemberDIDKey:  "did:key:grace",
			Alias:         "grace",
			IdentityScope: awid.IdentityModeLocal,
			IssuedAt:      "2026-06-22T00:00:00Z",
		})
	}))
	writeSelectionFixtureForTest(t, root, testSelectionFixture{
		AwebURL:     "https://aweb.invalid",
		TeamID:      "backend:demo",
		Alias:       "ada",
		WorkspaceID: "ws-ada",
		DID:         selfDID,
		StableID:    awid.ComputeStableID(pub),
		Address:     "demo/ada",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: "http://127.0.0.1:1",
		SigningKey:  priv,
	})
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "backend:demo",
		Memberships: []awconfig.TeamMembership{{
			TeamID:      "backend:demo",
			Alias:       "ada",
			CertPath:    awconfig.TeamCertificateRelativePath("backend:demo"),
			JoinedAt:    "2026-06-22T00:00:00Z",
			RegistryURL: registryServer.URL,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	sel, err := resolveSelectionForDir(root)
	if err != nil {
		t.Fatal(err)
	}
	target, found, err := resolveLiveTeamMemberAliasTarget(context.Background(), sel, "grace")
	if err != nil {
		t.Fatalf("resolve live team member via membership registry: %v", err)
	}
	if !found {
		t.Fatal("member not found")
	}
	if target.DIDKey != "did:key:grace" {
		t.Fatalf("target=%+v, want did:key:grace", target)
	}
	if registryCalls != 1 {
		t.Fatalf("membership registry calls=%d want 1", registryCalls)
	}
}

func TestLiveTeamRosterFallbackIgnoresQualifiedTargets(t *testing.T) {
	target, found, err := resolveLiveTeamMemberAliasTarget(context.Background(), &awconfig.Selection{TeamID: "backend:demo"}, "demo/grace")
	if err != nil {
		t.Fatal(err)
	}
	if found || strings.TrimSpace(target.Address) != "" {
		t.Fatalf("qualified target should not be resolved as alias: found=%v target=%+v", found, target)
	}
}
