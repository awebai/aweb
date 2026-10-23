package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
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

func TestAliasFallbackReadsWorkspaceFromExternalIdentityHome(t *testing.T) {
	root := t.TempDir()
	instance := filepath.Join(root, "instance")
	identityHome := filepath.Join(root, "principal")
	externalWorkspace := workspaceBinding("https://aweb.invalid", "backend:demo", "principal", "ws-principal")
	externalWorkspace.Memberships = append(externalWorkspace.Memberships, awconfig.WorktreeMembership{
		TeamID: "ops:demo", Alias: "principal-ops", CertPath: awconfig.TeamCertificateRelativePath("ops:demo"),
	})
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(identityHome, "workspace.yaml"), &externalWorkspace); err != nil {
		t.Fatal(err)
	}
	shadowWorkspace := workspaceBinding("https://aweb.invalid", "backend:demo", "shadow", "ws-shadow")
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(instance, ".aw", "workspace.yaml"), &shadowWorkspace); err != nil {
		t.Fatal(err)
	}

	if !shouldSearchOtherLocalTeamsForAlias(&awconfig.Selection{
		WorkingDir: instance, IdentityHome: identityHome,
		WorkspacePath: filepath.Join(identityHome, "workspace.yaml"),
		TeamID:        "backend:demo",
	}, "reviewer") {
		t.Fatal("external multi-team workspace did not enable alias fallback")
	}
}

func TestLiveRosterAliasFallbackReadsExternalTeamState(t *testing.T) {
	root := t.TempDir()
	instance := filepath.Join(root, "instance")
	identityHome := filepath.Join(root, "principal")
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/demo/teams/backend/members/grace" {
			t.Fatalf("unexpected registry path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(awid.TeamMemberReference{
			TeamID: "backend:demo", MemberDIDKey: "did:key:grace", Alias: "grace", IdentityScope: awid.IdentityModeLocal,
		})
	}))
	if err := awconfig.SaveTeamStateToIdentityHome(identityHome, &awconfig.TeamState{
		ActiveTeam:  "backend:demo",
		Memberships: []awconfig.TeamMembership{{TeamID: "backend:demo", Alias: "principal", CertPath: awconfig.TeamCertificateRelativePath("backend:demo"), RegistryURL: registryServer.URL}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(instance, &awconfig.TeamState{
		ActiveTeam:  "backend:demo",
		Memberships: []awconfig.TeamMembership{{TeamID: "backend:demo", Alias: "shadow", CertPath: awconfig.TeamCertificateRelativePath("backend:demo"), RegistryURL: "http://127.0.0.1:1"}},
	}); err != nil {
		t.Fatal(err)
	}

	target, found, err := resolveLiveTeamMemberAliasTarget(context.Background(), &awconfig.Selection{
		WorkingDir: instance, IdentityHome: identityHome, TeamID: "backend:demo",
	}, "grace")
	if err != nil {
		t.Fatal(err)
	}
	if !found || target.DIDKey != "did:key:grace" {
		t.Fatalf("target=%+v found=%v", target, found)
	}
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
		AwebURL:       apiServer.URL,
		TeamID:        "backend:demo",
		Alias:         "ada",
		WorkspaceID:   "ws-ada",
		DID:           selfDID,
		StableID:      awid.ComputeStableID(pub),
		Address:       "demo/ada",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   registryServer.URL,
		SigningKey:    priv,
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
		AwebURL:       apiServer.URL,
		TeamID:        "backend:demo",
		Alias:         "ada",
		WorkspaceID:   "ws-ada",
		DID:           selfDID,
		StableID:      awid.ComputeStableID(pub),
		Address:       "demo/ada",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   registryServer.URL,
		SigningKey:    priv,
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
		AwebURL:       "https://aweb.invalid",
		TeamID:        "backend:demo",
		Alias:         "ada",
		WorkspaceID:   "ws-ada",
		DID:           selfDID,
		StableID:      awid.ComputeStableID(pub),
		Address:       "demo/ada",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   registryServer.URL,
		SigningKey:    priv,
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
		AwebURL:       "https://aweb.invalid",
		TeamID:        "backend:demo",
		Alias:         "ada",
		WorkspaceID:   "ws-ada",
		DID:           selfDID,
		StableID:      awid.ComputeStableID(pub),
		Address:       "demo/ada",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   "http://127.0.0.1:1",
		SigningKey:    priv,
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

// Humans are intentionally absent from /v1/agents, but remain members of the
// active team's live registry roster. A member name is not a global address.
func TestMailSendAliasReachesActiveTeamMembers(t *testing.T) {
	t.Setenv("AWEB_IDENTITY_HOME", "")
	t.Setenv("AW_NO_UPDATE_CHECK", "1")
	resetMailSendGlobalsForLiveRosterTest(t)
	oldNewConversation := mailSendNewConversation
	t.Cleanup(func() { mailSendNewConversation = oldNewConversation })
	for _, tc := range []struct {
		name, kind, address, scope string
		fresh                      bool
	}{
		{name: "addressless human", kind: "human", scope: awid.IdentityModeGlobal},
		{name: "addressless human fresh conversation", kind: "human", scope: awid.IdentityModeGlobal, fresh: true},
		{name: "addressed human", kind: "human", scope: awid.IdentityModeGlobal, address: "demo/juan"},
		{name: "addressless agent", kind: "agent", scope: awid.IdentityModeGlobal},
		{name: "addressed agent", kind: "agent", scope: awid.IdentityModeGlobal, address: "demo/juan"},
		{name: "local human", kind: "human", scope: awid.IdentityModeLocal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			selfPub, selfKey, _ := ed25519.GenerateKey(nil)
			memberPub, _, _ := ed25519.GenerateKey(nil)
			selfDID, memberDID := awid.ComputeDIDKey(selfPub), awid.ComputeDIDKey(memberPub)
			memberStable := ""
			if tc.scope == awid.IdentityModeGlobal {
				memberStable = awid.ComputeStableID(memberPub)
			}
			var sent []awid.SendMessageRequest
			rosterReads := 0
			api := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/agents":
					var agents []awid.AgentView
					if tc.kind == "agent" {
						agents = []awid.AgentView{{AgentID: "juan-agent", Alias: "juan", AgentType: tc.kind, DIDKey: memberDID, DIDAW: memberStable, Address: tc.address, IdentityScope: tc.scope}}
					}
					_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "backend:demo", Agents: agents})
				case "/v1/conversations":
					_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
				case "/v1/messages":
					cert, err := awid.DecodeTeamCertificateHeader(r.Header.Get("X-AWID-Team-Certificate"))
					if err != nil || cert.Team != "backend:demo" || cert.MemberDIDKey != selfDID {
						t.Errorf("mail lost active-team authentication: cert=%+v err=%v", cert, err)
						w.WriteHeader(http.StatusForbidden)
						return
					}
					var req awid.SendMessageRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					sent = append(sent, req)
					_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: req.MessageID, ConversationID: req.ConversationID, Status: "delivered"})
				default:
					t.Errorf("unexpected team API request %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/namespaces/demo/teams/backend/members/juan" {
					t.Errorf("team alias escaped into global first-contact resolution: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				rosterReads++
				_ = json.NewEncoder(w).Encode(awid.TeamMemberReference{TeamID: "backend:demo", CertificateID: "juan-membership", Alias: "juan", MemberDIDKey: memberDID, MemberDIDAW: memberStable, MemberAddress: tc.address, IdentityScope: tc.scope})
			}))
			writeSelectionFixtureForTest(t, root, testSelectionFixture{AwebURL: api.URL, TeamID: "backend:demo", Alias: "ada", WorkspaceID: "ada-workspace", DID: selfDID, StableID: awid.ComputeStableID(selfPub), Address: "demo/ada", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: registry.URL, SigningKey: selfKey})
			mailSendTo, mailSendSubject, mailSendBody = "juan", "team mail", "hello human or agent"
			mailSendNewConversation = tc.fresh
			cmd := &cobra.Command{}
			cmd.Flags().Bool("e2ee", false, "")
			if err := mailSendCmd.RunE(cmd, nil); err != nil {
				t.Fatalf("active-team %s alias send failed: %v", tc.kind, err)
			}
			if len(sent) != 1 {
				t.Fatalf("mail posts=%d want1", len(sent))
			}
			req := sent[0]
			if req.NewConversation != tc.fresh {
				t.Fatalf("new_conversation=%v want%v", req.NewConversation, tc.fresh)
			}
			if tc.kind == "human" {
				if rosterReads != 1 || req.ToDID != memberDID || req.ToStableID != memberStable || req.ToAddress != "" {
					t.Fatalf("live team recipient binding lost: roster=%d request=%+v", rosterReads, req)
				}
			} else if req.ToAlias != "juan" {
				t.Fatalf("agent lost team alias route: %+v", req)
			}
			sig, err := base64.RawStdEncoding.DecodeString(req.Signature)
			if err != nil || !ed25519.Verify(selfPub, []byte(req.SignedPayload), sig) {
				t.Fatal("invalid message signature")
			}
			var signed awid.MessageEnvelope
			if err := json.Unmarshal([]byte(req.SignedPayload), &signed); err != nil {
				t.Fatal(err)
			}
			if signed.ToDID != req.ToDID || signed.ToStableID != req.ToStableID || signed.Body != "hello human or agent" {
				t.Fatalf("signed binding/body differ from delivery: %+v", signed)
			}
		})
	}
}
