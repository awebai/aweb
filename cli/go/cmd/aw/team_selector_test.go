package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestMailInboxTeamFlagSelectsRequestedMembership(t *testing.T) {
	t.Parallel()

	var sawStableID string
	var sawCertHeader string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/inbox":
			sawStableID = strings.TrimSpace(r.Header.Get("X-AWEB-DID-AW"))
			sawCertHeader = strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate"))
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{}})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	stableID := awid.ComputeStableID(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:         memberDID,
		StableID:    stableID,
		Address:     "acme.com/alice",
		RegistryURL: server.URL,
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		CreatedAt:   "2026-04-09T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}

	_, backendTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	backendCert, err := awid.SignTeamCertificate(backendTeamKey, awid.TeamCertificateFields{
		Team:          "backend:acme.com",
		MemberDIDKey:  memberDID,
		MemberDIDAW:   stableID,
		MemberAddress: "acme.com/alice",
		Alias:         "alice",
		Lifetime:      awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, "backend:acme.com", backendCert); err != nil {
		t.Fatal(err)
	}

	_, opsTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	opsCert, err := awid.SignTeamCertificate(opsTeamKey, awid.TeamCertificateFields{
		Team:          "ops:acme.com",
		MemberDIDKey:  memberDID,
		MemberDIDAW:   stableID,
		MemberAddress: "acme.com/alice",
		Alias:         "ops-alice",
		Lifetime:      awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, "ops:acme.com", opsCert); err != nil {
		t.Fatal(err)
	}

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		AwebURL: server.URL,
		Memberships: []awconfig.WorktreeMembership{
			{
				TeamID:      "backend:acme.com",
				Alias:       "alice",
				WorkspaceID: "ws-backend",
				CertPath:    awconfig.TeamCertificateRelativePath("backend:acme.com"),
				JoinedAt:    "2026-04-09T00:00:00Z",
			},
			{
				TeamID:      "ops:acme.com",
				Alias:       "ops-alice",
				WorkspaceID: "ws-ops",
				CertPath:    awconfig.TeamCertificateRelativePath("ops:acme.com"),
				JoinedAt:    "2026-04-09T00:00:00Z",
			},
		},
	})

	run := exec.CommandContext(ctx, bin, "mail", "inbox", "--team", "ops:acme.com", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("mail inbox failed: %v\n%s", err, string(out))
	}
	if sawStableID != "" {
		t.Fatalf("unexpected stable id header: %q", sawStableID)
	}
	if sawCertHeader == "" {
		t.Fatal("missing team cert header")
	}
	cert, err := awid.DecodeTeamCertificateHeader(sawCertHeader)
	if err != nil {
		t.Fatalf("decode team cert header: %v", err)
	}
	if cert.Team != "ops:acme.com" {
		t.Fatalf("team cert team = %q want ops:acme.com", cert.Team)
	}
}

func TestMailInboxTeamFlagRejectsUnknownMembership(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, "https://app.aweb.ai")

	run := exec.CommandContext(ctx, bin, "mail", "inbox", "--team", "ops:acme.com")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if got := string(out); !containsAll(got, `team "ops:acme.com" is not present in workspace memberships; available: backend:demo`) {
		t.Fatalf("unexpected output:\n%s", got)
	}
}

func TestMailInboxDefaultsToActiveTeamWhenTeamFlagIsUnset(t *testing.T) {
	t.Parallel()

	var sawStableID string
	var sawCertHeader string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/inbox":
			sawStableID = strings.TrimSpace(r.Header.Get("X-AWEB-DID-AW"))
			sawCertHeader = strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate"))
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{}})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	stableID := awid.ComputeStableID(memberPub)
	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     server.URL,
		TeamID:      "backend:demo",
		Alias:       "alice",
		WorkspaceID: "workspace-1",
		DID:         awid.ComputeDIDKey(memberPub),
		StableID:    stableID,
		Address:     "demo/alice",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		SigningKey:  memberKey,
		CreatedAt:   "2026-04-09T00:00:00Z",
	})

	run := exec.CommandContext(ctx, bin, "mail", "inbox", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("mail inbox failed: %v\n%s", err, string(out))
	}
	if sawStableID != "" {
		t.Fatalf("unexpected stable id header: %q", sawStableID)
	}
	if sawCertHeader == "" {
		t.Fatal("missing team cert header")
	}
	cert, err := awid.DecodeTeamCertificateHeader(sawCertHeader)
	if err != nil {
		t.Fatalf("decode team cert header: %v", err)
	}
	if cert.Team != "backend:demo" {
		t.Fatalf("team cert team = %q want backend:demo", cert.Team)
	}
}

func TestMailInboxUsesTeamCertificateWhenIdentityFileIsAbsent(t *testing.T) {
	var sawAuth string
	var sawStableID string
	var sawCertHeader string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/inbox":
			sawAuth = strings.TrimSpace(r.Header.Get("Authorization"))
			sawStableID = strings.TrimSpace(r.Header.Get("X-AWEB-DID-AW"))
			sawCertHeader = strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate"))
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{}})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	t.Setenv("HOME", tmp)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	expectedDID := awid.ComputeDIDKey(memberPub)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), memberKey); err != nil {
		t.Fatal(err)
	}

	workspace := workspaceBinding(server.URL, "backend:demo", "alice", "workspace-1")
	writeTeamCertificateWorkspaceForTest(t, tmp, workspace, &testSelectionFixture{
		AwebURL:     server.URL,
		TeamID:      "backend:demo",
		Alias:       "alice",
		WorkspaceID: "workspace-1",
		DID:         awid.ComputeDIDKey(memberPub),
		Lifetime:    awid.LifetimeEphemeral,
		SigningKey:  memberKey,
		CreatedAt:   "2026-04-09T00:00:00Z",
	})
	writeWorkspaceBindingForTest(t, tmp, workspace)

	run := exec.CommandContext(ctx, bin, "mail", "inbox", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("mail inbox failed: %v\n%s", err, string(out))
	}
	if !strings.HasPrefix(sawAuth, "DIDKey "+expectedDID+" ") {
		t.Fatalf("authorization=%q want DIDKey %s <sig>", sawAuth, expectedDID)
	}
	if sawStableID != "" {
		t.Fatalf("unexpected stable id header: %q", sawStableID)
	}
	if sawCertHeader == "" {
		t.Fatal("missing team cert header")
	}
	cert, err := awid.DecodeTeamCertificateHeader(sawCertHeader)
	if err != nil {
		t.Fatalf("decode team cert header: %v", err)
	}
	if cert.Team != "backend:demo" {
		t.Fatalf("team cert team = %q want backend:demo", cert.Team)
	}
}

func TestMailSendToAddressTeamFlagUsesSelectedCertificateContext(t *testing.T) {
	t.Parallel()

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	stableID := awid.ComputeStableID(memberPub)
	recipientPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(recipientPub)
	recipientStableID := awid.ComputeStableID(recipientPub)

	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/randy":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-randy",
				"domain":          "acme.com",
				"name":            "randy",
				"did_aw":          recipientStableID,
				"current_did_key": recipientDID,
				"reachability":    "public",
				"created_at":      "2026-04-27T00:00:00Z",
			})
		case "/v1/did/" + recipientStableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          recipientStableID,
				"current_did_key": recipientDID,
			})
		default:
			t.Fatalf("unexpected registry path=%s", r.URL.Path)
		}
	}))

	var sawCertHeader string
	var mailBody map[string]any
	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			sawCertHeader = strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate"))
			if err := json.NewDecoder(r.Body).Decode(&mailBody); err != nil {
				t.Fatalf("decode mail body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "mail-1",
				"status":       "delivered",
				"delivered_at": "2026-04-27T00:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected api path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), memberKey); err != nil {
		t.Fatal(err)
	}
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:         memberDID,
		StableID:    stableID,
		Address:     "other.example/amy",
		RegistryURL: registryServer.URL,
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		CreatedAt:   "2026-04-27T00:00:00Z",
	})
	writeTeamCertFixturesForTest(t, tmp, apiServer.URL, memberDID, stableID, []teamCertFixture{
		{TeamID: "backend:acme.com", Alias: "alice", WorkspaceID: "ws-backend", Address: "acme.com/alice"},
		{TeamID: "ops:acme.com", Alias: "ops-alice", WorkspaceID: "ws-ops", Address: "acme.com/ops-alice"},
	})

	run := exec.CommandContext(ctx, bin, "mail", "send", "--team", "ops:acme.com", "--to-address", "acme.com/randy", "--body", "hello", "--json")
	run.Env = withoutEnvForTest(testCommandEnv(tmp), "AWID_REGISTRY_URL")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("mail send failed: %v\n%s", err, string(out))
	}
	if sawCertHeader == "" {
		t.Fatal("missing team cert header")
	}
	cert, err := awid.DecodeTeamCertificateHeader(sawCertHeader)
	if err != nil {
		t.Fatalf("decode team cert header: %v", err)
	}
	if cert.Team != "ops:acme.com" {
		t.Fatalf("team cert team = %q want ops:acme.com", cert.Team)
	}
	requireSignedPayloadBindingForTest(t, mailBody["signed_payload"], "mail", recipientDID, recipientStableID, "acme.com/ops-alice")
}

func TestChatSendBareAliasFallsBackToUniqueLocalTeamMembership(t *testing.T) {
	t.Parallel()

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	stableID := awid.ComputeStableID(memberPub)

	var postedCertHeader string
	var postedBody map[string]any
	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			cert := requireCertificateAuthForTest(t, r)
			agents := []map[string]any{}
			if cert.Team == "ops:acme.com" {
				agents = append(agents, map[string]any{
					"agent_id": "agent-randy",
					"alias":    "randy",
					"did_key":  "did:key:z6Mkrandy",
					"status":   "active",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": cert.Team, "agents": agents})
		case "/v1/chat/sessions":
			postedCertHeader = strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate"))
			if err := json.NewDecoder(r.Body).Decode(&postedBody); err != nil {
				t.Fatalf("decode chat body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{
				SessionID: "session-1",
				MessageID: "chat-1",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected api path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), memberKey); err != nil {
		t.Fatal(err)
	}
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       memberDID,
		StableID:  stableID,
		Address:   "acme.com/alice",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-27T00:00:00Z",
	})
	writeTeamCertFixturesForTest(t, tmp, apiServer.URL, memberDID, stableID, []teamCertFixture{
		{TeamID: "backend:acme.com", Alias: "alice", WorkspaceID: "ws-backend", Address: "acme.com/alice"},
		{TeamID: "ops:acme.com", Alias: "ops-alice", WorkspaceID: "ws-ops", Address: "acme.com/ops-alice"},
	})

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "randy", "hello", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("chat send failed: %v\n%s", err, string(out))
	}
	cert, err := awid.DecodeTeamCertificateHeader(postedCertHeader)
	if err != nil {
		t.Fatalf("decode posted team cert: %v", err)
	}
	if cert.Team != "ops:acme.com" {
		t.Fatalf("posted team cert team = %q want ops:acme.com", cert.Team)
	}
	toAliases, ok := postedBody["to_aliases"].([]any)
	if !ok || len(toAliases) != 1 || toAliases[0] != "randy" {
		t.Fatalf("to_aliases=%#v, want [randy]", postedBody["to_aliases"])
	}
}

func TestChatSendBareAliasRequiresTeamWhenFallbackIsAmbiguous(t *testing.T) {
	t.Parallel()

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	stableID := awid.ComputeStableID(memberPub)
	var chatPosts int

	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			cert := requireCertificateAuthForTest(t, r)
			agents := []map[string]any{}
			if cert.Team == "ops:acme.com" || cert.Team == "qa:acme.com" {
				agents = append(agents, map[string]any{
					"agent_id": "agent-" + cert.Team,
					"alias":    "randy",
					"did_key":  "did:key:z6Mkrandy",
					"status":   "active",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": cert.Team, "agents": agents})
		case "/v1/chat/sessions":
			chatPosts++
			http.Error(w, "unexpected chat post", http.StatusInternalServerError)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected api path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), memberKey); err != nil {
		t.Fatal(err)
	}
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       memberDID,
		StableID:  stableID,
		Address:   "acme.com/alice",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-27T00:00:00Z",
	})
	writeTeamCertFixturesForTest(t, tmp, apiServer.URL, memberDID, stableID, []teamCertFixture{
		{TeamID: "backend:acme.com", Alias: "alice", WorkspaceID: "ws-backend", Address: "acme.com/alice"},
		{TeamID: "ops:acme.com", Alias: "ops-alice", WorkspaceID: "ws-ops", Address: "acme.com/ops-alice"},
		{TeamID: "qa:acme.com", Alias: "qa-alice", WorkspaceID: "ws-qa", Address: "acme.com/qa-alice"},
	})

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "randy", "hello")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected ambiguous alias error:\n%s", string(out))
	}
	if got := string(out); !containsAll(got, `alias "randy" exists in multiple local team memberships`, "ops:acme.com", "qa:acme.com", "pass --team") {
		t.Fatalf("unexpected output:\n%s", got)
	}
	if chatPosts != 0 {
		t.Fatalf("chat posts=%d, want 0", chatPosts)
	}
}

type teamCertFixture struct {
	TeamID      string
	Alias       string
	WorkspaceID string
	Address     string
}

func writeTeamCertFixturesForTest(t *testing.T, workingDir, serverURL, memberDID, stableID string, fixtures []teamCertFixture) {
	t.Helper()
	memberships := make([]awconfig.WorktreeMembership, 0, len(fixtures))
	for _, fixture := range fixtures {
		_, teamKey, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatalf("generate team keypair: %v", err)
		}
		cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
			Team:          fixture.TeamID,
			MemberDIDKey:  memberDID,
			MemberDIDAW:   stableID,
			MemberAddress: fixture.Address,
			Alias:         fixture.Alias,
			Lifetime:      awid.LifetimePersistent,
		})
		if err != nil {
			t.Fatalf("sign team cert for %s: %v", fixture.TeamID, err)
		}
		if _, err := awconfig.SaveTeamCertificateForTeam(workingDir, fixture.TeamID, cert); err != nil {
			t.Fatalf("save team cert for %s: %v", fixture.TeamID, err)
		}
		memberships = append(memberships, awconfig.WorktreeMembership{
			TeamID:      fixture.TeamID,
			Alias:       fixture.Alias,
			WorkspaceID: fixture.WorkspaceID,
			CertPath:    awconfig.TeamCertificateRelativePath(fixture.TeamID),
			JoinedAt:    "2026-04-27T00:00:00Z",
		})
	}
	writeWorkspaceBindingForTest(t, workingDir, awconfig.WorktreeWorkspace{
		AwebURL:     serverURL,
		Memberships: memberships,
	})
}

func containsAll(text string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && !strings.Contains(text, needle) {
			return false
		}
	}
	return true
}
