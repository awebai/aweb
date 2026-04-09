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

	var sawTeamID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/inbox":
			certHeader := r.Header.Get("X-AWID-Team-Certificate")
			cert, err := awid.DecodeTeamCertificateHeader(certHeader)
			if err != nil {
				t.Fatalf("decode team cert header: %v", err)
			}
			sawTeamID = cert.Team
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
		AwebURL:    server.URL,
		ActiveTeam: "backend:acme.com",
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
	if sawTeamID != "ops:acme.com" {
		t.Fatalf("team cert used %q", sawTeamID)
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

	var sawTeamID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/inbox":
			cert, err := awid.DecodeTeamCertificateHeader(r.Header.Get("X-AWID-Team-Certificate"))
			if err != nil {
				t.Fatalf("decode team cert header: %v", err)
			}
			sawTeamID = cert.Team
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
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "mail", "inbox", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("mail inbox failed: %v\n%s", err, string(out))
	}
	if sawTeamID != "backend:demo" {
		t.Fatalf("team cert used %q", sawTeamID)
	}
}

func containsAll(text string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && !strings.Contains(text, needle) {
			return false
		}
	}
	return true
}
