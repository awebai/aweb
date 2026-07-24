package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected path to exist %s: %v", path, err)
	}
}

func resetTeamAcceptInviteGlobals(t *testing.T) {
	t.Helper()
	oldAlias := teamAcceptAlias
	oldAddress := teamAcceptAddress
	oldLocal := teamAcceptLocal
	oldGlobal := teamAcceptGlobal
	oldNoAddress := teamAcceptNoAddress
	t.Cleanup(func() {
		teamAcceptAlias = oldAlias
		teamAcceptAddress = oldAddress
		teamAcceptLocal = oldLocal
		teamAcceptGlobal = oldGlobal
		teamAcceptNoAddress = oldNoAddress
	})
	teamAcceptAlias = ""
	teamAcceptAddress = ""
	teamAcceptLocal = false
	teamAcceptGlobal = false
	teamAcceptNoAddress = false
}

// writeControllerKeyForTest writes a controller key to the test HOME's AWID state directory.
func writeControllerKeyForTest(t *testing.T, home, domain string, key ed25519.PrivateKey) {
	t.Helper()
	dir := filepath.Join(home, ".awid", "controllers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key.Seed(),
	})
	if err := os.WriteFile(filepath.Join(dir, awconfig.NormalizeDomain(domain)+".key"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeTeamKeyForTest writes a team key to the test HOME's AWID state directory.
func writeTeamKeyForTest(t *testing.T, home, domain, name string, key ed25519.PrivateKey) {
	t.Helper()
	dir := filepath.Join(home, ".awid", "team-keys", awconfig.NormalizeDomain(domain))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key.Seed(),
	})
	if err := os.WriteFile(filepath.Join(dir, strings.ToLower(strings.TrimSpace(name))+".key"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeTeamInviteForTest writes a team invite JSON file to the test HOME's config directory.
func writeTeamInviteForTest(t *testing.T, home string, invite *awconfig.TeamInvite) {
	t.Helper()
	dir := filepath.Join(home, ".config", "aw", "team-invites")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(invite, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, invite.InviteID+".json"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func resetTeamMembersGlobals(t *testing.T) {
	t.Helper()
	oldTeamID := teamMembersTeamID
	oldTeam := teamMembersTeam
	oldNamespace := teamMembersNamespace
	oldRegistry := teamMembersRegistryURL
	oldIncludeRevoked := teamMembersIncludeRevoked
	oldJSON := jsonFlag
	t.Cleanup(func() {
		teamMembersTeamID = oldTeamID
		teamMembersTeam = oldTeam
		teamMembersNamespace = oldNamespace
		teamMembersRegistryURL = oldRegistry
		teamMembersIncludeRevoked = oldIncludeRevoked
		jsonFlag = oldJSON
	})
	teamMembersTeamID = ""
	teamMembersTeam = ""
	teamMembersNamespace = ""
	teamMembersRegistryURL = ""
	teamMembersIncludeRevoked = false
	jsonFlag = false
}

func TestRunTeamMembersListsActiveCertificates(t *testing.T) {
	resetTeamMembersGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	var sawActiveOnly string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/certificates" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		sawActiveOnly = r.URL.Query().Get("active_only")
		_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []map[string]any{{
			"certificate_id": "cert-alice",
			"team_id":        "backend:acme.com",
			"member_did_key": "did:key:alice",
			"member_address": "acme.com/alice",
			"alias":          "alice",
			"identity_scope": "global",
			"issued_at":      "2026-06-22T00:00:00Z",
		}}})
	}))
	defer server.Close()
	teamMembersTeamID = "backend:acme.com"
	teamMembersRegistryURL = server.URL

	if err := runTeamMembers(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runTeamMembers: %v", err)
	}
	if sawActiveOnly != "true" {
		t.Fatalf("active_only=%q want true", sawActiveOnly)
	}
}

func TestRunTeamMembersInfersActiveTeamAndCanIncludeRevoked(t *testing.T) {
	resetTeamMembersGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/certificates" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		if got := r.URL.Query().Get("active_only"); got != "" {
			t.Fatalf("active_only=%q want absent when including revoked", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []map[string]any{{
			"certificate_id": "cert-bob",
			"team_id":        "backend:acme.com",
			"member_did_key": "did:key:bob",
			"alias":          "bob",
			"identity_scope": "local",
			"issued_at":      "2026-06-22T00:00:00Z",
			"revoked_at":     "2026-06-22T01:00:00Z",
		}}})
	}))
	defer server.Close()
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "backend:acme.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "self",
			CertPath:    "team-certs/backend_acme.com.json",
			RegistryURL: server.URL,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	teamMembersIncludeRevoked = true

	if err := runTeamMembers(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runTeamMembers: %v", err)
	}
}

func TestRunTeamMembersDiscoversRegistryFromHostedMembershipAwebURL(t *testing.T) {
	resetTeamMembersGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/certificates" {
			t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []map[string]any{{
			"certificate_id": "cert-ada",
			"team_id":        "backend:acme.com",
			"member_did_key": "did:key:ada",
			"alias":          "ada",
			"identity_scope": "local",
			"issued_at":      "2026-06-22T00:00:00Z",
		}}})
	}))
	defer registryServer.Close()
	awebServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/discovery" {
			t.Fatalf("unexpected discovery request %s %s", r.Method, r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"onboarding_url": awebServerURLForTest(r),
			"aweb_url":       awebServerURLForTest(r),
			"registry_url":   registryServer.URL,
		})
	}))
	defer awebServer.Close()
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "backend:acme.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "backend:acme.com",
			Alias:    "self",
			CertPath: "team-certs/backend_acme.com.json",
			AwebURL:  awebServer.URL + "/api",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	if err := runTeamMembers(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runTeamMembers: %v", err)
	}
}

func awebServerURLForTest(r *http.Request) string {
	return "http://" + r.Host + "/api"
}

func TestFormatTeamMembersPrintsRosterColumns(t *testing.T) {
	out := formatTeamMembers(teamMembersOutput{TeamID: "backend:acme.com", Members: []teamMemberItem{{
		Alias:         "alice",
		MemberAddress: "acme.com/alice",
		MemberDIDKey:  "did:key:alice",
		IdentityScope: "global",
		IssuedAt:      "2026-06-22T00:00:00Z",
		RevokedAt:     "-",
	}}})
	for _, want := range []string{"NAME", "MEMBER", "DID", "IDENTITY", "ISSUED", "REVOKED", "alice", "acme.com/alice", "did:key:alice", "global"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func resetTeamRemoveMemberGlobals(t *testing.T) {
	t.Helper()
	oldTeam := teamRemoveTeam
	oldNamespace := teamRemoveNamespace
	oldMember := teamRemoveMember
	oldCertID := teamRemoveCertID
	oldRegistry := teamRemoveRegistryURL
	oldAwebURL := teamRemoveAwebURL
	oldAPIKey := teamRemoveAPIKey
	oldJSON := jsonFlag
	t.Cleanup(func() {
		teamRemoveTeam = oldTeam
		teamRemoveNamespace = oldNamespace
		teamRemoveMember = oldMember
		teamRemoveCertID = oldCertID
		teamRemoveRegistryURL = oldRegistry
		teamRemoveAwebURL = oldAwebURL
		teamRemoveAPIKey = oldAPIKey
		jsonFlag = oldJSON
	})
	teamRemoveTeam = ""
	teamRemoveNamespace = ""
	teamRemoveMember = ""
	teamRemoveCertID = ""
	teamRemoveRegistryURL = ""
	teamRemoveAwebURL = ""
	teamRemoveAPIKey = ""
	jsonFlag = false
}

func TestRunTeamRemoveMemberHostedPostsCloudRevokeByMemberAddressWithExplicitTeamKey(t *testing.T) {
	resetTeamRemoveMemberGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	var gotBody map[string]any
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/teams/default:alice.aweb.ai/agents/remove-member" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		gotAuth = strings.TrimSpace(r.Header.Get("Authorization"))
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":            "removed",
			"canonical_team_id": "default:alice.aweb.ai",
			"member_address":    "alice.aweb.ai/reviewer",
			"certificate_id":    "cert-123",
			"agent_id":          "agent-123",
			"workspace_id":      "workspace-123",
		})
	}))
	defer server.Close()
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "default:alice.aweb.ai",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "default:alice.aweb.ai",
			Alias:    "owner",
			CertPath: "team-certs/default__alice.aweb.ai.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(root, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		AwebURL: server.URL + "/api",
		APIKey:  "aw_sk_workspace_bound_must_not_be_used",
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:   "default:alice.aweb.ai",
			Alias:    "owner",
			CertPath: "team-certs/default__alice.aweb.ai.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	teamRemoveTeam = "default"
	teamRemoveNamespace = "alice.aweb.ai"
	teamRemoveMember = "alice.aweb.ai/reviewer"
	teamRemoveAPIKey = "aw_sk_team_owner"

	if err := runTeamRemoveMember(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runTeamRemoveMember: %v", err)
	}
	if gotAuth != "Bearer aw_sk_team_owner" {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if gotBody["member_address"] != "alice.aweb.ai/reviewer" || gotBody["certificate_id"] != nil {
		t.Fatalf("body=%#v", gotBody)
	}
}

func TestRunTeamRemoveMemberHostedDoesNotUseWorkspaceBoundAPIKey(t *testing.T) {
	resetTeamRemoveMemberGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("workspace-bound API key should not be sent to hosted remove-member: %s %s", r.Method, r.URL.String())
	}))
	defer server.Close()
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "default:alice.aweb.ai",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "default:alice.aweb.ai",
			Alias:    "owner",
			CertPath: "team-certs/default__alice.aweb.ai.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(root, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		AwebURL: server.URL,
		APIKey:  "aw_sk_workspace_bound",
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:   "default:alice.aweb.ai",
			Alias:    "owner",
			CertPath: "team-certs/default__alice.aweb.ai.pem",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	teamRemoveTeam = "default"
	teamRemoveNamespace = "alice.aweb.ai"
	teamRemoveMember = "alice.aweb.ai/reviewer"

	err := runTeamRemoveMember(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "workspace-bound API keys cannot remove hosted team members") {
		t.Fatalf("error=%v", err)
	}
}

func TestRunTeamRemoveMemberHostedPostsCloudRevokeByCertificateID(t *testing.T) {
	resetTeamRemoveMemberGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv(initAPIKeyEnvVar, "aw_sk_env")
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/teams/default:alice.aweb.ai/agents/remove-member" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		if got := strings.TrimSpace(r.Header.Get("Authorization")); got != "Bearer aw_sk_env" {
			t.Fatalf("Authorization=%q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "removed", "certificate_id": "cert-456"})
	}))
	defer server.Close()
	teamRemoveTeam = "default"
	teamRemoveNamespace = "alice.aweb.ai"
	teamRemoveCertID = "cert-456"
	teamRemoveAwebURL = server.URL

	if err := runTeamRemoveMember(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runTeamRemoveMember: %v", err)
	}
	if gotBody["certificate_id"] != "cert-456" || gotBody["member_address"] != nil {
		t.Fatalf("body=%#v", gotBody)
	}
}

func TestPostHostedTeamRemoveMemberMapsNotFoundStatusIn2xxResponseToAlreadyRemoved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/teams/default:alice.aweb.ai/agents/remove-member" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "not_found", "team_id": "default:alice.aweb.ai", "certificate_id": "cert-456"})
	}))
	defer server.Close()

	resp, err := postHostedTeamRemoveMember(context.Background(), server.URL, "aw_sk_owner", "default:alice.aweb.ai", hostedTeamRemoveMemberRequest{CertificateID: "cert-456"})
	if err != nil {
		t.Fatalf("postHostedTeamRemoveMember: %v", err)
	}
	if resp.Status != "already_removed" || resp.TeamID != "default:alice.aweb.ai" || resp.CertificateID != "cert-456" {
		t.Fatalf("response=%+v", resp)
	}
}

func TestPostHostedTeamRemoveMemberTreatsHTTP404AsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/teams/default:alice.aweb.ai/agents/remove-member" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found"))
	}))
	defer server.Close()

	_, err := postHostedTeamRemoveMember(context.Background(), server.URL, "aw_sk_owner", "default:alice.aweb.ai", hostedTeamRemoveMemberRequest{CertificateID: "cert-456"})
	if err == nil || !strings.Contains(err.Error(), "hosted remove-member returned 404") {
		t.Fatalf("error=%v, want hosted remove-member returned 404", err)
	}
}

func TestPostHostedTeamRemoveMemberSurfacesNon2xxErrors(t *testing.T) {
	for _, statusCode := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusUnprocessableEntity, http.StatusConflict, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(statusCode), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": "expected_error"}})
			}))
			defer server.Close()

			_, err := postHostedTeamRemoveMember(context.Background(), server.URL, "aw_sk_owner", "default:alice.aweb.ai", hostedTeamRemoveMemberRequest{CertificateID: "cert-456"})
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("hosted remove-member returned %d", statusCode)) {
				t.Fatalf("error=%v, want hosted remove-member returned %d", err, statusCode)
			}
		})
	}
}

func TestRunTeamRemoveMemberLocalCanRevokeByCertificateID(t *testing.T) {
	resetTeamRemoveMemberGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("HOME", root)
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, root, "acme.com", "backend", teamKey)
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/certificates/revoke" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
			t.Fatalf("missing Authorization header")
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})
	}))
	defer server.Close()
	teamRemoveTeam = "backend"
	teamRemoveNamespace = "acme.com"
	teamRemoveCertID = "cert-local"
	teamRemoveRegistryURL = server.URL

	if err := runTeamRemoveMember(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runTeamRemoveMember: %v", err)
	}
	if gotBody["certificate_id"] != "cert-local" {
		t.Fatalf("body=%#v", gotBody)
	}
}

func TestRunTeamRemoveMemberHostedRequiresTeamAPIKey(t *testing.T) {
	resetTeamRemoveMemberGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	teamRemoveTeam = "default"
	teamRemoveNamespace = "alice.aweb.ai"
	teamRemoveMember = "alice.aweb.ai/reviewer"
	teamRemoveAwebURL = "https://app.aweb.ai/api"

	err := runTeamRemoveMember(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("expected missing team API key error")
	}
	for _, want := range []string{"requires --api-key or AWEB_API_KEY", "team-scoped owner/admin API key", "workspace-bound API keys cannot remove hosted team members"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
}

func TestIsAwebHostedNamespaceRequiresAwebAILabelBoundary(t *testing.T) {
	t.Parallel()

	for _, domain := range []string{"aweb.ai", " Alice.AWEB.AI. ", "foo.bar.aweb.ai"} {
		if !isAwebHostedNamespace(domain) {
			t.Fatalf("%q should be treated as hosted", domain)
		}
	}
	for _, domain := range []string{"evil-aweb.ai", "aweb.ai.example.com", "example.com", ".aweb.ai", "foo..aweb.ai", ""} {
		if isAwebHostedNamespace(domain) {
			t.Fatalf("%q should not be treated as hosted", domain)
		}
	}
}

func TestNewTeamCloudHTTPClientUsesAwebAPITransport(t *testing.T) {
	t.Parallel()

	client := newTeamCloudHTTPClient()
	if client.Timeout != awid.APITimeout() {
		t.Fatalf("timeout=%v want %v", client.Timeout, awid.APITimeout())
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type=%T want *http.Transport", client.Transport)
	}
	if transport == http.DefaultTransport {
		t.Fatal("team cloud client must not use http.DefaultTransport")
	}
	if transport.ResponseHeaderTimeout != awid.APITimeout() {
		t.Fatalf("response header timeout=%v want %v", transport.ResponseHeaderTimeout, awid.APITimeout())
	}
}

func TestTeamKeyLoadErrorHostedNamespacePointsToDashboard(t *testing.T) {
	err := teamKeyLoadError("aweb:juan.aweb.ai", "juan.aweb.ai", errors.New("open missing: no such file or directory"))
	got := err.Error()
	for _, want := range []string{
		"aweb.ai hosted namespace",
		"hosted dashboard Add existing agent",
		"cannot sign the add-member operation locally",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q missing %q", got, want)
		}
	}
}

func TestTeamKeyLoadErrorByoidtNamespacePointsToLocalControllerKey(t *testing.T) {
	err := teamKeyLoadError("backend:example.com", "example.com", errors.New("open missing: no such file or directory"))
	got := err.Error()
	for _, want := range []string{
		"BYOIDT/BYOD teams",
		"~/.awid/team-keys/<namespace>/<team>.key",
		"hosted aweb.ai teams should use the dashboard Add existing agent action",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "This looks like an aweb.ai hosted namespace") {
		t.Fatalf("non-hosted namespace used hosted-specific message: %q", got)
	}
}

func setTeamImportRequestGlobalsForTest(t *testing.T, team, namespace string) {
	t.Helper()
	oldTeam := teamImportRequestTeam
	oldNamespace := teamImportRequestNamespace
	oldOrganizationID := teamImportRequestOrganizationID
	oldCloudTeamID := teamImportRequestCloudTeamID
	oldTimestamp := teamImportRequestTimestamp
	oldApply := teamImportRequestApply
	teamImportRequestTeam = team
	teamImportRequestNamespace = namespace
	teamImportRequestOrganizationID = "org-1"
	teamImportRequestCloudTeamID = ""
	teamImportRequestTimestamp = "2026-05-09T12:00:00Z"
	teamImportRequestApply = false
	t.Cleanup(func() {
		teamImportRequestTeam = oldTeam
		teamImportRequestNamespace = oldNamespace
		teamImportRequestOrganizationID = oldOrganizationID
		teamImportRequestCloudTeamID = oldCloudTeamID
		teamImportRequestTimestamp = oldTimestamp
		teamImportRequestApply = oldApply
	})
}

func TestRunTeamImportRequestRejectsHostedNamespaceBeforeKeyLoad(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	setTeamImportRequestGlobalsForTest(t, "aweb", " Juan.AWEB.AI. ")
	err := runTeamImportRequest(nil, nil)
	if err == nil {
		t.Fatal("expected hosted namespace refusal")
	}
	got := err.Error()
	for _, want := range []string{
		"hosted by aweb.ai",
		"hosted dashboard flow",
		"BYOT import-request",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "team-keys") {
		t.Fatalf("hosted refusal should happen before key-load guidance, got %q", got)
	}
}

func TestRunTeamImportRequestMissingKeyUsesBYOTGuidance(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	setTeamImportRequestGlobalsForTest(t, "research", "example.com")
	err := runTeamImportRequest(nil, nil)
	if err == nil {
		t.Fatal("expected missing local team key error")
	}
	got := err.Error()
	for _, want := range []string{
		"research:example.com",
		"BYOIDT/BYOD teams",
		"~/.awid/team-keys/<namespace>/<team>.key",
		"hosted aweb.ai teams should use the dashboard Add existing agent action",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q missing %q", got, want)
		}
	}
}

func TestBuildTeamImportRequestOutputSignsCanonicalACPayload(t *testing.T) {
	teamKey := ed25519.NewKeyFromSeed([]byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31,
	})
	pub := teamKey.Public().(ed25519.PublicKey)
	out, err := buildTeamImportRequestOutput(
		teamKey,
		"research:acme.com",
		"org-1",
		"",
		true,
		"2026-05-09T12:00:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}

	wantCanonical := `{"awid_team_id":"research:acme.com","dry_run":true,"operation":"byoidt_import","organization_id":"org-1","team_id":"","timestamp":"2026-05-09T12:00:00Z"}`
	if out.CanonicalPayload != wantCanonical {
		t.Fatalf("canonical payload mismatch:\n got: %s\nwant: %s", out.CanonicalPayload, wantCanonical)
	}
	if out.ControllerDID != awid.ComputeDIDKey(pub) {
		t.Fatalf("controller did=%q want %q", out.ControllerDID, awid.ComputeDIDKey(pub))
	}
	if out.ControllerDID != "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd" {
		t.Fatalf("controller did interop vector changed: %q", out.ControllerDID)
	}
	const wantSignature = "wJ9qUNecyxiqSF45ALU6upFloyUPiQW1RXkste671QcTjBM9nGqN9ngTcgGwVX2OO+s4gQ/yFIXKL7OewHelBw"
	if out.ControllerSignature != wantSignature {
		t.Fatalf("signature mismatch:\n got: %s\nwant: %s", out.ControllerSignature, wantSignature)
	}
	sig, err := base64.RawStdEncoding.DecodeString(out.ControllerSignature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(out.CanonicalPayload), sig) {
		t.Fatal("controller signature does not verify")
	}
	if got := out.RequestBody["organization_id"]; got != "org-1" {
		t.Fatalf("request organization_id=%v", got)
	}
	if got := out.RequestBody["team_id"]; got != nil {
		t.Fatalf("empty cloud team id should encode as nil request field, got %v", got)
	}
	if got := out.RequestBody["controller_signature"]; got != out.ControllerSignature {
		t.Fatalf("request signature=%v want %s", got, out.ControllerSignature)
	}
	if _, ok := out.RequestBody["access_mode"]; ok {
		t.Fatal("request body must not include stale unsigned access_mode")
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "access_mode") {
		t.Fatalf("import-request output must not expose stale access_mode, got %s", encoded)
	}
}

func TestExecuteTeamRegisterSignsAndPostsServicePayload(t *testing.T) {
	teamKey := ed25519.NewKeyFromSeed([]byte{
		31, 30, 29, 28, 27, 26, 25, 24,
		23, 22, 21, 20, 19, 18, 17, 16,
		15, 14, 13, 12, 11, 10, 9, 8,
		7, 6, 5, 4, 3, 2, 1, 0,
	})
	var registerBody map[string]any
	srv := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url":        "http://" + r.Host,
				"aweb_url":              "http://" + r.Host + "/api",
				"registry_url":          "http://registry.example.test",
				"team_registration_url": "http://" + r.Host + "/api/v1/teams/service-register",
				"features":              []string{"teams"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/teams/service-register":
			if err := json.NewDecoder(r.Body).Decode(&registerBody); err != nil {
				t.Fatalf("decode register body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dry_run":      false,
				"status":       "created",
				"awid_team_id": "circle:juanreyero.com",
				"team_did_key": awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)),
				"next_steps": []map[string]any{{
					"label":    "Initialize",
					"command":  "aw service init --service http://" + r.Host + " --team circle:juanreyero.com",
					"required": true,
				}},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))

	out, err := executeTeamRegister(
		context.Background(),
		teamKey,
		"circle:juanreyero.com",
		srv.URL,
		false,
		"2026-05-25T12:00:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := `{"awid_team_id":"circle:juanreyero.com","dry_run":false,"operation":"team_service_register","service_url":"` + srv.URL + `","timestamp":"2026-05-25T12:00:00Z"}`
	if out.CanonicalPayload != wantCanonical {
		t.Fatalf("canonical payload mismatch:\n got: %s\nwant: %s", out.CanonicalPayload, wantCanonical)
	}
	if out.ControllerDID != awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("controller did mismatch")
	}
	if got := registerBody["service_url"]; got != srv.URL {
		t.Fatalf("posted service_url=%v want %s", got, srv.URL)
	}
	sig, err := base64.RawStdEncoding.DecodeString(registerBody["controller_signature"].(string))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(teamKey.Public().(ed25519.PublicKey), []byte(out.CanonicalPayload), sig) {
		t.Fatal("posted controller signature does not verify")
	}
	if len(out.NextSteps) != 1 || !strings.Contains(out.NextSteps[0].Command, "aw service init") {
		t.Fatalf("next steps not preserved: %+v", out.NextSteps)
	}
}

func TestRunTeamRegisterUsesDiscoveredRegistryForLocalKeyCheck(t *testing.T) {
	teamKey := ed25519.NewKeyFromSeed([]byte{
		31, 30, 29, 28, 27, 26, 25, 24,
		23, 22, 21, 20, 19, 18, 17, 16,
		15, 14, 13, 12, 11, 10, 9, 8,
		7, 6, 5, 4, 3, 2, 1, 0,
	})
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")
	writeTeamKeyForTest(t, home, "juanreyero.com", "circle", teamKey)

	registryHits := 0
	registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registryHits++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/juanreyero.com/teams/circle" {
			t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":      "circle:juanreyero.com",
			"domain":       "juanreyero.com",
			"name":         "circle",
			"display_name": "Circle",
			"team_did_key": teamDID,
			"visibility":   "private",
			"created_at":   "2026-05-25T12:00:00Z",
		})
	}))

	var posted bool
	service := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url":        "http://" + r.Host,
				"aweb_url":              "http://" + r.Host + "/api",
				"registry_url":          registry.URL,
				"team_registration_url": "http://" + r.Host + "/api/v1/teams/service-register",
				"features":              []string{"teams"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/teams/service-register":
			posted = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dry_run":      false,
				"status":       "created",
				"awid_team_id": "circle:juanreyero.com",
				"team_did_key": teamDID,
			})
		default:
			t.Fatalf("unexpected service request %s %s", r.Method, r.URL.Path)
		}
	}))

	oldTeam := teamRegisterTeam
	oldService := teamRegisterServiceURL
	oldRegistry := teamRegisterRegistryURL
	oldTimestamp := teamRegisterTimestamp
	oldDryRun := teamRegisterDryRun
	teamRegisterTeam = "circle:juanreyero.com"
	teamRegisterServiceURL = service.URL
	teamRegisterRegistryURL = ""
	teamRegisterTimestamp = "2026-05-25T12:00:00Z"
	teamRegisterDryRun = false
	t.Cleanup(func() {
		teamRegisterTeam = oldTeam
		teamRegisterServiceURL = oldService
		teamRegisterRegistryURL = oldRegistry
		teamRegisterTimestamp = oldTimestamp
		teamRegisterDryRun = oldDryRun
	})

	if err := runTeamRegister(&cobra.Command{}, nil); err != nil {
		t.Fatal(err)
	}
	if registryHits != 1 {
		t.Fatalf("registry hits=%d want 1", registryHits)
	}
	if !posted {
		t.Fatal("service registration endpoint was not called")
	}
}

func TestTeamImportRequestCommandDoesNotExposeAccessModeFlag(t *testing.T) {
	if flag := teamImportRequestCmd.Flags().Lookup("access-mode"); flag != nil {
		t.Fatal("BYOT import-request must not expose stale --access-mode flag")
	}
}

func TestExecuteTeamCleanupCloudSignsProjectionDeletePayload(t *testing.T) {
	t.Parallel()

	teamKey := ed25519.NewKeyFromSeed([]byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31,
	})
	pub := teamKey.Public().(ed25519.PublicKey)
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/teams/byoidt/projection-delete" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dry_run":                          false,
			"canonical_team_id":                "research:acme.com",
			"team_id":                          "server-team-id",
			"agents_deleted":                   2,
			"workspaces_deleted":               2,
			"cloud_workspace_metadata_deleted": 2,
			"team_members_deleted":             1,
			"byot_authorizations_deleted":      0,
			"team_deleted":                     true,
			"audit_id":                         "audit-1",
		})
	}))
	defer server.Close()

	out, err := executeTeamCleanupCloud(
		context.Background(),
		teamKey,
		"team",
		"research:acme.com",
		false,
		"2026-05-24T12:00:00Z",
		server.URL,
	)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "deleted" || out.TeamID != "research:acme.com" || !out.TeamDeleted {
		t.Fatalf("unexpected output: %+v", out)
	}
	if gotBody["awid_team_id"] != "research:acme.com" || gotBody["dry_run"] != false {
		t.Fatalf("unexpected body: %#v", gotBody)
	}
	canonical, err := awid.CanonicalJSONValue(map[string]any{
		"operation":    "byoidt_projection_delete",
		"awid_team_id": "research:acme.com",
		"dry_run":      false,
		"timestamp":    "2026-05-24T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, ok := gotBody["controller_signature"].(string)
	if !ok || signature == "" {
		t.Fatalf("missing controller_signature in %#v", gotBody)
	}
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatal("cleanup signature does not verify against canonical projection-delete payload")
	}
}

func TestExecuteTeamCleanupCloudCanSignWithNamespaceControllerScope(t *testing.T) {
	t.Parallel()

	namespaceKey := ed25519.NewKeyFromSeed([]byte{
		31, 30, 29, 28, 27, 26, 25, 24,
		23, 22, 21, 20, 19, 18, 17, 16,
		15, 14, 13, 12, 11, 10, 9, 8,
		7, 6, 5, 4, 3, 2, 1, 0,
	})
	pub := namespaceKey.Public().(ed25519.PublicKey)
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/teams/byoidt/projection-delete" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dry_run":                          true,
			"canonical_team_id":                "research:acme.com",
			"team_id":                          "server-team-id",
			"agents_deleted":                   1,
			"workspaces_deleted":               1,
			"cloud_workspace_metadata_deleted": 1,
			"team_members_deleted":             1,
			"byot_authorizations_deleted":      0,
			"team_deleted":                     true,
		})
	}))
	defer server.Close()

	out, err := executeTeamCleanupCloud(
		context.Background(),
		namespaceKey,
		"namespace",
		"research:acme.com",
		true,
		"2026-05-24T12:00:00Z",
		server.URL,
	)
	if err != nil {
		t.Fatal(err)
	}
	if out.ControllerScope != "namespace" || !out.DryRun {
		t.Fatalf("unexpected output: %+v", out)
	}
	if gotBody["controller_scope"] != "namespace" {
		t.Fatalf("expected namespace controller_scope in body, got %#v", gotBody)
	}
	canonical, err := awid.CanonicalJSONValue(map[string]any{
		"operation":        "byoidt_projection_delete",
		"awid_team_id":     "research:acme.com",
		"dry_run":          true,
		"timestamp":        "2026-05-24T12:00:00Z",
		"controller_scope": "namespace",
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, ok := gotBody["controller_signature"].(string)
	if !ok || signature == "" {
		t.Fatalf("missing controller_signature in %#v", gotBody)
	}
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatal("namespace cleanup signature does not verify against scoped canonical payload")
	}
}

func TestLoadTeamCleanupCloudNamespaceKeyVerifiesDNSController(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := ed25519.NewKeyFromSeed([]byte{
		3, 1, 4, 1, 5, 9, 2, 6,
		5, 3, 5, 8, 9, 7, 9, 3,
		2, 3, 8, 4, 6, 2, 6, 4,
		3, 3, 8, 3, 2, 7, 9, 5,
	})
	controllerDID := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	writeControllerKeyForTest(t, home, "acme.com", key)

	priorResolver := teamCleanupCloudTXTResolver
	teamCleanupCloudTXTResolver = staticTXTResolver{
		"_awid.acme.com": {"awid=v1; controller=" + controllerDID + ";"},
	}
	t.Cleanup(func() { teamCleanupCloudTXTResolver = priorResolver })

	loaded, err := loadTeamCleanupCloudNamespaceKey(context.Background(), "acme.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if awid.ComputeDIDKey(loaded.Public().(ed25519.PublicKey)) != controllerDID {
		t.Fatal("loaded wrong namespace controller key")
	}
}

func TestTeamCreateRegistersAtRegistry(t *testing.T) {
	t.Parallel()

	var gotPayload map[string]any
	var gotNamespacePayload map[string]any
	var gotAuthHeader string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			if err := json.NewDecoder(r.Body).Decode(&gotNamespacePayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"domain":         "acme.com",
				"controller_did": gotNamespacePayload["controller_did"],
				"created_at":     "2026-04-06T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			gotAuthHeader = r.Header.Get("Authorization")
			if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "backend:acme.com",
				"domain":       "acme.com",
				"name":         gotPayload["name"],
				"team_did_key": gotPayload["team_did_key"],
				"created_at":   "2026-04-06T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Create controller key (prerequisite for team create)
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeControllerKeyForTest(t, tmp, "acme.com", controllerKey)

	run := exec.CommandContext(ctx, bin, "id", "team", "create",
		"--name", "Backend",
		"--namespace", "Acme.com",
		"--display-name", "Backend Team",
		"--registry", server.URL,
		"--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("team create failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "created" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", got["team_id"])
	}
	if got["team_did_key"] == "" || got["team_did_key"] == nil {
		t.Fatal("team_did_key is empty")
	}
	if gotPayload["name"] != "backend" {
		t.Fatalf("registry payload name=%v", gotPayload["name"])
	}
	if gotNamespacePayload["domain"] != "acme.com" {
		t.Fatalf("namespace payload domain=%v", gotNamespacePayload["domain"])
	}
	if !strings.HasPrefix(gotAuthHeader, "DIDKey ") {
		t.Fatalf("expected DIDKey auth, got %q", gotAuthHeader)
	}

	// Verify team key was stored on disk
	teamKeyPath := filepath.Join(tmp, ".awid", "team-keys", "acme.com", "backend.key")
	if _, err := os.Stat(teamKeyPath); err != nil {
		t.Fatalf("team key missing: %v", err)
	}
}

func TestBootstrapFirstLocalTeamMemberCreatesTeamAndRegistersCertificate(t *testing.T) {
	var gotNamespacePayload map[string]any
	var gotCreatePayload map[string]any
	var gotCertPayload map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			if err := json.NewDecoder(r.Body).Decode(&gotNamespacePayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"domain":         "acme.com",
				"controller_did": gotNamespacePayload["controller_did"],
				"created_at":     "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			if err := json.NewDecoder(r.Body).Decode(&gotCreatePayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:acme.com",
				"domain":       "acme.com",
				"name":         "default",
				"team_did_key": gotCreatePayload["team_did_key"],
				"created_at":   "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/default/certificates":
			if err := json.NewDecoder(r.Body).Decode(&gotCertPayload); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	t.Setenv("HOME", t.TempDir())
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.SetFallbackRegistryURL(server.URL); err != nil {
		t.Fatal(err)
	}

	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := bootstrapFirstLocalTeamMember(ctx, registry, "", "acme.com", "default", "", controllerKey, memberKey, awid.ComputeStableID(memberPub), "acme.com/alice", "alice")
	if err != nil {
		t.Fatalf("bootstrapFirstLocalTeamMember: %v", err)
	}
	if result.TeamID != "default:acme.com" {
		t.Fatalf("team_id=%q", result.TeamID)
	}
	if result.Certificate == nil {
		t.Fatal("expected certificate")
	}
	if result.Certificate.MemberDIDKey != awid.ComputeDIDKey(memberPub) {
		t.Fatalf("member_did_key=%q", result.Certificate.MemberDIDKey)
	}
	if result.Certificate.MemberAddress != "acme.com/alice" {
		t.Fatalf("member_address=%q", result.Certificate.MemberAddress)
	}
	if gotNamespacePayload["domain"] != "acme.com" {
		t.Fatalf("namespace payload domain=%v", gotNamespacePayload["domain"])
	}
	if result.Certificate.Alias != "alice" {
		t.Fatalf("alias=%q", result.Certificate.Alias)
	}
	if gotCreatePayload["name"] != "default" {
		t.Fatalf("create payload name=%v", gotCreatePayload["name"])
	}
	if gotCertPayload["member_address"] != "acme.com/alice" {
		t.Fatalf("cert payload member_address=%v", gotCertPayload["member_address"])
	}
	if gotCertPayload["alias"] != "alice" {
		t.Fatalf("cert payload alias=%v", gotCertPayload["alias"])
	}
	if gotCertPayload["identity_scope"] != awid.IdentityModeGlobal {
		t.Fatalf("cert payload lifetime=%v", gotCertPayload["identity_scope"])
	}

	teamKeyPath, err := awconfig.TeamKeyPath("acme.com", "default")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(teamKeyPath); err != nil {
		t.Fatalf("team key missing: %v", err)
	}
}

func TestTeamInviteAndAcceptInviteFlow(t *testing.T) {
	t.Parallel()

	var registeredCert map[string]any
	var memberDIDKey string
	var memberStableID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-alice",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          memberStableID,
				"current_did_key": memberDIDKey,
				"reachability":    "public",
				"created_at":      "2026-04-06T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Pre-create team key (normally done by team create)
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	// Pre-create agent identity (the accepting agent has an identity)
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey = awid.ComputeDIDKey(memberPub)
	memberStableID = awid.ComputeStableID(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       memberDIDKey,
		StableID:  memberStableID,
		Address:   "acme.com/alice",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-06T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}
	// Step 1: Create invite
	runInvite := exec.CommandContext(ctx, bin, "id", "team", "invite",
		"--team", "backend",
		"--namespace", "acme.com",
		"--persistent",
		"--json")
	runInvite.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	runInvite.Dir = tmp
	inviteOut, err := runInvite.CombinedOutput()
	if err != nil {
		t.Fatalf("team invite failed: %v\n%s", err, string(inviteOut))
	}

	var inviteGot map[string]any
	if err := json.Unmarshal(extractJSON(t, inviteOut), &inviteGot); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(inviteOut))
	}
	if inviteGot["status"] != "created" {
		t.Fatalf("invite status=%v", inviteGot["status"])
	}
	token, ok := inviteGot["token"].(string)
	if !ok || token == "" {
		t.Fatal("invite token is empty")
	}

	// Step 2: Accept invite. This local-controller invite has team-key authority
	// but no namespace-controller authority, so global reuse must suppress the
	// default team-domain address claim explicitly.
	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", token, "--global", "--no-address", "--json")
	runAccept.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	runAccept.Dir = tmp
	acceptOut, err := runAccept.CombinedOutput()
	if err != nil {
		t.Fatalf("accept-invite failed: %v\n%s", err, string(acceptOut))
	}

	var acceptGot map[string]any
	if err := json.Unmarshal(extractJSON(t, acceptOut), &acceptGot); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(acceptOut))
	}
	if acceptGot["status"] != "accepted" {
		t.Fatalf("accept status=%v", acceptGot["status"])
	}
	if acceptGot["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", acceptGot["team_id"])
	}
	if acceptGot["alias"] != "alice" {
		t.Fatalf("alias=%v", acceptGot["alias"])
	}

	// Verify certificate was saved to disk
	certPath := awconfig.TeamCertificatePath(tmp, "backend:acme.com")
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	if cert.Team != "backend:acme.com" {
		t.Fatalf("cert team_id=%q", cert.Team)
	}
	if cert.MemberDIDKey != memberDIDKey {
		t.Fatalf("cert member_did_key=%q want %q", cert.MemberDIDKey, memberDIDKey)
	}
	if cert.Alias != "alice" {
		t.Fatalf("cert alias=%q", cert.Alias)
	}
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load teams state: %v", err)
	}
	if teamState.ActiveTeam != "backend:acme.com" {
		t.Fatalf("active_team=%q", teamState.ActiveTeam)
	}
	if membership := teamState.Membership("backend:acme.com"); membership == nil {
		t.Fatal("expected backend team membership in teams.yaml")
	} else if strings.TrimSpace(membership.CertPath) == "" {
		t.Fatal("teams.yaml membership missing cert_path")
	}

	// Verify certificate was registered at awid
	if registeredCert["member_did_key"] != memberDIDKey {
		t.Fatalf("registry cert member_did_key=%v", registeredCert["member_did_key"])
	}

	// Verify certificate signature
	teamPub := teamKey.Public().(ed25519.PublicKey)
	if err := awid.VerifyTeamCertificate(cert, teamPub); err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
}

func TestTeamInviteDefaultsToActiveTeamAndLocal(t *testing.T) {
	t.Parallel()

	var registeredCert map[string]any
	var connectCalls int
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "backend:acme.com",
				"alias":        "bob",
				"agent_id":     "agent-bob",
				"workspace_id": "workspace-bob",
				"repo_id":      "",
				"team_did_key": "did:key:z6MkiTeam",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_id":        "instructions-1",
				"active_team_instructions_id": "instructions-1",
				"version":                     1,
				"document": map[string]any{
					"body_md": "Use aw mail inbox and aw chat pending.",
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-bob", "backend:acme.com", "bob")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	home := t.TempDir()
	inviterDir := filepath.Join(home, "alice")
	acceptDir := filepath.Join(home, "bob")
	if err := os.MkdirAll(inviterDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(acceptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, home, "acme.com", "backend", teamKey)
	writeWorkspaceBindingForTest(t, inviterDir, awconfig.WorktreeWorkspace{
		AwebURL: server.URL,
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "alice",
			WorkspaceID: "workspace-alice",
			CertPath:    awconfig.TeamCertificateRelativePath("backend:acme.com"),
			JoinedAt:    "2026-05-16T00:00:00Z",
		}},
	})
	writeIdentityForTest(t, inviterDir, awconfig.WorktreeIdentity{
		DID:         "did:key:z6MkiR5hWfjt7SeH1Zs3xJMp5YowQbK5xkYH5BXMxHnXj1aA",
		StableID:    "did:aw:alice",
		Address:     "acme.com/alice",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: server.URL,
		CreatedAt:   "2026-05-16T00:00:00Z",
	})

	runInvite := exec.CommandContext(ctx, bin, "id", "team", "invite")
	runInvite.Env = testCommandEnv(home)
	runInvite.Dir = inviterDir
	inviteOut, err := runInvite.CombinedOutput()
	if err != nil {
		t.Fatalf("team invite failed: %v\n%s", err, string(inviteOut))
	}
	token := ""
	for _, line := range strings.Split(string(inviteOut), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Command:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[1] == "aw" && fields[4] == "accept-invite" {
			token = fields[5]
		}
	}
	if token == "" {
		t.Fatalf("invite output did not include accept command with token:\n%s", string(inviteOut))
	}

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", token, "--name", "bob", "--json")
	runAccept.Env = testCommandEnv(home)
	runAccept.Dir = acceptDir
	acceptOut, err := runAccept.CombinedOutput()
	if err != nil {
		t.Fatalf("accept-invite failed: %v\n%s", err, string(acceptOut))
	}
	var acceptGot map[string]any
	if err := json.Unmarshal(extractJSON(t, acceptOut), &acceptGot); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(acceptOut))
	}
	if acceptGot["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", acceptGot["team_id"])
	}
	if acceptGot["alias"] != "bob" {
		t.Fatalf("alias=%v", acceptGot["alias"])
	}

	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(acceptDir, "backend:acme.com"))
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	wantLifetime := awid.LifetimeEphemeral
	if cert.Lifetime != wantLifetime {
		t.Fatalf("lifetime=%q want %q", cert.Lifetime, wantLifetime)
	}
	if cert.MemberDIDAW != "" || cert.MemberAddress != "" {
		t.Fatalf("local cert should not include global identity fields: did_aw=%q address=%q", cert.MemberDIDAW, cert.MemberAddress)
	}
	requireWorktreeEncryptionKeyForTest(t, acceptDir)
	if registeredCert["identity_scope"] != awid.IdentityModeLocal {
		t.Fatalf("registry lifetime=%v", registeredCert["identity_scope"])
	}
	teamState, err := awconfig.LoadTeamState(acceptDir)
	if err != nil {
		t.Fatalf("load teams state: %v", err)
	}
	membership := teamState.Membership("backend:acme.com")
	if membership == nil {
		t.Fatal("accepted invite did not write team membership")
	}
	if membership.RegistryURL != server.URL {
		t.Fatalf("membership registry_url=%q want %q", membership.RegistryURL, server.URL)
	}
	if membership.AwebURL != server.URL {
		t.Fatalf("membership aweb_url=%q want %q", membership.AwebURL, server.URL)
	}

	runInit := exec.CommandContext(ctx, bin, "init")
	runInit.Env = testCommandEnv(home)
	runInit.Dir = acceptDir
	initOut, err := runInit.CombinedOutput()
	if err != nil {
		t.Fatalf("init after accept-invite failed: %v\n%s", err, string(initOut))
	}
	if connectCalls != 1 {
		t.Fatalf("connect calls=%d", connectCalls)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(acceptDir, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if workspace.AwebURL != server.URL {
		t.Fatalf("workspace aweb_url=%q want %q", workspace.AwebURL, server.URL)
	}
	agentsDoc, err := os.ReadFile(filepath.Join(acceptDir, "AGENTS.md"))
	if err != nil {
		t.Fatalf("expected aw init to create AGENTS.md by default: %v\n%s", err, string(initOut))
	}
	if !strings.Contains(string(agentsDoc), awDocsMarkerStart) || !strings.Contains(string(agentsDoc), "Use aw mail inbox and aw chat pending.") {
		t.Fatalf("AGENTS.md missing marked aw instructions:\n%s", string(agentsDoc))
	}
}

func TestTeamInviteHostedUsesCloudAuthorityWithoutLocalTeamKey(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	teamID := "default:gracehosted.aweb.ai"
	var createAuthHadCert bool
	var acceptVerifiedDID bool
	var connectCalls int
	_, hostedTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/create-invite":
			cert := requireCertificateAuthForTest(t, r)
			if cert.Team != teamID {
				t.Fatalf("create invite cert team=%q want %q", cert.Team, teamID)
			}
			createAuthHadCert = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id":      "invite-hosted-1",
				"token":          "aw_inv_hosted_test_token",
				"token_prefix":   "hosted_t",
				"access_mode":    "open",
				"max_uses":       1,
				"expires_at":     "2026-05-17T00:00:00Z",
				"namespace_slug": "gracehosted",
				"namespace":      "gracehosted.aweb.ai",
				"server_url":     server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/accept-invite":
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatal(err)
			}
			didKey, _ := req["did"].(string)
			if didKey == "" {
				t.Fatal("accept request missing did")
			}
			timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
			parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
			if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != didKey {
				t.Fatalf("bad accept auth header %q", r.Header.Get("Authorization"))
			}
			if !verifyCloudDIDPayload(t, mustExtractPublicKey(t, didKey), http.MethodPost, "/api/v1/spawn/accept-invite", timestamp, body, parts[2]) {
				t.Fatal("accept invite signature did not verify")
			}
			acceptVerifiedDID = true

			cert, err := awid.SignTeamCertificate(hostedTeamKey, awid.TeamCertificateFields{
				Team:         teamID,
				MemberDIDKey: didKey,
				Alias:        "bob",
				Lifetime:     awid.LifetimeEphemeral,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":        "server-team-id",
				"team_slug":      "default",
				"namespace_slug": "gracehosted",
				"namespace":      "gracehosted.aweb.ai",
				"identity_id":    "agent-bob",
				"alias":          "bob",
				"api_key":        "aw_sk_child_not_printed",
				"server_url":     server.URL,
				"did":            didKey,
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "open",
				"created":        true,
				"team_cert":      encoded,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      teamID,
				"alias":        "bob",
				"agent_id":     "agent-bob",
				"workspace_id": "workspace-bob",
				"repo_id":      "",
				"team_did_key": "did:key:z6MkiTeam",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_id":        "instructions-1",
				"active_team_instructions_id": "instructions-1",
				"version":                     1,
				"document": map[string]any{
					"body_md": "Use aw mail inbox and aw chat pending.",
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-bob", "backend:acme.com", "bob")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	home := t.TempDir()
	inviterDir := filepath.Join(home, "alice")
	acceptDir := filepath.Join(home, "bob")
	if err := os.MkdirAll(inviterDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(acceptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, "aw")
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, inviterDir, awconfig.WorktreeWorkspace{
		AwebURL: server.URL,
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "alice",
			WorkspaceID: "workspace-alice",
			CertPath:    awconfig.TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-05-16T00:00:00Z",
		}},
	})

	runInvite := exec.CommandContext(ctx, bin, "id", "team", "invite", "--json")
	runInvite.Env = testCommandEnv(home)
	runInvite.Dir = inviterDir
	inviteOut, err := runInvite.CombinedOutput()
	if err != nil {
		t.Fatalf("hosted team invite failed: %v\n%s", err, string(inviteOut))
	}
	var inviteGot map[string]any
	if err := json.Unmarshal(extractJSON(t, inviteOut), &inviteGot); err != nil {
		t.Fatalf("invalid invite json: %v\n%s", err, string(inviteOut))
	}
	if inviteGot["token"] != "aw_inv_hosted_test_token" {
		t.Fatalf("token=%v", inviteGot["token"])
	}
	if !createAuthHadCert {
		t.Fatal("hosted create-invite did not use certificate auth")
	}

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", "aw_inv_hosted_test_token", "--name", "bob", "--json")
	runAccept.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL)
	runAccept.Dir = acceptDir
	acceptOut, err := runAccept.CombinedOutput()
	if err != nil {
		t.Fatalf("hosted accept-invite failed: %v\n%s", err, string(acceptOut))
	}
	var acceptGot map[string]any
	if err := json.Unmarshal(extractJSON(t, acceptOut), &acceptGot); err != nil {
		t.Fatalf("invalid accept json: %v\n%s", err, string(acceptOut))
	}
	if acceptGot["team_id"] != teamID {
		t.Fatalf("team_id=%v", acceptGot["team_id"])
	}
	if acceptGot["alias"] != "bob" {
		t.Fatalf("alias=%v", acceptGot["alias"])
	}
	if strings.Contains(string(acceptOut), "aw_sk_child_not_printed") {
		t.Fatalf("accept output leaked child api key:\n%s", string(acceptOut))
	}
	if !acceptVerifiedDID {
		t.Fatal("hosted accept-invite did not prove DID possession")
	}

	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(acceptDir, teamID))
	if err != nil {
		t.Fatalf("load accepted hosted cert: %v", err)
	}
	if cert.Alias != "bob" || cert.Lifetime != awid.LifetimeEphemeral {
		t.Fatalf("unexpected cert alias/lifetime: %q/%q", cert.Alias, cert.Lifetime)
	}
	if cert.MemberDIDAW != "" || cert.MemberAddress != "" {
		t.Fatalf("local workspace cert has global fields: %q %q", cert.MemberDIDAW, cert.MemberAddress)
	}
	requireWorktreeEncryptionKeyForTest(t, acceptDir)
	if _, err := os.Stat(filepath.Join(acceptDir, awconfig.DefaultWorktreeWorkspaceRelativePath())); !os.IsNotExist(err) {
		t.Fatalf("accept-invite should not create workspace.yaml before aw init, stat err=%v", err)
	}

	runInit := exec.CommandContext(ctx, bin, "init")
	runInit.Env = testCommandEnv(home)
	runInit.Dir = acceptDir
	initOut, err := runInit.CombinedOutput()
	if err != nil {
		t.Fatalf("init after hosted accept-invite failed: %v\n%s", err, string(initOut))
	}
	if connectCalls != 1 {
		t.Fatalf("connect calls=%d", connectCalls)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(acceptDir, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load accepted workspace: %v", err)
	}
	if workspace.AwebURL != server.URL {
		t.Fatalf("workspace aweb_url=%q want %q", workspace.AwebURL, server.URL)
	}
}

func TestTeamAcceptHostedInviteWithAddressCreatesGlobalIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	teamID := "default:globalhosted.aweb.ai"
	_, hostedTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var acceptedStableID string
	var expectedGlobalDID string
	var expectedGlobalStableID string
	var acceptBody map[string]any
	var acceptVerifiedDID bool
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/accept-invite":
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &acceptBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := acceptBody["did"].(string)
			if didKey != expectedGlobalDID {
				t.Fatalf("hosted global accept used did %q, want existing %q", didKey, expectedGlobalDID)
			}
			if acceptBody["stable_id"] != expectedGlobalStableID {
				t.Fatalf("stable_id=%v want %s", acceptBody["stable_id"], expectedGlobalStableID)
			}
			pub := mustExtractPublicKey(t, didKey)
			acceptedStableID = awid.ComputeStableID(pub)
			if acceptBody["identity_scope"] != awid.IdentityModeGlobal {
				t.Fatalf("identity_scope=%v", acceptBody["identity_scope"])
			}
			if acceptBody["name"] != "durable-child" {
				t.Fatalf("name=%v", acceptBody["name"])
			}
			if _, ok := acceptBody["alias"]; ok {
				t.Fatalf("global hosted accept should not send alias: %v", acceptBody["alias"])
			}
			claim, ok := acceptBody["atomic_address_claim"].(map[string]any)
			if !ok {
				t.Fatalf("global hosted accept missing atomic_address_claim: %v", acceptBody)
			}
			if claim["domain"] != "globalhosted.aweb.ai" || claim["address_name"] != "durable-child" {
				t.Fatalf("atomic claim address=%v/%v", claim["domain"], claim["address_name"])
			}
			if claim["did_aw"] != acceptedStableID || claim["current_did_key"] != didKey {
				t.Fatalf("atomic claim did=%v/%v want %s/%s", claim["did_aw"], claim["current_did_key"], acceptedStableID, didKey)
			}
			if claim["identity_custody"] != string(awid.AddressClaimCustodySelf) || claim["namespace_custody"] != string(awid.AddressClaimCustodyHostedCustodial) {
				t.Fatalf("atomic claim custody=%v/%v", claim["identity_custody"], claim["namespace_custody"])
			}
			if strings.TrimSpace(fmt.Sprint(claim["identity_signature"])) == "" {
				t.Fatal("atomic claim missing identity_signature")
			}
			if _, ok := claim["did_log_proof"].(map[string]any); !ok {
				t.Fatalf("atomic claim missing did_log_proof: %v", claim)
			}
			timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
			parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
			if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != didKey {
				t.Fatalf("bad accept auth header %q", r.Header.Get("Authorization"))
			}
			if !verifyCloudDIDPayload(t, pub, http.MethodPost, "/api/v1/spawn/accept-invite", timestamp, body, parts[2]) {
				t.Fatal("accept invite signature did not verify")
			}
			acceptVerifiedDID = true

			cert, err := awid.SignTeamCertificate(hostedTeamKey, awid.TeamCertificateFields{
				Team:          teamID,
				MemberDIDKey:  didKey,
				MemberDIDAW:   acceptedStableID,
				MemberAddress: "globalhosted.aweb.ai/durable-child",
				Alias:         "durable-child",
				Lifetime:      awid.LifetimePersistent,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":        "server-team-id",
				"team_slug":      "default",
				"namespace_slug": "globalhosted",
				"namespace":      "globalhosted.aweb.ai",
				"identity_id":    "agent-durable-child",
				"name":           "durable-child",
				"api_key":        "aw_sk_child_not_printed",
				"server_url":     server.URL,
				"did":            didKey,
				"stable_id":      acceptedStableID,
				"address":        "globalhosted.aweb.ai/durable-child",
				"custody":        "self",
				"identity_scope": awid.IdentityModeGlobal,
				"access_mode":    "open",
				"created":        true,
				"team_cert":      encoded,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	home := t.TempDir()
	acceptDir := filepath.Join(home, "durable")
	if err := os.MkdirAll(acceptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	globalPub, globalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	globalDID := awid.ComputeDIDKey(globalPub)
	globalStableID := awid.ComputeStableID(globalPub)
	expectedGlobalDID = globalDID
	expectedGlobalStableID = globalStableID
	writeIdentityForTest(t, acceptDir, awconfig.WorktreeIdentity{
		DID:            globalDID,
		StableID:       globalStableID,
		Address:        "globalhosted.aweb.ai/durable-child",
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryURL:    server.URL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-06-30T00:00:00Z",
	})
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(acceptDir), globalKey); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, "aw")
	buildAwBinary(t, ctx, bin)

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", "aw_inv_hosted_global_token",
		"--global",
		"--address", "globalhosted.aweb.ai/durable-child",
		"--json")
	runAccept.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL, "AWID_REGISTRY_URL="+server.URL)
	runAccept.Dir = acceptDir
	acceptOut, err := runAccept.CombinedOutput()
	if err != nil {
		t.Fatalf("hosted global accept-invite failed: %v\n%s", err, string(acceptOut))
	}
	if !acceptVerifiedDID {
		t.Fatal("hosted global accept-invite did not prove DID possession")
	}

	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(acceptDir, teamID))
	if err != nil {
		t.Fatalf("load accepted hosted global cert: %v", err)
	}
	if cert.Alias != "durable-child" || cert.Lifetime != awid.LifetimePersistent {
		t.Fatalf("unexpected cert alias/lifetime: %q/%q", cert.Alias, cert.Lifetime)
	}
	if cert.MemberDIDAW != acceptedStableID {
		t.Fatalf("cert member_did_aw=%q want %q", cert.MemberDIDAW, acceptedStableID)
	}
	if cert.MemberAddress != "globalhosted.aweb.ai/durable-child" {
		t.Fatalf("cert member_address=%q", cert.MemberAddress)
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(acceptDir, awconfig.DefaultWorktreeIdentityRelativePath()))
	if err != nil {
		t.Fatalf("load global identity.yaml: %v", err)
	}
	if identity.StableID != acceptedStableID || identity.Address != "globalhosted.aweb.ai/durable-child" {
		t.Fatalf("identity stable/address=%q/%q want %q/%q", identity.StableID, identity.Address, acceptedStableID, "globalhosted.aweb.ai/durable-child")
	}
	if identity.RegistryURL != server.URL {
		t.Fatalf("identity registry_url=%q want %q", identity.RegistryURL, server.URL)
	}
	requireWorktreeEncryptionKeyForTest(t, acceptDir)
	if _, err := os.Stat(filepath.Join(acceptDir, awconfig.DefaultWorktreeWorkspaceRelativePath())); !os.IsNotExist(err) {
		t.Fatalf("accept-invite should not create workspace.yaml before aw init, stat err=%v", err)
	}
}

func TestTeamAcceptHostedGlobalInviteRetryReusesPendingSigningKey(t *testing.T) {
	resetTeamAcceptInviteGlobals(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	acceptDir := filepath.Join(home, "retry-global")
	if err := os.MkdirAll(acceptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	teamID := "circle:globalhosted.aweb.ai"
	globalPub, globalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	globalDID := awid.ComputeDIDKey(globalPub)
	globalStableID := awid.ComputeStableID(globalPub)
	writeIdentityForTest(t, acceptDir, awconfig.WorktreeIdentity{
		DID:            globalDID,
		StableID:       globalStableID,
		Address:        "globalhosted.aweb.ai/retry-child",
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryStatus: "registered",
		CreatedAt:      "2026-06-30T00:00:00Z",
	})
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(acceptDir), globalKey); err != nil {
		t.Fatal(err)
	}
	_, hostedTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var firstDID string
	var firstStableID string
	var acceptCalls int
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/did" {
			t.Fatalf("hosted global retry must not use split DID registration")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/spawn/accept-invite" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		acceptCalls++
		var req awid.SpawnAcceptInviteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.AtomicAddressClaim == nil {
			t.Fatal("missing atomic_address_claim")
		}
		stableID := req.AtomicAddressClaim.DIDAW
		if acceptCalls == 1 {
			firstDID = req.DID
			firstStableID = stableID
			http.Error(w, `{"detail":"simulated post-awid failure"}`, http.StatusInternalServerError)
			return
		}
		if req.DID != firstDID || stableID != firstStableID {
			t.Fatalf("retry did/stable=%q/%q want %q/%q", req.DID, stableID, firstDID, firstStableID)
		}
		cert, err := awid.SignTeamCertificate(hostedTeamKey, awid.TeamCertificateFields{
			Team:          teamID,
			MemberDIDKey:  req.DID,
			MemberDIDAW:   stableID,
			MemberAddress: "globalhosted.aweb.ai/retry-child",
			Alias:         "retry-child",
			Lifetime:      awid.LifetimePersistent,
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := awid.EncodeTeamCertificateHeader(cert)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":        "server-team-id",
			"team_slug":      "default",
			"namespace_slug": "globalhosted",
			"namespace":      "globalhosted.aweb.ai",
			"identity_id":    "agent-retry-child",
			"name":           "retry-child",
			"api_key":        "aw_sk_child_not_printed",
			"server_url":     server.URL,
			"did":            req.DID,
			"stable_id":      stableID,
			"address":        "globalhosted.aweb.ai/retry-child",
			"custody":        "self",
			"identity_scope": awid.IdentityModeGlobal,
			"access_mode":    "open",
			"created":        true,
			"team_cert":      encoded,
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = acceptHostedTeamInviteWithDetails(acceptDir, "aw_inv_retry_global", teamAcceptInviteOptions{Address: "globalhosted.aweb.ai/retry-child", Scope: awid.IdentityModeGlobal})
	if err == nil {
		t.Fatal("first accept should fail")
	}
	assertPathExists(t, awconfig.WorktreeSigningKeyPath(acceptDir))

	accepted, err := acceptHostedTeamInviteWithDetails(acceptDir, "aw_inv_retry_global", teamAcceptInviteOptions{Address: "globalhosted.aweb.ai/retry-child", Scope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatalf("retry accept: %v", err)
	}
	if accepted.Certificate.MemberDIDAW != firstStableID {
		t.Fatalf("accepted stable=%q want %q", accepted.Certificate.MemberDIDAW, firstStableID)
	}
	if acceptCalls != 2 {
		t.Fatalf("accept calls=%d want 2", acceptCalls)
	}
}

func TestTeamAcceptHostedLocalInviteRetryReusesPendingSigningKey(t *testing.T) {
	resetTeamAcceptInviteGlobals(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	acceptDir := filepath.Join(home, "retry-local")
	if err := os.MkdirAll(acceptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	teamID := "circle:gracehosted.aweb.ai"
	_, hostedTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var firstDID string
	var acceptCalls int
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/spawn/accept-invite" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		acceptCalls++
		var req awid.SpawnAcceptInviteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if acceptCalls == 1 {
			// AC committed, but the CLI fails after the POST.
			firstDID = req.DID
			http.Error(w, `{"detail":"simulated post-awid failure"}`, http.StatusInternalServerError)
			return
		}
		// The retry must present the SAME did:key (the persisted key), so AC's
		// key-aware branch re-mints idempotently instead of 409-ing on a new key.
		if req.DID != firstDID {
			t.Fatalf("retry did=%q want %q (must reuse the persisted key)", req.DID, firstDID)
		}
		cert, err := awid.SignTeamCertificate(hostedTeamKey, awid.TeamCertificateFields{
			Team:         teamID,
			MemberDIDKey: req.DID,
			Alias:        "retry-child",
			Lifetime:     awid.LifetimeEphemeral,
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := awid.EncodeTeamCertificateHeader(cert)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":        "server-team-id",
			"team_slug":      "default",
			"namespace_slug": "gracehosted",
			"namespace":      "gracehosted.aweb.ai",
			"identity_id":    "agent-retry-child",
			"alias":          "retry-child",
			"api_key":        "aw_sk_child_not_printed",
			"server_url":     server.URL,
			"did":            req.DID,
			"custody":        "self",
			"lifetime":       "ephemeral",
			"access_mode":    "open",
			"created":        true,
			"team_cert":      encoded,
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = acceptHostedTeamInviteWithDetails(acceptDir, "aw_inv_retry_local", teamAcceptInviteOptions{Name: "retry-child", Scope: awid.IdentityModeLocal})
	if err == nil {
		t.Fatal("first accept should fail")
	}
	// The fix persists the generated signing key BEFORE the AC POST, so it
	// survives a post-commit failure and the retry presents the same did:key.
	assertPathExists(t, awconfig.WorktreeSigningKeyPath(acceptDir))

	accepted, err := acceptHostedTeamInviteWithDetails(acceptDir, "aw_inv_retry_local", teamAcceptInviteOptions{Name: "retry-child", Scope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatalf("retry accept: %v", err)
	}
	if got := strings.TrimSpace(accepted.Output.Alias); got != "retry-child" {
		t.Fatalf("accepted alias=%q want retry-child", got)
	}
	if acceptCalls != 2 {
		t.Fatalf("accept calls=%d want 2", acceptCalls)
	}
}

func TestTeamInviteWithoutServiceContextDoesNotUseHostedFallback(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	runInvite := exec.CommandContext(ctx, bin, "id", "team", "invite",
		"--team", "alpha",
		"--namespace", "alpha.test.local",
		"--global",
		"--json")
	runInvite.Env = idCreateCommandEnv(tmp)
	runInvite.Dir = tmp
	out, err := runInvite.CombinedOutput()
	if err == nil {
		t.Fatalf("expected invite to fail without local team key")
	}
	text := string(out)
	if !strings.Contains(text, "no team key for alpha.test.local/alpha") {
		t.Fatalf("expected local-controller key error, got:\n%s", text)
	}
	if strings.Contains(text, "--global is not supported for hosted team invites") {
		t.Fatalf("non-hosted invite without service context used hosted fallback:\n%s", text)
	}
}

func TestTeamInviteWithLocalTeamKeySupportsGlobalWithoutServiceContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "alpha.test.local", "alpha", teamKey)

	runInvite := exec.CommandContext(ctx, bin, "id", "team", "invite",
		"--team", "alpha",
		"--namespace", "alpha.test.local",
		"--global",
		"--json")
	runInvite.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL=http://localhost:8310")
	runInvite.Dir = tmp
	out, err := runInvite.CombinedOutput()
	if err != nil {
		t.Fatalf("team invite failed: %v\n%s", err, string(out))
	}
	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "created" {
		t.Fatalf("status=%v want created", got["status"])
	}
	token, _ := got["token"].(string)
	if token == "" {
		t.Fatalf("token missing in output: %v", got)
	}
}

func TestHostedTeamAcceptInviteRefusesExistingIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), signingKey); err != nil {
		t.Fatal(err)
	}
	// A bare signing key WITH the pending-accept marker is reused on retry
	// (TestTeamAcceptHostedLocalInviteRetryReusesPendingSigningKey); without the
	// marker it is refused as stray (TestHostedTeamAcceptInviteRefusesStrayBareKey).
	// What must not be clobbered is a COMPLETED identity, so add an identity.yaml.
	identityPath := filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath())
	if err := os.MkdirAll(filepath.Dir(identityPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, []byte("did_key: did:key:zExisting\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", "aw_inv_refuse_existing", "--name", "bob")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL=http://127.0.0.1:1")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected hosted accept-invite to refuse existing identity:\n%s", string(out))
	}
	if !strings.Contains(string(out), "refusing to overwrite existing") || !strings.Contains(string(out), "identity.yaml") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestHostedTeamAcceptInviteRetryAllowsPendingKeyWithSavedCertificateNoIdentity(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), signingKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostedAcceptPendingMarkerPath(tmp), []byte("pending hosted accept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamID := "default:partial.aweb.ai"
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  awid.ComputeDIDKey(pub),
		MemberDIDAW:   awid.ComputeStableID(pub),
		MemberAddress: "partial.aweb.ai/recover",
		Alias:         "recover",
		Lifetime:      awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, teamID, cert); err != nil {
		t.Fatal(err)
	}

	reusedPub, _, err := hostedAcceptSigningKey(tmp)
	if err != nil {
		t.Fatalf("hostedAcceptSigningKey should allow marked partial cert recovery: %v", err)
	}
	if got, want := awid.ComputeDIDKey(reusedPub), awid.ComputeDIDKey(pub); got != want {
		t.Fatalf("reused DID=%q want %q", got, want)
	}
}

func TestHostedTeamAcceptInvitePartialCertWithoutMarkerGivesRecoveryGuidance(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), signingKey); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamID := "default:partial.aweb.ai"
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  awid.ComputeDIDKey(pub),
		MemberDIDAW:   awid.ComputeStableID(pub),
		MemberAddress: "partial.aweb.ai/recover",
		Alias:         "recover",
		Lifetime:      awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, teamID, cert); err != nil {
		t.Fatal(err)
	}

	_, _, err = hostedAcceptSigningKey(tmp)
	if err == nil {
		t.Fatal("expected unmarked partial cert state to be refused")
	}
	for _, want := range []string{
		"not a pending hosted accept",
		".aw/team-certs",
		".aw/identity.yaml",
		"back up/remove",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestHostedTeamAcceptInviteRefusesStrayBareKey(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// A bare signing key with no pending-accept marker is a stray leftover, not a
	// genuine pending hosted accept (aabq.13 reuses pending keys for retry-safety;
	// aabq.26 distinguishes the two via the marker). The accept must refuse it
	// rather than silently adopt an unrelated key.
	_, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), signingKey); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", "aw_inv_stray", "--name", "bob")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL=http://127.0.0.1:1")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected accept-invite to refuse a stray bare key:\n%s", string(out))
	}
	if !strings.Contains(string(out), "not a pending hosted accept") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestTeamAcceptInviteLocalRejectsSecondTeam(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()
	if err := awconfig.SaveTeamState(workingDir, &awconfig.TeamState{
		ActiveTeam:  "one:acme.com",
		Memberships: []awconfig.TeamMembership{{TeamID: "one:acme.com", Alias: "alice", CertPath: ".aw/team-certs/one_acme.com.jwt"}},
	}); err != nil {
		t.Fatal(err)
	}
	_, err := acceptHostedTeamInviteWithDetails(workingDir, "aw_inv_second_local", teamAcceptInviteOptions{Name: "bob", Scope: awid.IdentityModeLocal})
	if err == nil || !strings.Contains(err.Error(), "local identities can only join one team") {
		t.Fatalf("expected local one-team guard, got %v", err)
	}
}

func TestTeamAcceptInviteGlobalWithoutIdentityErrorsToIDCreate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()
	_, err := acceptHostedTeamInviteWithDetails(workingDir, "aw_inv_no_identity", teamAcceptInviteOptions{Name: "alice", Scope: awid.IdentityModeGlobal, Address: "globalhosted.aweb.ai/alice"})
	if err == nil || !strings.Contains(err.Error(), "aw id create") {
		t.Fatalf("expected aw id create guidance, got %v", err)
	}
}

func TestHostedGlobalAcceptNoAddressUsesExistingStableID(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()
	teamID := "default:globalhosted.aweb.ai"
	globalPub, globalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	globalDID := awid.ComputeDIDKey(globalPub)
	globalStableID := awid.ComputeStableID(globalPub)
	writeIdentityForTest(t, workingDir, awconfig.WorktreeIdentity{
		DID:            globalDID,
		StableID:       globalStableID,
		Address:        "globalhosted.aweb.ai/alice",
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryStatus: "registered",
		CreatedAt:      "2026-06-30T00:00:00Z",
	})
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), globalKey); err != nil {
		t.Fatal(err)
	}
	_, hostedTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var acceptVerifiedDID bool
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/spawn/accept-invite" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var reqMap map[string]any
		if err := json.Unmarshal(body, &reqMap); err != nil {
			t.Fatal(err)
		}
		if reqMap["did"] != globalDID {
			t.Fatalf("did=%v want %s", reqMap["did"], globalDID)
		}
		if reqMap["stable_id"] != globalStableID {
			t.Fatalf("stable_id=%v want %s", reqMap["stable_id"], globalStableID)
		}
		if reqMap["identity_scope"] != awid.IdentityModeGlobal {
			t.Fatalf("identity_scope=%v", reqMap["identity_scope"])
		}
		if reqMap["name"] != "alice" {
			t.Fatalf("name=%v", reqMap["name"])
		}
		if _, ok := reqMap["alias"]; ok {
			t.Fatalf("global hosted no-address accept should not send alias: %v", reqMap["alias"])
		}
		if _, ok := reqMap["atomic_address_claim"]; ok {
			t.Fatalf("global hosted no-address accept should not send atomic_address_claim: %v", reqMap["atomic_address_claim"])
		}
		timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
		if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != globalDID {
			t.Fatalf("bad accept auth header %q", r.Header.Get("Authorization"))
		}
		if !verifyCloudDIDPayload(t, globalPub, http.MethodPost, "/api/v1/spawn/accept-invite", timestamp, body, parts[2]) {
			t.Fatal("accept invite signature did not verify")
		}
		acceptVerifiedDID = true

		cert, err := awid.SignTeamCertificate(hostedTeamKey, awid.TeamCertificateFields{
			Team:          teamID,
			MemberDIDKey:  globalDID,
			MemberDIDAW:   globalStableID,
			Alias:         "alice",
			Lifetime:      awid.LifetimePersistent,
			IdentityScope: awid.IdentityModeGlobal,
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := awid.EncodeTeamCertificateHeader(cert)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":        "server-team-id",
			"team_slug":      "default",
			"namespace_slug": "globalhosted",
			"namespace":      "globalhosted.aweb.ai",
			"identity_id":    "agent-alice",
			"name":           "alice",
			"api_key":        "aw_sk_child_not_printed",
			"server_url":     server.URL,
			"did":            globalDID,
			"stable_id":      globalStableID,
			"custody":        "self",
			"identity_scope": awid.IdentityModeGlobal,
			"access_mode":    "open",
			"created":        true,
			"team_cert":      encoded,
		})
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)

	accepted, err := acceptHostedTeamInviteWithDetails(workingDir, "aw_inv_no_address", teamAcceptInviteOptions{Name: "alice", Scope: awid.IdentityModeGlobal, NoAddress: true})
	if err != nil {
		t.Fatalf("hosted global no-address accept: %v", err)
	}
	if !acceptVerifiedDID {
		t.Fatal("hosted global no-address accept did not prove DID possession")
	}
	if accepted.Certificate.MemberDIDAW != globalStableID {
		t.Fatalf("cert member_did_aw=%q want %q", accepted.Certificate.MemberDIDAW, globalStableID)
	}
	if accepted.Certificate.MemberAddress != "" {
		t.Fatalf("cert member_address=%q want empty", accepted.Certificate.MemberAddress)
	}
	storedCert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(workingDir, teamID))
	if err != nil {
		t.Fatalf("load persisted no-address cert: %v", err)
	}
	if storedCert.MemberDIDAW != globalStableID || storedCert.MemberAddress != "" {
		t.Fatalf("persisted cert did_aw/address=%q/%q", storedCert.MemberDIDAW, storedCert.MemberAddress)
	}
	if _, err := os.Stat(filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())); !os.IsNotExist(err) {
		t.Fatalf("accept-invite should not create workspace.yaml before aw init, stat err=%v", err)
	}
}

func TestTeamAcceptInviteGlobalDefaultClaimUsesNamespaceAuthority(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()

	oldPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(pub)
	memberDIDAW := awid.ComputeStableID(oldPub)
	writeIdentityForTest(t, workingDir, awconfig.WorktreeIdentity{
		DID:            memberDID,
		StableID:       memberDIDAW,
		Address:        "otherco.com/alice",
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryStatus: "registered",
		CreatedAt:      "2026-06-30T00:00:00Z",
	})
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), memberKey); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, home, "acme.com", "backend", teamKey)
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeControllerKeyForTest(t, home, "acme.com", controllerKey)

	var claimDryRuns []bool
	var events []string
	var sawCert bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+memberDIDAW+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          memberDIDAW,
				"current_did_key": memberDID,
				"log_head": map[string]any{
					"seq":              2,
					"operation":        "rotate_key",
					"previous_did_key": awid.ComputeDIDKey(oldPub),
					"new_did_key":      memberDID,
					"prev_entry_hash":  "prevhash",
					"entry_hash":       "entryhash",
					"state_hash":       "statehash",
					"authorized_by":    memberDID,
					"timestamp":        "2026-06-30T00:00:00Z",
					"signature":        "sig",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/addresses/claims":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			dryRun := payload["dry_run"] == true
			claimDryRuns = append(claimDryRuns, dryRun)
			if dryRun {
				events = append(events, "claim-dry-run")
			} else {
				events = append(events, "claim-apply")
			}
			if payload["did_aw"] != memberDIDAW || payload["current_did_key"] != memberDID || payload["address_name"] != "alice" {
				t.Fatalf("claim payload=%+v", payload)
			}
			proof, _ := payload["did_log_proof"].(map[string]any)
			if proof["operation"] != "rotate_key" || proof["new_did_key"] != memberDID {
				t.Fatalf("did_log_proof=%+v", proof)
			}
			status, addressStatus := "claimed", "created"
			if dryRun {
				status, addressStatus = "available", "would_create"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": status, "dry_run": dryRun, "domain": "acme.com", "name": "alice", "did_aw": memberDIDAW, "current_did_key": memberDID,
				"did_status": "existing", "address_status": addressStatus,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/backend/certificates":
			events = append(events, "register-certificate")
			sawCert = true
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["member_did_aw"] != memberDIDAW || payload["member_address"] != "acme.com/alice" || payload["identity_scope"] != awid.IdentityModeGlobal {
				t.Fatalf("cert payload=%+v", payload)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{InviteID: inviteID, Domain: "acme.com", TeamName: "backend", Secret: secret, RegistryURL: server.URL, CreatedAt: "2026-06-30T00:00:00Z"}
	writeTeamInviteForTest(t, home, invite)
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := acceptTeamInviteWithDetails(workingDir, token, teamAcceptInviteOptions{Name: "alice", Scope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatalf("acceptTeamInviteWithDetails: %v", err)
	}
	if !sawCert || len(claimDryRuns) != 2 || !claimDryRuns[0] || claimDryRuns[1] {
		t.Fatalf("sawCert=%v claimDryRuns=%v", sawCert, claimDryRuns)
	}
	if got, want := strings.Join(events, ","), "claim-dry-run,claim-apply,register-certificate"; got != want {
		t.Fatalf("default claim order=%s want %s", got, want)
	}
	if accepted.Certificate.MemberDIDAW != memberDIDAW || accepted.Certificate.MemberAddress != "acme.com/alice" {
		t.Fatalf("cert global fields=%q/%q", accepted.Certificate.MemberDIDAW, accepted.Certificate.MemberAddress)
	}
}

func TestTeamAcceptInviteGlobalDefaultClaimResumesAfterClaimRollbackFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()

	oldPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(pub)
	memberDIDAW := awid.ComputeStableID(oldPub)
	writeIdentityForTest(t, workingDir, awconfig.WorktreeIdentity{
		DID:            memberDID,
		StableID:       memberDIDAW,
		Address:        "otherco.com/alice",
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryStatus: "registered",
		CreatedAt:      "2026-06-30T00:00:00Z",
	})
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), memberKey); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, home, "acme.com", "backend", teamKey)
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeControllerKeyForTest(t, home, "acme.com", controllerKey)

	addressExists := false
	certificateAttempts := 0
	deleteAttempts := 0
	var events []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+memberDIDAW+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": memberDIDAW, "current_did_key": memberDID,
				"log_head": map[string]any{
					"seq": 2, "operation": "rotate_key", "previous_did_key": awid.ComputeDIDKey(oldPub),
					"new_did_key": memberDID, "prev_entry_hash": strings.Repeat("a", 64), "entry_hash": strings.Repeat("b", 64),
					"state_hash": strings.Repeat("c", 64), "authorized_by": awid.ComputeDIDKey(oldPub),
					"timestamp": "2026-06-30T00:00:00Z", "signature": "sig",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/addresses/claims":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			dryRun := payload["dry_run"] == true
			status, addressStatus := "available", "would_create"
			if addressExists {
				status, addressStatus = "already_applied", "existing"
			} else if !dryRun {
				addressExists = true
				status, addressStatus = "claimed", "created"
			}
			events = append(events, fmt.Sprintf("claim-%t-%s", dryRun, addressStatus))
			response := map[string]any{
				"status": status, "dry_run": dryRun, "domain": "acme.com", "name": "alice",
				"did_aw": memberDIDAW, "current_did_key": memberDID,
				"did_status": "existing", "address_status": addressStatus,
			}
			if !dryRun {
				response["address"] = map[string]any{
					"address_id": "claim-address-id", "domain": "acme.com", "name": "alice",
					"did_aw": memberDIDAW, "current_did_key": memberDID,
				}
			}
			_ = json.NewEncoder(w).Encode(response)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/backend/certificates":
			certificateAttempts++
			if certificateAttempts == 1 {
				events = append(events, "certificate-failed")
				http.Error(w, "certificate rejected", http.StatusBadRequest)
				return
			}
			events = append(events, "certificate-registered")
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			deleteAttempts++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["expected_address_id"] != "claim-address-id" || payload["expected_did_aw"] != memberDIDAW || payload["expected_current_did_key"] != memberDID {
				t.Fatalf("conditional rollback payload=%+v", payload)
			}
			events = append(events, "rollback-failed")
			http.Error(w, "address changed since it was claimed", http.StatusConflict)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{InviteID: inviteID, Domain: "acme.com", TeamName: "backend", Secret: secret, RegistryURL: server.URL, CreatedAt: "2026-06-30T00:00:00Z"}
	writeTeamInviteForTest(t, home, invite)
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}

	_, err = acceptTeamInviteWithDetails(workingDir, token, teamAcceptInviteOptions{Name: "alice", Scope: awid.IdentityModeGlobal})
	if err == nil || !strings.Contains(err.Error(), "newly claimed") || !strings.Contains(err.Error(), "rollback failed") || !strings.Contains(err.Error(), "retry the same invite") {
		t.Fatalf("first failure lacks honest recovery state: %v", err)
	}
	if !addressExists {
		t.Fatal("failed rollback should leave the claimed address for retry")
	}

	accepted, err := acceptTeamInviteWithDetails(workingDir, token, teamAcceptInviteOptions{Name: "alice", Scope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatalf("retry should reuse the existing claim: %v", err)
	}
	if accepted.Certificate.MemberAddress != "acme.com/alice" {
		t.Fatalf("accepted address=%q", accepted.Certificate.MemberAddress)
	}
	if certificateAttempts != 2 || deleteAttempts != 1 {
		t.Fatalf("certificate attempts=%d delete attempts=%d", certificateAttempts, deleteAttempts)
	}
	wantEvents := "claim-true-would_create,claim-false-created,certificate-failed,rollback-failed,claim-true-existing,claim-false-existing,certificate-registered"
	if got := strings.Join(events, ","); got != wantEvents {
		t.Fatalf("resume events=%s want %s", got, wantEvents)
	}
}

func TestRollbackDefaultAddressClaimDeletesOnlyNewlyCreatedAddress(t *testing.T) {
	var deleteAttempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/namespaces/acme.com/addresses/alice" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		deleteAttempts++
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["expected_address_id"] != "claim-address-id" || payload["expected_did_aw"] != "did:aw:claim" || payload["expected_current_did_key"] != "did:key:claim" {
			t.Fatalf("conditional delete payload=%+v", payload)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	registry := awid.NewAWIDRegistryClient(server.Client(), nil)
	claim := &awid.AtomicAddressClaimParams{
		Domain:                        "acme.com",
		AddressName:                   "alice",
		NamespaceControllerSigningKey: controllerKey,
	}
	cause := errors.New("certificate registration failed")

	err = rollbackDefaultAddressClaimAfterCertificateFailure(
		registry,
		server.URL,
		claim,
		&awid.AtomicAddressClaimResult{
			AddressStatus: "created",
			Address: &awid.RegistryAddress{
				AddressID: "claim-address-id", DIDAW: "did:aw:claim", CurrentDIDKey: "did:key:claim",
			},
		},
		cause,
	)
	if err == nil || !strings.Contains(err.Error(), "newly claimed default address acme.com/alice was rolled back") {
		t.Fatalf("successful rollback error=%v", err)
	}
	if deleteAttempts != 1 {
		t.Fatalf("delete attempts=%d want 1", deleteAttempts)
	}

	err = rollbackDefaultAddressClaimAfterCertificateFailure(
		registry,
		server.URL,
		claim,
		&awid.AtomicAddressClaimResult{AddressStatus: "existing"},
		cause,
	)
	if !errors.Is(err, cause) {
		t.Fatalf("pre-existing claim error=%v want cause", err)
	}
	if deleteAttempts != 1 {
		t.Fatalf("pre-existing claim was deleted: attempts=%d", deleteAttempts)
	}
}

func TestTeamAcceptInviteAddressOverrideUsesRegisteredAddress(t *testing.T) {
	t.Parallel()

	var registeredCert map[string]any
	var memberDIDKey string
	var memberStableID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/otherco.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-otherco-alice",
				"domain":          "otherco.com",
				"name":            "alice",
				"did_aw":          memberStableID,
				"current_did_key": memberDIDKey,
				"reachability":    "public",
				"created_at":      "2026-04-16T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey = awid.ComputeDIDKey(memberPub)
	memberStableID = awid.ComputeStableID(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       memberDIDKey,
		StableID:  memberStableID,
		Address:   "acme.com/alice",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-16T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}

	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{
		InviteID:    inviteID,
		Domain:      "acme.com",
		TeamName:    "backend",
		Secret:      secret,
		RegistryURL: server.URL,
		CreatedAt:   "2026-04-16T00:00:00Z",
	}
	writeTeamInviteForTest(t, tmp, invite)
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", token,
		"--global",
		"--address", "otherco.com/alice",
		"--json")
	runAccept.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	runAccept.Dir = tmp
	acceptOut, err := runAccept.CombinedOutput()
	if err != nil {
		t.Fatalf("accept-invite failed: %v\n%s", err, string(acceptOut))
	}

	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "backend:acme.com"))
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	if cert.MemberAddress != "otherco.com/alice" {
		t.Fatalf("cert member_address=%q", cert.MemberAddress)
	}
	if registeredCert["member_address"] != "otherco.com/alice" {
		t.Fatalf("registry cert member_address=%v", registeredCert["member_address"])
	}
	if registeredCert["member_did_aw"] != memberStableID {
		t.Fatalf("registry cert member_did_aw=%v", registeredCert["member_did_aw"])
	}
}

func TestTeamAcceptInviteRejectsAddressOnLocalInvite(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "local", "default", teamKey)

	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{
		InviteID:  inviteID,
		Domain:    "local",
		TeamName:  "default",
		Ephemeral: true,
		Secret:    secret,
		CreatedAt: "2026-04-16T00:00:00Z",
	}
	writeTeamInviteForTest(t, tmp, invite)
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", token,
		"--name", "gsk",
		"--address", "local/gsk")
	runAccept.Env = idCreateCommandEnv(tmp)
	runAccept.Dir = tmp
	acceptOut, err := runAccept.CombinedOutput()
	if err == nil {
		t.Fatalf("expected accept-invite to fail:\n%s", string(acceptOut))
	}
	if !strings.Contains(string(acceptOut), "--address requires --global") {
		t.Fatalf("unexpected output:\n%s", string(acceptOut))
	}
	if _, err := os.Stat(awconfig.TeamCertificatePath(tmp, "default:local")); !os.IsNotExist(err) {
		t.Fatalf("local cert should not be written, stat err=%v", err)
	}
}

func TestTeamAcceptInviteAddressOverrideRejectsDifferentDID(t *testing.T) {
	t.Parallel()

	var registerCalls int
	var memberDIDKey string
	var memberStableID string
	otherDIDAW := "did:aw:other"
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/otherco.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-otherco-alice",
				"domain":          "otherco.com",
				"name":            "alice",
				"did_aw":          otherDIDAW,
				"current_did_key": memberDIDKey,
				"reachability":    "public",
				"created_at":      "2026-04-16T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			registerCalls++
			t.Fatalf("certificate should not be registered when address ownership mismatches")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey = awid.ComputeDIDKey(memberPub)
	memberStableID = awid.ComputeStableID(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       memberDIDKey,
		StableID:  memberStableID,
		Address:   "acme.com/alice",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-16T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}

	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{
		InviteID:    inviteID,
		Domain:      "acme.com",
		TeamName:    "backend",
		Secret:      secret,
		RegistryURL: server.URL,
		CreatedAt:   "2026-04-16T00:00:00Z",
	}
	writeTeamInviteForTest(t, tmp, invite)
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", token,
		"--global",
		"--address", "otherco.com/alice")
	runAccept.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	runAccept.Dir = tmp
	acceptOut, err := runAccept.CombinedOutput()
	if err == nil {
		t.Fatalf("expected accept-invite to fail:\n%s", string(acceptOut))
	}
	if !strings.Contains(string(acceptOut), `member address otherco.com/alice belongs to did:aw:other, not `+memberStableID) {
		t.Fatalf("unexpected output:\n%s", string(acceptOut))
	}
	if registerCalls != 0 {
		t.Fatalf("register calls=%d want 0", registerCalls)
	}
}

func TestLocalAcceptInviteRejectsPreseededGlobalIdentity(t *testing.T) {
	t.Parallel()

	registryCalls := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registryCalls++
		t.Fatalf("unexpected registry call for local accept with preseeded global identity: %s %s", r.Method, r.URL.Path)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "local", "default", teamKey)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := awid.ComputeDIDKey(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:           memberDIDKey,
		StableID:      awid.ComputeStableID(memberPub),
		Address:       "local/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-04-13T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}

	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{
		InviteID:    inviteID,
		Domain:      "local",
		TeamName:    "default",
		Ephemeral:   true,
		Secret:      secret,
		RegistryURL: server.URL,
		CreatedAt:   "2026-04-13T00:00:00Z",
	}
	writeTeamInviteForTest(t, tmp, invite)
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", token, "--json")
	runAccept.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	runAccept.Dir = tmp
	acceptOut, err := runAccept.CombinedOutput()
	if err == nil {
		t.Fatalf("expected accept-invite to fail:\n%s", string(acceptOut))
	}
	if !strings.Contains(string(acceptOut), "already has a global identity") || !strings.Contains(string(acceptOut), "--global") {
		t.Fatalf("unexpected output:\n%s", string(acceptOut))
	}
	if registryCalls != 0 {
		t.Fatalf("registry calls=%d want 0", registryCalls)
	}
	if _, err := os.Stat(awconfig.TeamCertificatePath(tmp, "default:local")); !os.IsNotExist(err) {
		t.Fatalf("local cert should not be written, stat err=%v", err)
	}
}

func TestTeamAddMemberFlow(t *testing.T) {
	t.Parallel()

	var registeredCert map[string]any
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := awid.ComputeDIDKey(memberPub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          "did:aw:test123",
				"current_did_key": memberDIDKey,
				"reachability":    "public",
				"created_at":      "2026-04-06T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Pre-create team key
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	run := exec.CommandContext(ctx, bin, "id", "team", "add-member",
		"--team", "backend",
		"--namespace", "acme.com",
		"--member", "acme.com/alice",
		"--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("add-member failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "added" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", got["team_id"])
	}
	if got["member"] != "acme.com/alice" {
		t.Fatalf("member=%v", got["member"])
	}
	if got["member_address"] != "acme.com/alice" {
		t.Fatalf("member_address=%v", got["member_address"])
	}
	if registeredCert["member_did_key"] != memberDIDKey {
		t.Fatalf("registry cert member_did_key=%v", registeredCert["member_did_key"])
	}
	if registeredCert["member_address"] != "acme.com/alice" {
		t.Fatalf("registry cert member_address=%v", registeredCert["member_address"])
	}
	if registeredCert["identity_scope"] != awid.IdentityModeGlobal {
		t.Fatalf("registry cert lifetime=%v", registeredCert["identity_scope"])
	}
	encodedCert, ok := registeredCert["certificate"].(string)
	if !ok || strings.TrimSpace(encodedCert) == "" {
		t.Fatalf("registry cert certificate blob missing: %v", registeredCert["certificate"])
	}
	decodedCert, err := awid.DecodeTeamCertificateHeader(encodedCert)
	if err != nil {
		t.Fatalf("decode registered certificate: %v", err)
	}
	if decodedCert.CertificateID != got["certificate_id"] {
		t.Fatalf("registered certificate_id=%q output=%v", decodedCert.CertificateID, got["certificate_id"])
	}
	if fetchCommand, ok := got["fetch_command"].(string); !ok || !strings.Contains(fetchCommand, "aw id team fetch-cert") || !strings.Contains(fetchCommand, decodedCert.CertificateID) {
		t.Fatalf("fetch_command=%v", got["fetch_command"])
	}
}

func TestTeamFetchCertInstallsFetchedCertificate(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	teamDID := awid.ComputeDIDKey(teamPub)
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:         "backend:acme.com",
		MemberDIDKey: memberDID,
		Alias:        "alice",
		Lifetime:     awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	encodedCert, err := awid.EncodeTeamCertificateHeader(cert)
	if err != nil {
		t.Fatal(err)
	}

	var gotAuth string
	var forceCert *awid.TeamCertificate
	var encodedForceCert string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/v1/namespaces/acme.com/teams/backend/certificates/") {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotAuth = strings.TrimSpace(r.Header.Get("Authorization"))
		certificateID := strings.TrimPrefix(r.URL.Path, "/v1/namespaces/acme.com/teams/backend/certificates/")
		responseCert := cert
		responseBlob := encodedCert
		if forceCert != nil && certificateID == forceCert.CertificateID {
			responseCert = forceCert
			responseBlob = encodedForceCert
		}
		if certificateID != responseCert.CertificateID {
			t.Fatalf("unexpected certificate fetch %s", certificateID)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":        "backend:acme.com",
			"certificate_id": responseCert.CertificateID,
			"member_did_key": memberDID,
			"alias":          "alice",
			"lifetime":       awid.LifetimePersistent,
			"issued_at":      responseCert.IssuedAt,
			"certificate":    responseBlob,
		})
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "team", "fetch-cert",
		"--team", "backend",
		"--namespace", "acme.com",
		"--cert-id", cert.CertificateID,
		"--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("fetch-cert failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "installed" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", got["team_id"])
	}
	if !strings.Contains(gotAuth, memberDID) {
		t.Fatalf("Authorization=%q", gotAuth)
	}

	installed, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "backend:acme.com"))
	if err != nil {
		t.Fatalf("load installed certificate: %v", err)
	}
	if installed.CertificateID != cert.CertificateID {
		t.Fatalf("installed certificate_id=%q", installed.CertificateID)
	}
	if installed.TeamDIDKey != teamDID {
		t.Fatalf("installed team_did_key=%q", installed.TeamDIDKey)
	}
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if teamState.ActiveTeam != "backend:acme.com" {
		t.Fatalf("active_team=%q", teamState.ActiveTeam)
	}
	if len(teamState.Memberships) != 1 || teamState.Memberships[0].CertPath == "" {
		t.Fatalf("memberships=%+v", teamState.Memberships)
	}
	requireWorktreeEncryptionKeyForTest(t, tmp)

	otherCert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:         "backend:acme.com",
		MemberDIDKey: memberDID,
		Alias:        "alice",
		Lifetime:     awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	runOverwrite := exec.CommandContext(ctx, bin, "id", "team", "fetch-cert",
		"--team", "backend",
		"--namespace", "acme.com",
		"--cert-id", otherCert.CertificateID,
		"--json")
	runOverwrite.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	runOverwrite.Dir = tmp
	overwriteOut, err := runOverwrite.CombinedOutput()
	if err == nil {
		t.Fatalf("expected fetch-cert overwrite to fail:\n%s", string(overwriteOut))
	}
	if !strings.Contains(string(overwriteOut), "--force") {
		t.Fatalf("overwrite error should mention --force:\n%s", string(overwriteOut))
	}

	forceCert = otherCert
	encodedForceCert, err = awid.EncodeTeamCertificateHeader(forceCert)
	if err != nil {
		t.Fatal(err)
	}
	runForce := exec.CommandContext(ctx, bin, "id", "team", "fetch-cert",
		"--team", "backend",
		"--namespace", "acme.com",
		"--cert-id", forceCert.CertificateID,
		"--force",
		"--json")
	runForce.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	runForce.Dir = tmp
	forceOut, err := runForce.CombinedOutput()
	if err != nil {
		t.Fatalf("fetch-cert --force failed: %v\n%s", err, string(forceOut))
	}
	installed, err = awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "backend:acme.com"))
	if err != nil {
		t.Fatalf("load force-installed certificate: %v", err)
	}
	if installed.CertificateID != forceCert.CertificateID {
		t.Fatalf("force-installed certificate_id=%q", installed.CertificateID)
	}
}

func TestTeamRemoveMemberFlow(t *testing.T) {
	t.Parallel()

	var gotRevokePayload map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/teams/backend/members/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":        "backend:acme.com",
				"certificate_id": "cert-42",
				"member_did_key": "did:key:z6MkAlice",
				"member_did_aw":  "did:aw:test123",
				"member_address": "acme.com/alice",
				"alias":          "alice",
				"lifetime":       "persistent",
				"issued_at":      "2026-04-06T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates/revoke"):
			if err := json.NewDecoder(r.Body).Decode(&gotRevokePayload); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Pre-create team key
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	run := exec.CommandContext(ctx, bin, "id", "team", "remove-member",
		"--team", "backend",
		"--namespace", "acme.com",
		"--member", "acme.com/alice",
		"--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("remove-member failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "removed" {
		t.Fatalf("status=%v", got["status"])
	}
	if gotRevokePayload["certificate_id"] != "cert-42" {
		t.Fatalf("revoke certificate_id=%v", gotRevokePayload["certificate_id"])
	}
}

func TestTeamRemoveMemberFlowCrossNamespaceMember(t *testing.T) {
	t.Parallel()

	var gotRevokePayload map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/teams/backend/members/bob":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":        "backend:acme.com",
				"certificate_id": "cert-cross",
				"member_did_key": "did:key:z6MkBob",
				"member_did_aw":  "did:aw:bob",
				"member_address": "partner.com/bob",
				"alias":          "bob",
				"lifetime":       "persistent",
				"issued_at":      "2026-04-06T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates/revoke"):
			if err := json.NewDecoder(r.Body).Decode(&gotRevokePayload); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	run := exec.CommandContext(ctx, bin, "id", "team", "remove-member",
		"--team", "backend",
		"--namespace", "acme.com",
		"--member", "partner.com/bob",
		"--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("remove-member failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "removed" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["member_address"] != "partner.com/bob" {
		t.Fatalf("member_address=%v", got["member_address"])
	}
	if gotRevokePayload["certificate_id"] != "cert-cross" {
		t.Fatalf("revoke certificate_id=%v", gotRevokePayload["certificate_id"])
	}
}

func TestTeamAddMemberByDIDIssuesLocalCertificate(t *testing.T) {
	t.Parallel()

	var registeredCert map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)

	run := exec.CommandContext(ctx, bin, "id", "team", "add-member",
		"--team", "backend",
		"--namespace", "acme.com",
		"--did", memberDID,
		"--name", "laptop",
		"--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("add-member by did failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "added" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", got["team_id"])
	}
	if got["member"] != memberDID {
		t.Fatalf("member=%v", got["member"])
	}
	if _, ok := got["member_address"]; ok {
		t.Fatalf("member_address should be omitted in DID path: %v", got["member_address"])
	}
	if registeredCert["member_did_key"] != memberDID {
		t.Fatalf("registry cert member_did_key=%v", registeredCert["member_did_key"])
	}
	if registeredCert["alias"] != "laptop" {
		t.Fatalf("registry cert alias=%v", registeredCert["alias"])
	}
	if registeredCert["identity_scope"] != awid.IdentityModeLocal {
		t.Fatalf("registry cert lifetime=%v", registeredCert["identity_scope"])
	}
	if _, ok := registeredCert["member_did_aw"]; ok {
		t.Fatalf("registry cert member_did_aw=%v", registeredCert["member_did_aw"])
	}
	if _, ok := registeredCert["member_address"]; ok {
		t.Fatalf("registry cert member_address=%v", registeredCert["member_address"])
	}
}

func TestTeamAddMemberByDIDIssuesGlobalCertificateWhenStableFieldsProvided(t *testing.T) {
	t.Parallel()

	var registeredCert map[string]any
	var memberDID string
	memberDIDAW := "did:aw:alice"
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-alice",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          memberDIDAW,
				"current_did_key": memberDID,
				"reachability":    "public",
				"created_at":      "2026-04-06T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID = awid.ComputeDIDKey(memberPub)

	run := exec.CommandContext(ctx, bin, "id", "team", "add-member",
		"--team", "backend",
		"--namespace", "acme.com",
		"--did", memberDID,
		"--name", "alice",
		"--lifetime", awid.LifetimePersistent,
		"--did-aw", memberDIDAW,
		"--address", "acme.com/alice",
		"--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("add-member by did global compatibility path failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["member"] != "acme.com/alice" {
		t.Fatalf("member=%v", got["member"])
	}
	if got["member_address"] != "acme.com/alice" {
		t.Fatalf("member_address=%v", got["member_address"])
	}
	if registeredCert["member_did_key"] != memberDID {
		t.Fatalf("registry cert member_did_key=%v", registeredCert["member_did_key"])
	}
	if registeredCert["member_did_aw"] != memberDIDAW {
		t.Fatalf("registry cert member_did_aw=%v", registeredCert["member_did_aw"])
	}
	if registeredCert["member_address"] != "acme.com/alice" {
		t.Fatalf("registry cert member_address=%v", registeredCert["member_address"])
	}
	if registeredCert["identity_scope"] != awid.IdentityModeGlobal {
		t.Fatalf("registry cert lifetime=%v", registeredCert["identity_scope"])
	}
}

func TestTeamAddMemberByDIDRejectsAddressForDifferentDID(t *testing.T) {
	t.Parallel()

	var registerCalls int
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	otherDIDAW := "did:aw:other"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-alice",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          otherDIDAW,
				"current_did_key": memberDID,
				"reachability":    "public",
				"created_at":      "2026-04-06T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			registerCalls++
			t.Fatalf("certificate should not be registered when address ownership mismatches")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	run := exec.CommandContext(ctx, bin, "id", "team", "add-member",
		"--team", "backend",
		"--namespace", "acme.com",
		"--did", memberDID,
		"--name", "alice",
		"--lifetime", awid.LifetimePersistent,
		"--did-aw", "did:aw:alice",
		"--address", "acme.com/alice")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected add-member to fail:\n%s", string(out))
	}
	if !strings.Contains(string(out), `member address acme.com/alice belongs to did:aw:other, not did:aw:alice`) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if registerCalls != 0 {
		t.Fatalf("register calls=%d want 0", registerCalls)
	}
}

func TestTeamAddMemberRejectsDidAndMemberTogether(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "id", "team", "add-member",
		"--team", "backend",
		"--namespace", "acme.com",
		"--member", "acme.com/alice",
		"--did", "did:key:z6Mkexample",
		"--name", "alice")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected add-member to fail:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--member and --did are mutually exclusive") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestTeamAddMemberByDIDRequiresAlias(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)

	run := exec.CommandContext(ctx, bin, "id", "team", "add-member",
		"--team", "backend",
		"--namespace", "acme.com",
		"--did", memberDID)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected add-member to fail:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--name is required when using --did") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestCertShow(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Create a certificate on disk
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:         "backend:acme.com",
		MemberDIDKey: awid.ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, "backend:acme.com", cert); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "cert", "show", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("cert show failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", got["team_id"])
	}
	if got["alias"] != "alice" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if got["certificate_id"] != cert.CertificateID {
		t.Fatalf("certificate_id=%v want %v", got["certificate_id"], cert.CertificateID)
	}
}

func TestTeamListMigratesLegacyWorkspaceYAML(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	workspacePath := filepath.Join(tmp, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if err := os.MkdirAll(filepath.Dir(workspacePath), 0o700); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(workspacePath, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai/api
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    role_name: backend
    workspace_id: ws-backend
    cert_path: team-certs/backend__acme.com.pem
    joined_at: "2026-04-13T00:00:00Z"
  - team_id: ops:acme.com
    alias: alice-ops
    role_name: ops
    workspace_id: ws-ops
    cert_path: team-certs/ops__acme.com.pem
    joined_at: "2026-04-14T00:00:00Z"
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	if _, err := os.Stat(awconfig.TeamStatePath(tmp)); !os.IsNotExist(err) {
		t.Fatalf("teams.yaml should not exist before list, stat err=%v", err)
	}

	run := exec.CommandContext(ctx, bin, "id", "team", "list", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("team list failed: %v\n%s", err, string(out))
	}

	var got struct {
		ActiveTeam  string         `json:"active_team"`
		Memberships []teamListItem `json:"memberships"`
	}
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid list json: %v\n%s", err, string(out))
	}
	if got.ActiveTeam != "backend:acme.com" {
		t.Fatalf("active_team=%q", got.ActiveTeam)
	}
	if len(got.Memberships) != 2 {
		t.Fatalf("memberships=%d want 2", len(got.Memberships))
	}

	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if teamState.Membership("backend:acme.com") == nil || teamState.Membership("ops:acme.com") == nil {
		t.Fatalf("unexpected migrated memberships: %#v", teamState.Memberships)
	}

	data, err := os.ReadFile(awconfig.TeamStatePath(tmp))
	if err != nil {
		t.Fatalf("read teams.yaml: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "workspace_id:") {
		t.Fatalf("teams.yaml should not contain workspace_id:\n%s", text)
	}
	if strings.Contains(text, "role_name:") {
		t.Fatalf("teams.yaml should not contain role_name:\n%s", text)
	}
}

func TestTeamAddSwitchListLeaveFlow(t *testing.T) {
	var registeredCert map[string]any
	var memberDIDKey string
	var memberStableID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-alice",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          memberStableID,
				"current_did_key": memberDIDKey,
				"reachability":    "public",
				"created_at":      "2026-04-09T00:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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
	memberDIDKey = awid.ComputeDIDKey(memberPub)
	memberStableID = awid.ComputeStableID(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:         memberDIDKey,
		StableID:    memberStableID,
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
	keyBefore, err := os.ReadFile(filepath.Join(tmp, ".aw", "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	identityBefore, err := os.ReadFile(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	writeTeamStateForTest(t, tmp, awconfig.TeamState{
		ActiveTeam: "backend:acme.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "backend:acme.com",
			Alias:    "alice",
			CertPath: awconfig.TeamCertificateRelativePath("backend:acme.com"),
			JoinedAt: "2026-04-09T00:00:00Z",
		}},
	})

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "ops", teamKey)
	_, token, err := createTeamInviteToken("acme.com", "ops", server.URL, "", false)
	if err != nil {
		t.Fatal(err)
	}

	runAdd := exec.CommandContext(ctx, bin, "id", "team", "add", token, "--json")
	runAdd.Env = testCommandEnv(tmp)
	runAdd.Dir = tmp
	addOut, err := runAdd.CombinedOutput()
	if err != nil {
		t.Fatalf("team add failed: %v\n%s", err, string(addOut))
	}

	var addGot map[string]any
	if err := json.Unmarshal(extractJSON(t, addOut), &addGot); err != nil {
		t.Fatalf("invalid add json: %v\n%s", err, string(addOut))
	}
	if addGot["team_id"] != "ops:acme.com" {
		t.Fatalf("team_id=%v", addGot["team_id"])
	}
	if registeredCert["member_did_key"] != memberDIDKey {
		t.Fatalf("registered cert member_did_key=%v", registeredCert["member_did_key"])
	}
	keyAfter, err := os.ReadFile(filepath.Join(tmp, ".aw", "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	identityAfter, err := os.ReadFile(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("signing.key changed during aw id team add")
	}
	if !bytes.Equal(identityBefore, identityAfter) {
		t.Fatal("identity.yaml changed during aw id team add")
	}

	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if teamState.ActiveTeam != "backend:acme.com" {
		t.Fatalf("active_team=%q", teamState.ActiveTeam)
	}
	if teamState.Membership("ops:acme.com") == nil {
		t.Fatal("expected ops team membership in teams.yaml")
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "workspace.yaml")); !os.IsNotExist(err) {
		t.Fatalf("workspace.yaml should not be created by aw id team add, stat err=%v", err)
	}

	runList := exec.CommandContext(ctx, bin, "id", "team", "list", "--json")
	runList.Env = testCommandEnv(tmp)
	runList.Dir = tmp
	listOut, err := runList.CombinedOutput()
	if err != nil {
		t.Fatalf("team list failed: %v\n%s", err, string(listOut))
	}
	var listGot struct {
		ActiveTeam  string         `json:"active_team"`
		Memberships []teamListItem `json:"memberships"`
	}
	if err := json.Unmarshal(extractJSON(t, listOut), &listGot); err != nil {
		t.Fatalf("invalid list json: %v\n%s", err, string(listOut))
	}
	if listGot.ActiveTeam != "backend:acme.com" || len(listGot.Memberships) != 2 {
		t.Fatalf("list=%+v", listGot)
	}

	runSwitch := exec.CommandContext(ctx, bin, "id", "team", "switch", "ops:acme.com", "--json")
	runSwitch.Env = testCommandEnv(tmp)
	runSwitch.Dir = tmp
	switchOut, err := runSwitch.CombinedOutput()
	if err != nil {
		t.Fatalf("team switch failed: %v\n%s", err, string(switchOut))
	}
	var switchGot map[string]any
	if err := json.Unmarshal(extractJSON(t, switchOut), &switchGot); err != nil {
		t.Fatalf("invalid switch json: %v\n%s", err, string(switchOut))
	}
	if switchGot["active_team"] != "ops:acme.com" {
		t.Fatalf("active_team=%v", switchGot["active_team"])
	}
	teamState, err = awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if teamState.ActiveTeam != "ops:acme.com" {
		t.Fatalf("teams active_team=%q", teamState.ActiveTeam)
	}

	runLeave := exec.CommandContext(ctx, bin, "id", "team", "leave", "ops:acme.com", "--json")
	runLeave.Env = testCommandEnv(tmp)
	runLeave.Dir = tmp
	leaveOut, err := runLeave.CombinedOutput()
	if err != nil {
		t.Fatalf("team leave failed: %v\n%s", err, string(leaveOut))
	}
	var leaveGot map[string]any
	if err := json.Unmarshal(extractJSON(t, leaveOut), &leaveGot); err != nil {
		t.Fatalf("invalid leave json: %v\n%s", err, string(leaveOut))
	}
	if leaveGot["active_team"] != "backend:acme.com" {
		t.Fatalf("active_team=%v", leaveGot["active_team"])
	}
	teamState, err = awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if teamState.Membership("ops:acme.com") != nil {
		t.Fatal("expected ops team removed from teams.yaml")
	}
	if _, err := os.Stat(awconfig.TeamCertificatePath(tmp, "ops:acme.com")); !os.IsNotExist(err) {
		t.Fatalf("ops cert should be removed, stat err=%v", err)
	}
}

func TestTeamSwitchWritesOnlyTeamsYAML(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	workspacePath := filepath.Join(tmp, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if err := os.MkdirAll(filepath.Dir(workspacePath), 0o700); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	workspaceBody := []byte(strings.TrimSpace(`
# Keep this comment to prove team switch does not rewrite workspace.yaml.
aweb_url: https://app.aweb.ai/api
active_team: backend:demo
memberships:
  - team_id: backend:demo
    alias: alice
    role_name: backend
    workspace_id: ws-backend
    cert_path: team-certs/backend__demo.pem
  - team_id: ops:demo
    alias: alice-ops
    role_name: ops
    workspace_id: ws-ops
    cert_path: team-certs/ops__demo.pem
`) + "\n")
	if err := os.WriteFile(workspacePath, workspaceBody, 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}
	writeTeamStateForTest(t, tmp, awconfig.TeamState{
		ActiveTeam: "backend:demo",
		Memberships: []awconfig.TeamMembership{
			{
				TeamID:   "backend:demo",
				Alias:    "alice",
				CertPath: awconfig.TeamCertificateRelativePath("backend:demo"),
			},
			{
				TeamID:   "ops:demo",
				Alias:    "alice-ops",
				CertPath: awconfig.TeamCertificateRelativePath("ops:demo"),
			},
		},
	})

	run := exec.CommandContext(ctx, bin, "id", "team", "switch", "ops:demo", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("team switch failed: %v\n%s", err, string(out))
	}
	var switchGot map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &switchGot); err != nil {
		t.Fatalf("invalid switch json: %v\n%s", err, string(out))
	}
	if switchGot["active_team"] != "ops:demo" {
		t.Fatalf("active_team=%v", switchGot["active_team"])
	}

	workspaceAfter, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatalf("read workspace after switch: %v", err)
	}
	if !bytes.Equal(workspaceAfter, workspaceBody) {
		t.Fatalf("workspace.yaml changed after team switch:\n%s", string(workspaceAfter))
	}
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if teamState.ActiveTeam != "ops:demo" {
		t.Fatalf("teams active_team=%q", teamState.ActiveTeam)
	}
}

func TestTeamLeaveRejectsOnlyMembership(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultTeamStateForTest(t, tmp)

	run := exec.CommandContext(ctx, bin, "id", "team", "leave", "backend:demo")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "cannot leave the only team") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestTeamSwitchAlreadyActiveIsNoOp(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultTeamStateForTest(t, tmp)

	teamStateBefore, err := os.ReadFile(awconfig.TeamStatePath(tmp))
	if err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "team", "switch", "backend:demo")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("team switch failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Team backend:demo is already active") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}

	teamStateAfter, err := os.ReadFile(awconfig.TeamStatePath(tmp))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(teamStateBefore, teamStateAfter) {
		t.Fatal("teams.yaml changed for already-active switch")
	}
}

func TestTeamSwitchRejectsUnknownMembershipWithAvailableTeams(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeTeamStateForTest(t, tmp, awconfig.TeamState{
		ActiveTeam: "backend:acme.com",
		Memberships: []awconfig.TeamMembership{
			{
				TeamID:   "backend:acme.com",
				Alias:    "alice",
				CertPath: awconfig.TeamCertificateRelativePath("backend:acme.com"),
				JoinedAt: "2026-04-09T00:00:00Z",
			},
			{
				TeamID:   "ops:acme.com",
				Alias:    "alice-ops",
				CertPath: awconfig.TeamCertificateRelativePath("ops:acme.com"),
				JoinedAt: "2026-04-09T00:00:00Z",
			},
		},
	})

	run := exec.CommandContext(ctx, bin, "id", "team", "switch", "unknown:acme.com")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), `team "unknown:acme.com" is not present in local team memberships; available: backend:acme.com, ops:acme.com`) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}
