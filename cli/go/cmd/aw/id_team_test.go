package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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
)

// writeControllerKeyForTest writes a controller key to the test HOME's config directory.
func writeControllerKeyForTest(t *testing.T, home, domain string, key ed25519.PrivateKey) {
	t.Helper()
	dir := filepath.Join(home, ".config", "aw", "controllers")
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

// writeTeamKeyForTest writes a team key to the test HOME's config directory.
func writeTeamKeyForTest(t *testing.T, home, domain, name string, key ed25519.PrivateKey) {
	t.Helper()
	dir := filepath.Join(home, ".config", "aw", "team-keys", awconfig.NormalizeDomain(domain))
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
		"~/.config/aw/team-keys/<namespace>/<team>.key",
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
	oldAccessMode := teamImportRequestAccessMode
	oldTimestamp := teamImportRequestTimestamp
	oldApply := teamImportRequestApply
	teamImportRequestTeam = team
	teamImportRequestNamespace = namespace
	teamImportRequestOrganizationID = "org-1"
	teamImportRequestCloudTeamID = ""
	teamImportRequestAccessMode = "open"
	teamImportRequestTimestamp = "2026-05-09T12:00:00Z"
	teamImportRequestApply = false
	t.Cleanup(func() {
		teamImportRequestTeam = oldTeam
		teamImportRequestNamespace = oldNamespace
		teamImportRequestOrganizationID = oldOrganizationID
		teamImportRequestCloudTeamID = oldCloudTeamID
		teamImportRequestAccessMode = oldAccessMode
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
		"~/.config/aw/team-keys/<namespace>/<team>.key",
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
		"open",
		"2026-05-09T12:00:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}

	wantCanonical := `{"access_mode":"open","awid_team_id":"research:acme.com","dry_run":true,"operation":"byoidt_import","organization_id":"org-1","team_id":"","timestamp":"2026-05-09T12:00:00Z"}`
	if out.CanonicalPayload != wantCanonical {
		t.Fatalf("canonical payload mismatch:\n got: %s\nwant: %s", out.CanonicalPayload, wantCanonical)
	}
	if out.ControllerDID != awid.ComputeDIDKey(pub) {
		t.Fatalf("controller did=%q want %q", out.ControllerDID, awid.ComputeDIDKey(pub))
	}
	if out.ControllerDID != "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd" {
		t.Fatalf("controller did interop vector changed: %q", out.ControllerDID)
	}
	const wantSignature = "5mdXJbmrncZUuu6701IZDBUZfonfChxtdTn3JZ/bVz+79CkMOaosWSaNq5OD23U6LOHzQTuka9RraSOvS0gcCA"
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
}

func TestTeamCreateRegistersAtRegistry(t *testing.T) {
	t.Parallel()

	var gotPayload map[string]any
	var gotAuthHeader string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
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
	if !strings.HasPrefix(gotAuthHeader, "DIDKey ") {
		t.Fatalf("expected DIDKey auth, got %q", gotAuthHeader)
	}

	// Verify team key was stored on disk
	teamKeyPath := filepath.Join(tmp, ".config", "aw", "team-keys", "acme.com", "backend.key")
	if _, err := os.Stat(teamKeyPath); err != nil {
		t.Fatalf("team key missing: %v", err)
	}
}

func TestBootstrapFirstLocalTeamMemberCreatesTeamAndRegistersCertificate(t *testing.T) {
	var gotCreatePayload map[string]any
	var gotCertPayload map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
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

	// Step 2: Accept invite
	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", token, "--json")
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

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", token, "--alias", "bob", "--json")
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

	runAccept := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", "aw_inv_hosted_test_token", "--alias", "bob", "--json")
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

	run := exec.CommandContext(ctx, bin, "id", "team", "accept-invite", "aw_inv_refuse_existing", "--alias", "bob")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL=http://127.0.0.1:1")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected hosted accept-invite to refuse existing identity:\n%s", string(out))
	}
	if !strings.Contains(string(out), "refusing to overwrite existing") || !strings.Contains(string(out), ".aw/signing.key") {
		t.Fatalf("unexpected output:\n%s", string(out))
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
		"--alias", "gsk",
		"--address", "local/gsk")
	runAccept.Env = idCreateCommandEnv(tmp)
	runAccept.Dir = tmp
	acceptOut, err := runAccept.CombinedOutput()
	if err == nil {
		t.Fatalf("expected accept-invite to fail:\n%s", string(acceptOut))
	}
	if !strings.Contains(string(acceptOut), "--address is only valid for global invites") {
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

func TestLocalAcceptInviteIgnoresPreseededIdentityStableFields(t *testing.T) {
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
	writeTeamKeyForTest(t, tmp, "local", "default", teamKey)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := awid.ComputeDIDKey(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       memberDIDKey,
		StableID:  awid.ComputeStableID(memberPub),
		Address:   "local/alice",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-13T00:00:00Z",
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
	if err != nil {
		t.Fatalf("accept-invite failed: %v\n%s", err, string(acceptOut))
	}

	certPath := awconfig.TeamCertificatePath(tmp, "default:local")
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	if cert.Lifetime != awid.LifetimeEphemeral {
		t.Fatalf("cert lifetime=%q", cert.Lifetime)
	}
	if cert.MemberDIDKey != memberDIDKey {
		t.Fatalf("cert member_did_key=%q want %q", cert.MemberDIDKey, memberDIDKey)
	}
	if cert.MemberDIDAW != "" {
		t.Fatalf("cert member_did_aw=%q", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "" {
		t.Fatalf("cert member_address=%q", cert.MemberAddress)
	}
	if _, ok := registeredCert["member_did_aw"]; ok {
		t.Fatalf("registered cert member_did_aw=%v", registeredCert["member_did_aw"])
	}
	if _, ok := registeredCert["member_address"]; ok {
		t.Fatalf("registered cert member_address=%v", registeredCert["member_address"])
	}
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load teams state: %v", err)
	}
	if membership := teamState.Membership("default:local"); membership == nil {
		t.Fatal("expected local team membership in teams.yaml")
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
		"--alias", "laptop",
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
		"--alias", "alice",
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
		"--alias", "alice",
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
		"--alias", "alice")
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
	if !strings.Contains(string(out), "--alias is required when using --did") {
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
