package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"net/http"
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
	if gotCertPayload["lifetime"] != awid.LifetimePersistent {
		t.Fatalf("cert payload lifetime=%v", gotCertPayload["lifetime"])
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

func TestTeamAcceptInviteRejectsAddressOnEphemeralInvite(t *testing.T) {
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
	if !strings.Contains(string(acceptOut), "--address is only valid for persistent invites") {
		t.Fatalf("unexpected output:\n%s", string(acceptOut))
	}
	if _, err := os.Stat(awconfig.TeamCertificatePath(tmp, "default:local")); !os.IsNotExist(err) {
		t.Fatalf("ephemeral cert should not be written, stat err=%v", err)
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

func TestEphemeralAcceptInviteIgnoresPreseededIdentityStableFields(t *testing.T) {
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
	if registeredCert["lifetime"] != awid.LifetimePersistent {
		t.Fatalf("registry cert lifetime=%v", registeredCert["lifetime"])
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

func TestTeamAddMemberByDIDIssuesEphemeralCertificate(t *testing.T) {
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
	if registeredCert["lifetime"] != awid.LifetimeEphemeral {
		t.Fatalf("registry cert lifetime=%v", registeredCert["lifetime"])
	}
	if _, ok := registeredCert["member_did_aw"]; ok {
		t.Fatalf("registry cert member_did_aw=%v", registeredCert["member_did_aw"])
	}
	if _, ok := registeredCert["member_address"]; ok {
		t.Fatalf("registry cert member_address=%v", registeredCert["member_address"])
	}
}

func TestTeamAddMemberByDIDIssuesPersistentCertificateWhenStableFieldsProvided(t *testing.T) {
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
		t.Fatalf("add-member by did persistent failed: %v\n%s", err, string(out))
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
	if registeredCert["lifetime"] != awid.LifetimePersistent {
		t.Fatalf("registry cert lifetime=%v", registeredCert["lifetime"])
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

func TestTeamListMigratesMembershipsFromWorkspaceYAML(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai/api",
		ActiveTeam: "backend:acme.com",
		Memberships: []awconfig.WorktreeMembership{
			{
				TeamID:      "backend:acme.com",
				Alias:       "alice",
				WorkspaceID: "ws-backend",
				CertPath:    awconfig.TeamCertificateRelativePath("backend:acme.com"),
				JoinedAt:    "2026-04-13T00:00:00Z",
			},
			{
				TeamID:      "ops:acme.com",
				Alias:       "alice-ops",
				WorkspaceID: "ws-ops",
				CertPath:    awconfig.TeamCertificateRelativePath("ops:acme.com"),
				JoinedAt:    "2026-04-14T00:00:00Z",
			},
		},
	})

	if _, err := os.Stat(awconfig.TeamStatePath(tmp)); !os.IsNotExist(err) {
		t.Fatalf("teams.yaml should not exist before migration, stat err=%v", err)
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
	_, token, err := createTeamInviteToken("acme.com", "ops", server.URL, false)
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
