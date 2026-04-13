package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
	memberDIDKey := awid.ComputeDIDKey(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       memberDIDKey,
		StableID:  awid.ComputeStableID(memberPub),
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
	runInvite.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL=local")
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
	if registeredCert["member_did_key"] != memberDIDKey {
		t.Fatalf("registry cert member_did_key=%v", registeredCert["member_did_key"])
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

func TestCertIssueEmitsSignedEphemeralCertificateWithoutEmptyOptionalFields(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeControllerKeyForTest(t, tmp, "acme.com", controllerKey)

	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)

	run := exec.CommandContext(ctx, bin, "id", "cert", "issue",
		"--did", memberDID,
		"--team", "backend:acme.com",
		"--alias", "alice")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("cert issue failed: %v\n%s", err, string(out))
	}

	encoded := strings.TrimSpace(string(out))
	cert, err := awid.DecodeTeamCertificateHeader(encoded)
	if err != nil {
		t.Fatalf("decode certificate: %v", err)
	}
	if cert.Team != "backend:acme.com" {
		t.Fatalf("team=%q", cert.Team)
	}
	if cert.MemberDIDKey != memberDID {
		t.Fatalf("member_did_key=%q", cert.MemberDIDKey)
	}
	if cert.Alias != "alice" {
		t.Fatalf("alias=%q", cert.Alias)
	}
	if cert.Lifetime != awid.LifetimeEphemeral {
		t.Fatalf("lifetime=%q", cert.Lifetime)
	}
	if cert.MemberDIDAW != "" {
		t.Fatalf("member_did_aw=%q", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "" {
		t.Fatalf("member_address=%q", cert.MemberAddress)
	}
	if err := awid.VerifyTeamCertificate(cert, controllerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("verify certificate: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode raw certificate json: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal raw certificate json: %v", err)
	}
	if _, ok := payload["member_did_aw"]; ok {
		t.Fatalf("raw certificate unexpectedly included member_did_aw: %s", string(raw))
	}
	if _, ok := payload["member_address"]; ok {
		t.Fatalf("raw certificate unexpectedly included member_address: %s", string(raw))
	}
}

func TestCertIssuePersistentCertificateWritesOutputFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeControllerKeyForTest(t, tmp, "partner.com", controllerKey)

	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	outputPath := filepath.Join(tmp, "out", "team-cert.txt")

	run := exec.CommandContext(ctx, bin, "id", "cert", "issue",
		"--did", memberDID,
		"--team", "ops:partner.com",
		"--alias", "bob",
		"--lifetime", awid.LifetimePersistent,
		"--did-aw", "did:aw:zpartnerbob",
		"--address", "partner.com/bob",
		"--output", outputPath)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("cert issue failed: %v\n%s", err, string(out))
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("expected no stdout when --output is set, got:\n%s", string(out))
	}

	encodedBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	cert, err := awid.DecodeTeamCertificateHeader(strings.TrimSpace(string(encodedBytes)))
	if err != nil {
		t.Fatalf("decode certificate: %v", err)
	}
	if cert.Team != "ops:partner.com" {
		t.Fatalf("team=%q", cert.Team)
	}
	if cert.MemberDIDAW != "did:aw:zpartnerbob" {
		t.Fatalf("member_did_aw=%q", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "partner.com/bob" {
		t.Fatalf("member_address=%q", cert.MemberAddress)
	}
	if cert.Lifetime != awid.LifetimePersistent {
		t.Fatalf("lifetime=%q", cert.Lifetime)
	}
	if err := awid.VerifyTeamCertificate(cert, controllerKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
}

func TestCertIssueRejectsMissingRequiredFlags(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeControllerKeyForTest(t, tmp, "acme.com", controllerKey)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing did",
			args: []string{"id", "cert", "issue", "--team", "backend:acme.com", "--alias", "alice"},
			want: "--did is required",
		},
		{
			name: "missing team",
			args: []string{"id", "cert", "issue", "--did", "did:key:z6Mkexample", "--alias", "alice"},
			want: "--team is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := exec.CommandContext(ctx, bin, tc.args...)
			run.Env = testCommandEnv(tmp)
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("expected cert issue to fail:\n%s", string(out))
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("unexpected output:\n%s", string(out))
			}
		})
	}
}

func TestCertIssueFailsWhenControllerKeyMissing(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "id", "cert", "issue",
		"--did", "did:key:z6Mkexample",
		"--team", "backend:acme.com",
		"--alias", "alice")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected cert issue to fail:\n%s", string(out))
	}
	if !strings.Contains(string(out), "load controller key for acme.com") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestTeamAddSwitchListLeaveFlow(t *testing.T) {
	var registeredCert map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			cert, err := awid.DecodeTeamCertificateHeader(r.Header.Get("X-AWID-Team-Certificate"))
			if err != nil {
				t.Fatalf("decode cert header: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      cert.Team,
				"alias":        cert.Alias,
				"agent_id":     "agent-ops",
				"workspace_id": "ws-ops",
				"repo_id":      "repo-1",
				"team_did_key": cert.TeamDIDKey,
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

	t.Setenv("HOME", tmp)
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := awid.ComputeDIDKey(memberPub)
	memberStableID := awid.ComputeStableID(memberPub)
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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		AwebURL:    server.URL,
		ActiveTeam: "backend:acme.com",
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "alice",
			WorkspaceID: "ws-backend",
			CertPath:    awconfig.TeamCertificateRelativePath("backend:acme.com"),
			JoinedAt:    "2026-04-09T00:00:00Z",
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

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if workspace.ActiveTeam != "backend:acme.com" {
		t.Fatalf("active_team=%q", workspace.ActiveTeam)
	}
	if workspace.Membership("ops:acme.com") == nil {
		t.Fatal("expected ops team membership")
	}
	if workspace.Membership("ops:acme.com").WorkspaceID != "ws-ops" {
		t.Fatalf("workspace_id=%q", workspace.Membership("ops:acme.com").WorkspaceID)
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
	workspace, err = awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Membership("ops:acme.com") != nil {
		t.Fatal("expected ops membership removed")
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
	writeDefaultWorkspaceBindingForTest(t, tmp, "https://app.aweb.ai")

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
	writeDefaultWorkspaceBindingForTest(t, tmp, "https://app.aweb.ai")

	before, err := os.ReadFile(filepath.Join(tmp, ".aw", "workspace.yaml"))
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

	after, err := os.ReadFile(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("workspace.yaml changed for already-active switch")
	}
}

func TestTeamSwitchRejectsUnknownMembershipWithAvailableTeams(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai",
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
				Alias:       "alice-ops",
				WorkspaceID: "ws-ops",
				CertPath:    awconfig.TeamCertificateRelativePath("ops:acme.com"),
				JoinedAt:    "2026-04-09T00:00:00Z",
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
	if !strings.Contains(string(out), `team "unknown:acme.com" is not present in workspace memberships; available: backend:acme.com, ops:acme.com`) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}
