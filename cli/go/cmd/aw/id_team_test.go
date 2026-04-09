package main

import (
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
