package main

import (
	"context"
	"encoding/json"
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

func TestInitHostedPersistentWritesIdentityAndSignsCloudRequest(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		didRegisterPath  string
		didFullPath      string
		registeredDIDAW  string
		registeredDIDKey string
		signupBodyBytes  []byte
		signupBody       map[string]any
		signupAuth       string
		signupTimestamp  string
	)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["username"] != "juanre" {
				t.Fatalf("username=%v", payload["username"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"available": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			didRegisterPath = r.URL.Path
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"did_key", "server", "address", "handle"} {
				if _, ok := payload[field]; ok {
					t.Fatalf("register_did payload unexpectedly carried %q", field)
				}
			}
			registeredDIDAW, _ = payload["did_aw"].(string)
			registeredDIDKey, _ = payload["new_did_key"].(string)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"registered"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			didFullPath = r.URL.Path
			didAW := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			if didAW != registeredDIDAW {
				t.Fatalf("did full did_aw=%q want %q", didAW, registeredDIDAW)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          didAW,
				"current_did_key": registeredDIDKey,
				"server":          "",
				"address":         "",
				"handle":          nil,
				"created_at":      "2026-04-08T00:00:00Z",
				"updated_at":      "2026-04-08T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			signupAuth = strings.TrimSpace(r.Header.Get("Authorization"))
			signupTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
			var err error
			signupBodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(signupBodyBytes, &signupBody); err != nil {
				t.Fatal(err)
			}

			didKey, _ := signupBody["did_key"].(string)
			didAW, _ := signupBody["did_aw"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:juanre.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   didAW,
				MemberAddress: "juanre.aweb.ai/laptop",
				Alias:         "laptop",
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
				"user_id":          "user-1",
				"username":         "juanre",
				"org_id":           "org-1",
				"namespace_domain": "juanre.aweb.ai",
				"team_id":          "default:juanre.aweb.ai",
				"certificate":      encoded,
				"did_aw":           didAW,
				"member_address":   "juanre.aweb.ai/laptop",
				"alias":            "laptop",
				"team_did_key":     teamDIDKey,
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

	run := exec.CommandContext(
		ctx,
		bin,
		"--json",
		"init",
		"--hosted",
		"--persistent",
		"--username", "juanre",
		"--alias", "laptop",
		"--url", server.URL,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init --hosted failed: %v\n%s", err, string(out))
	}

	if signupBody["username"] != "juanre" {
		t.Fatalf("username=%v", signupBody["username"])
	}
	if didRegisterPath != "/v1/did" {
		t.Fatalf("did register path=%q", didRegisterPath)
	}
	if signupBody["alias"] != "laptop" {
		t.Fatalf("alias=%v", signupBody["alias"])
	}

	didKey, _ := signupBody["did_key"].(string)
	didAW, _ := signupBody["did_aw"].(string)
	if didFullPath != "/v1/did/"+didAW+"/full" {
		t.Fatalf("did full path=%q", didFullPath)
	}
	parts := strings.Fields(signupAuth)
	if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != didKey {
		t.Fatalf("Authorization=%q", signupAuth)
	}
	if !verifyCloudDIDPayload(t, mustExtractPublicKey(t, didKey), http.MethodPost, "/api/v1/onboarding/cli-signup", signupTimestamp, signupBodyBytes, parts[2]) {
		t.Fatal("cli-signup signed payload did not verify")
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if got["status"] != "signed_up" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["member_address"] != "juanre.aweb.ai/laptop" {
		t.Fatalf("member_address=%v", got["member_address"])
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("identity.yaml missing: %v", err)
	}
	if identity.DID != didKey {
		t.Fatalf("did=%q want %q", identity.DID, didKey)
	}
	if identity.StableID != didAW {
		t.Fatalf("stable_id=%q want %q", identity.StableID, didAW)
	}
	if identity.Address != "juanre.aweb.ai/laptop" {
		t.Fatalf("address=%q", identity.Address)
	}

	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.key")); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:juanre.aweb.ai"))
	if err != nil {
		t.Fatalf("team certificate missing: %v", err)
	}
	if cert.MemberDIDKey != didKey {
		t.Fatalf("cert did_key=%q want %q", cert.MemberDIDKey, didKey)
	}
	if cert.MemberDIDAW != didAW {
		t.Fatalf("cert did_aw=%q want %q", cert.MemberDIDAW, didAW)
	}
	if cert.MemberAddress != "juanre.aweb.ai/laptop" {
		t.Fatalf("cert member_address=%q", cert.MemberAddress)
	}
}

func TestInitHostedPersistentTreatsSameKeyAlreadyRegisteredAsSuccess(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		registerCalls    int
		keyLookups       int
		signupCalled     bool
		registeredDIDAW  string
		registeredDIDKey string
		signupBody       map[string]any
	)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			_ = json.NewEncoder(w).Encode(map[string]any{"available": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			registerCalls++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			registeredDIDAW, _ = payload["did_aw"].(string)
			registeredDIDKey, _ = payload["new_did_key"].(string)
			for _, field := range []string{"did_key", "server", "address", "handle"} {
				if _, ok := payload[field]; ok {
					t.Fatalf("register_did payload unexpectedly carried %q", field)
				}
			}
			http.Error(w, `{"detail":"did_aw already registered"}`, http.StatusConflict)
		case r.Method == http.MethodGet && registeredDIDAW != "" && r.URL.Path == "/v1/did/"+registeredDIDAW+"/key":
			keyLookups++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          registeredDIDAW,
				"current_did_key": registeredDIDKey,
				"log_head":        nil,
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			t.Fatalf("already-registered hosted init should not read full did state")
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			signupCalled = true
			signupBody = map[string]any{}
			if err := json.NewDecoder(r.Body).Decode(&signupBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := signupBody["did_key"].(string)
			didAW, _ := signupBody["did_aw"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:juanre.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   didAW,
				MemberAddress: "juanre.aweb.ai/laptop",
				Alias:         "laptop",
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
				"user_id":          "user-1",
				"username":         "juanre",
				"org_id":           "org-1",
				"namespace_domain": "juanre.aweb.ai",
				"team_id":          "default:juanre.aweb.ai",
				"certificate":      encoded,
				"did_aw":           didAW,
				"member_address":   "juanre.aweb.ai/laptop",
				"alias":            "laptop",
				"team_did_key":     teamDIDKey,
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

	run := exec.CommandContext(
		ctx,
		bin,
		"--json",
		"init",
		"--hosted",
		"--persistent",
		"--username", "juanre",
		"--alias", "laptop",
		"--url", server.URL,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init --hosted retry failed: %v\n%s", err, string(out))
	}

	if registerCalls != 1 {
		t.Fatalf("register calls=%d want 1", registerCalls)
	}
	if keyLookups != 1 {
		t.Fatalf("key lookups=%d want 1", keyLookups)
	}
	if !signupCalled {
		t.Fatal("cli-signup was not called after same-key registration conflict")
	}
	if signupBody["did_aw"] != registeredDIDAW {
		t.Fatalf("signup did_aw=%v want %q", signupBody["did_aw"], registeredDIDAW)
	}
	if signupBody["did_key"] != registeredDIDKey {
		t.Fatalf("signup did_key=%v want %q", signupBody["did_key"], registeredDIDKey)
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if got["status"] != "signed_up" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestInitHostedEphemeralOmitsIdentityFile(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		didRegisterCalls int
		signupBody       map[string]any
	)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			_ = json.NewEncoder(w).Encode(map[string]any{"available": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			didRegisterCalls++
			t.Fatalf("ephemeral hosted init should not register a did:aw")
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			t.Fatalf("ephemeral hosted init should not read back did:aw state")
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			signupBody = map[string]any{}
			if err := json.NewDecoder(r.Body).Decode(&signupBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := signupBody["did_key"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "default:juanre.aweb.ai",
				MemberDIDKey: didKey,
				Alias:        "laptop",
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
				"user_id":          "user-1",
				"username":         "juanre",
				"org_id":           "org-1",
				"namespace_domain": "juanre.aweb.ai",
				"team_id":          "default:juanre.aweb.ai",
				"certificate":      encoded,
				"did_aw":           "",
				"member_address":   "",
				"alias":            "laptop",
				"team_did_key":     teamDIDKey,
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

	run := exec.CommandContext(
		ctx,
		bin,
		"--json",
		"init",
		"--hosted",
		"--username", "juanre",
		"--alias", "laptop",
		"--url", server.URL,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init --hosted failed: %v\n%s", err, string(out))
	}

	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should not exist for ephemeral hosted init: %v", err)
	}
	if didRegisterCalls != 0 {
		t.Fatalf("did registrations=%d want 0", didRegisterCalls)
	}
	if signupBody["did_aw"] != "" {
		t.Fatalf("ephemeral signup did_aw=%v want empty string", signupBody["did_aw"])
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.key")); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:juanre.aweb.ai"))
	if err != nil {
		t.Fatalf("team certificate missing: %v", err)
	}
	if cert.MemberDIDAW != "" {
		t.Fatalf("cert member_did_aw=%q want empty", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "" {
		t.Fatalf("cert member_address=%q want empty", cert.MemberAddress)
	}
	if cert.Lifetime != awid.LifetimeEphemeral {
		t.Fatalf("cert lifetime=%q want %q", cert.Lifetime, awid.LifetimeEphemeral)
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if got["status"] != "signed_up" {
		t.Fatalf("status=%v", got["status"])
	}
}
