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

func TestInitHostedWritesIdentityAndSignsCloudRequest(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		didRegisterPath string
		didFullPath     string
		signupBodyBytes []byte
		signupBody      map[string]any
		signupAuth      string
		signupTimestamp string
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
			if payload["address"] != "juanre.aweb.ai/laptop" {
				t.Fatalf("address=%v", payload["address"])
			}
			if payload["handle"] != "laptop" {
				t.Fatalf("handle=%v", payload["handle"])
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"registered"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			didFullPath = r.URL.Path
			didKey, _ := signupBody["did_key"].(string)
			didAW := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          didAW,
				"current_did_key": didKey,
				"server":          "",
				"address":         "juanre.aweb.ai/laptop",
				"handle":          "laptop",
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
