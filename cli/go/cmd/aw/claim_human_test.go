package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestClaimHumanCommandSendsSignedOnboardingRequest(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	var gotBodyBytes []byte
	var gotBody map[string]any
	var gotAuth string
	var gotTimestamp string
	var onboardingURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": onboardingURL,
				"aweb_url":       onboardingURL,
				"registry_url":   "https://api.awid.ai",
				"version":        "1.7.0",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/claim-human":
			gotAuth = strings.TrimSpace(r.Header.Get("Authorization"))
			gotTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
			var err error
			gotBodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(gotBodyBytes, &gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "verification_sent",
				"email":  "alice@example.com",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	onboardingURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "alice.aweb.ai/alice-laptop", didKey, stableID, "https://api.awid.ai", priv)

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com", "--mock-url", server.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("claim-human failed: %v\n%s", err, string(out))
	}

	if gotBody["username"] != "alice" {
		t.Fatalf("username=%v", gotBody["username"])
	}
	if gotBody["email"] != "alice@example.com" {
		t.Fatalf("email=%v", gotBody["email"])
	}
	if gotBody["did_key"] != didKey {
		t.Fatalf("did_key=%v want %v", gotBody["did_key"], didKey)
	}

	parts := strings.Fields(gotAuth)
	if len(parts) != 3 || parts[0] != "DIDKey" {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if parts[1] != didKey {
		t.Fatalf("auth did=%q want %q", parts[1], didKey)
	}

	if !verifyCloudDIDPayload(t, pub, http.MethodPost, "/api/v1/onboarding/claim-human", gotTimestamp, gotBodyBytes, parts[2]) {
		t.Fatal("signed claim-human payload did not verify")
	}

	output := string(out)
	if !strings.Contains(output, "Verification email sent to alice@example.com. Click the link in the email to activate your dashboard login.") {
		t.Fatalf("output=%q", output)
	}
}

func TestClaimHumanCommandFallsBackWithoutIdentityFile(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)

	var gotBodyBytes []byte
	var gotBody map[string]any
	var gotAuth string
	var gotTimestamp string
	var onboardingURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": onboardingURL,
				"aweb_url":       onboardingURL,
				"registry_url":   "https://api.awid.ai",
				"version":        "1.7.0",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/claim-human":
			gotAuth = strings.TrimSpace(r.Header.Get("Authorization"))
			gotTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
			var err error
			gotBodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(gotBodyBytes, &gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "verification_sent",
				"email":  "alice@example.com",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	onboardingURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	writeWorkspaceBindingForTest(t, tmp, workspaceBinding(server.URL, "default:alice.aweb.ai", "alice-laptop", "workspace-1"))
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should be absent, err=%v", err)
	}

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com", "--mock-url", server.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("claim-human failed: %v\n%s", err, string(out))
	}

	if gotBody["username"] != "alice" {
		t.Fatalf("username=%v", gotBody["username"])
	}
	if gotBody["email"] != "alice@example.com" {
		t.Fatalf("email=%v", gotBody["email"])
	}
	if gotBody["did_key"] != didKey {
		t.Fatalf("did_key=%v want %v", gotBody["did_key"], didKey)
	}

	parts := strings.Fields(gotAuth)
	if len(parts) != 3 || parts[0] != "DIDKey" {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	if parts[1] != didKey {
		t.Fatalf("auth did=%q want %q", parts[1], didKey)
	}

	if !verifyCloudDIDPayload(t, pub, http.MethodPost, "/api/v1/onboarding/claim-human", gotTimestamp, gotBodyBytes, parts[2]) {
		t.Fatal("signed claim-human payload did not verify")
	}

	output := string(out)
	if !strings.Contains(output, "Verification email sent to alice@example.com. Click the link in the email to activate your dashboard login.") {
		t.Fatalf("output=%q", output)
	}
}

func TestClaimHumanCommandRequiresIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com", "--mock-url", "http://127.0.0.1:1")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected claim-human to fail without identity:\n%s", string(out))
	}
	if !strings.Contains(string(out), "No identity found. Run aw init first to create an agent, then claim-human to attach an email.") {
		t.Fatalf("output=%q", string(out))
	}
}

func TestClaimHumanCommandRequiresEmailFlag(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "claim-human", "--mock-url", "http://127.0.0.1:1")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected claim-human to fail without --email:\n%s", string(out))
	}
	if !strings.Contains(string(out), "missing required flag: --email") {
		t.Fatalf("output=%q", string(out))
	}
}

func TestClaimHumanCommandMapsNotFound(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"detail":"username not found"}`)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "alice.aweb.ai/alice-laptop", didKey, stableID, "https://api.awid.ai", priv)

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com", "--mock-url", server.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected claim-human to fail on 404:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Username not registered. Run aw init first.") {
		t.Fatalf("output=%q", string(out))
	}
}

func TestClaimHumanCommandMapsUnauthorized(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"detail":"did:key mismatch"}`)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "alice.aweb.ai/alice-laptop", didKey, stableID, "https://api.awid.ai", priv)

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com", "--mock-url", server.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected claim-human to fail on 401:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Your signing key does not match the registered agent. Check .aw/signing.key is intact.") {
		t.Fatalf("output=%q", string(out))
	}
}

func TestClaimHumanCommandMapsConflictVerbatim(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"detail":"The email alice@example.com is already associated with another account."}`)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "alice.aweb.ai/alice-laptop", didKey, stableID, "https://api.awid.ai", priv)

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com", "--mock-url", server.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected claim-human to fail on conflict:\n%s", string(out))
	}
	if !strings.Contains(string(out), "The email alice@example.com is already associated with another account.") {
		t.Fatalf("output=%q", string(out))
	}
}

func TestUsernameFromMemberAddressRejectsBYOD(t *testing.T) {
	t.Parallel()

	_, err := usernameFromMemberAddress("acme.com/alice")
	if err == nil {
		t.Fatal("expected BYOD address to be rejected")
	}
	if !strings.Contains(err.Error(), "claim-human is only for managed aweb.ai accounts") {
		t.Fatalf("err=%v", err)
	}
}

func verifyCloudDIDPayload(t *testing.T, pubKey ed25519.PublicKey, method, path, timestamp string, body []byte, signature string) bool {
	t.Helper()

	sum := sha256.Sum256(body)
	payload, err := json.Marshal(map[string]string{
		"body_sha256": hex.EncodeToString(sum[:]),
		"method":      strings.ToUpper(strings.TrimSpace(method)),
		"path":        path,
		"timestamp":   timestamp,
	})
	if err != nil {
		t.Fatal(err)
	}

	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.Verify(pubKey, payload, sig)
}
