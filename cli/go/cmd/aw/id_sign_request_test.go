package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestAwIDSignWorksWithStandaloneIdentity(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", did, stableID, "https://api.awid.ai", priv)

	run := exec.CommandContext(ctx, bin, "id", "sign", "--payload", `{"domain":"acme.com","operation":"register"}`, "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id sign failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["did_key"] != did {
		t.Fatalf("did_key=%v want %v", got["did_key"], did)
	}
	timestamp, _ := got["timestamp"].(string)
	signature, _ := got["signature"].(string)
	verifySignedPayload(t, pub, map[string]any{
		"domain":    "acme.com",
		"operation": "register",
	}, timestamp, signature)
}

func TestAwIDSignWorksWithEphemeralWorkspace(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeEphemeralSigningWorkspace(t, tmp, "https://app.aweb.ai", "demo/alice", did, priv)

	run := exec.CommandContext(ctx, bin, "id", "sign", "--payload", `{"key":"plan","operation":"put_doc"}`, "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id sign failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["did_key"] != did {
		t.Fatalf("did_key=%v want %v", got["did_key"], did)
	}
	timestamp, _ := got["timestamp"].(string)
	signature, _ := got["signature"].(string)
	verifySignedPayload(t, pub, map[string]any{
		"key":       "plan",
		"operation": "put_doc",
	}, timestamp, signature)
}

func TestAwIDRequestSignsAndSendsHTTP(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	address := "acme.com/alice"

	var gotContentType string
	var gotBody string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = strings.TrimSpace(r.Header.Get("Content-Type"))
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(data)

		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		parts := strings.Split(auth, " ")
		if len(parts) != 3 || parts[0] != "DIDKey" {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		if parts[1] != did {
			t.Fatalf("did=%q want %q", parts[1], did)
		}
		verifySignedPayload(t, pub, map[string]any{
			"domain":    "acme.com",
			"key":       "plan",
			"operation": "put_doc",
		}, timestamp, parts[2])

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "ok")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
		})
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, address, did, stableID, "https://api.awid.ai", priv)

	run := exec.CommandContext(ctx, bin, "id", "request", "PUT", server.URL+"/v1/docs/acme.com/plan",
		"--sign", `{"domain":"acme.com","key":"plan","operation":"put_doc"}`,
		"--body", `{"content":"# Q3 Plan"}`,
		"--header", "X-Custom: value",
		"--json",
	)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id request failed: %v\n%s", err, string(out))
	}
	if gotContentType != "application/json" {
		t.Fatalf("content-type=%q want application/json", gotContentType)
	}
	if gotBody != `{"content":"# Q3 Plan"}` {
		t.Fatalf("body=%q", gotBody)
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != float64(http.StatusOK) {
		t.Fatalf("status=%v", got["status"])
	}
	body, ok := got["body"].(map[string]any)
	if !ok || body["ok"] != true {
		t.Fatalf("body=%v", got["body"])
	}
	headers, ok := got["headers"].(map[string]any)
	if !ok || headers["x-upstream"] != "ok" {
		t.Fatalf("headers=%v", got["headers"])
	}
}

func TestAwIDRequestRawPrintsBodyOnly(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	var sawAuthorization bool
	var sawTimestamp bool
	var sawStableID string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuthorization = strings.TrimSpace(r.Header.Get("Authorization")) != ""
		sawTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp")) != ""
		sawStableID = strings.TrimSpace(r.Header.Get("X-AWEB-DID-AW"))
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("pong"))
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", did, stableID, "https://api.awid.ai", priv)

	run := exec.CommandContext(ctx, bin, "id", "request", "GET", server.URL+"/ping",
		"--sign", `{"operation":"ping"}`,
		"--raw",
	)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id request --raw failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "pong") {
		t.Fatalf("output=%q", string(out))
	}
	if !sawAuthorization || !sawTimestamp {
		t.Fatalf("raw request missing DIDKey auth headers: authorization=%v timestamp=%v", sawAuthorization, sawTimestamp)
	}
	if sawStableID != stableID {
		t.Fatalf("raw request X-AWEB-DID-AW=%q want %q", sawStableID, stableID)
	}
}

func TestAwIDRequestDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	var redirectedHit bool
	redirectTarget := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedHit = true
		t.Fatalf("unexpected redirected request with Authorization=%q", r.Header.Get("Authorization"))
	}))

	redirectSource := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", redirectTarget.URL+"/sink")
		w.WriteHeader(http.StatusFound)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", did, stableID, "https://api.awid.ai", priv)

	run := exec.CommandContext(ctx, bin, "id", "request", "GET", redirectSource.URL+"/start",
		"--sign", `{"operation":"ping"}`,
		"--json",
	)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("request failed: %v\n%s", err, string(out))
	}
	var got map[string]any
	if jsonErr := json.Unmarshal(extractJSON(t, out), &got); jsonErr != nil {
		t.Fatalf("invalid json: %v\n%s", jsonErr, string(out))
	}
	if got["status"] != float64(http.StatusFound) {
		t.Fatalf("status=%v want %d", got["status"], http.StatusFound)
	}
	if redirectedHit {
		t.Fatal("redirect target should not have been contacted")
	}
}

func writeEphemeralSigningWorkspace(t *testing.T, workingDir, serverURL, address, did string, signingKey ed25519.PrivateKey) {
	t.Helper()
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if err := awid.SaveSigningKey(signingKeyPath, signingKey); err != nil {
		t.Fatal(err)
	}
	handle := "alice"
	namespace := "demo"
	if domain, derivedHandle, ok := awconfig.CutIdentityAddress(address); ok {
		namespace = domain
		handle = derivedHandle
	}
	writeIdentityForTest(t, workingDir, awconfig.WorktreeIdentity{
		DID:       did,
		Address:   address,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimeEphemeral,
		CreatedAt: "2026-04-04T00:00:00Z",
	})
	writeWorkspaceBindingForTest(t, workingDir, workspaceBinding(serverURL, "backend:"+namespace, handle, "workspace-1"))
}

func verifySignedPayload(t *testing.T, pub ed25519.PublicKey, payload map[string]any, timestamp, signature string) {
	t.Helper()
	signedPayload := make(map[string]any, len(payload)+1)
	for key, value := range payload {
		signedPayload[key] = value
	}
	signedPayload["timestamp"] = timestamp
	canonical, err := awid.CanonicalJSONValue(signedPayload)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sigBytes) {
		t.Fatalf("signature did not verify for %s", canonical)
	}
}
