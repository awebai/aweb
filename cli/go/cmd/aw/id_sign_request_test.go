package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func TestAwIDSignWorksWithLocalWorkspace(t *testing.T) {
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

func TestAwIDRequestTeamAuthSignsLocalWorkspaceRequest(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	requestBody := `{"task":"prepare-awco"}`
	wantBodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(requestBody)))

	var sawStableID string
	var sawCert *awid.TeamCertificate
	var sawPayload map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/awco/tasks" || r.URL.RawQuery != "dry_run=true" {
			t.Fatalf("unexpected request target %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s want POST", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != requestBody {
			t.Fatalf("body=%q want %q", string(body), requestBody)
		}

		sawStableID = strings.TrimSpace(r.Header.Get("X-AWEB-DID-AW"))
		sawCert = requireCertificateAuthForTest(t, r)
		if sawCert.MemberDIDKey != did {
			t.Fatalf("certificate member_did_key=%q want %q", sawCert.MemberDIDKey, did)
		}
		if sawCert.MemberDIDAW != "" || sawCert.MemberAddress != "" {
			t.Fatalf("local certificate unexpectedly had global identity fields: did_aw=%q address=%q", sawCert.MemberDIDAW, sawCert.MemberAddress)
		}

		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.Split(auth, " ")
		if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != did {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		canonical := decodeSignedPayloadHeaderForTest(t, r.Header.Get("X-AWEB-Signed-Payload"))
		sigBytes, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !ed25519.Verify(pub, []byte(canonical), sigBytes) {
			t.Fatalf("signature did not verify for canonical payload %s", canonical)
		}
		if err := json.Unmarshal([]byte(canonical), &sawPayload); err != nil {
			t.Fatalf("signed payload JSON: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeLocalTeamSignedRequestWorkspaceForTest(t, tmp, server.URL, "backend:acme.com", "athena", did, priv)

	run := exec.CommandContext(ctx, bin, "id", "request", "POST", server.URL+"/v1/awco/tasks?dry_run=true",
		"--team-auth",
		"--sign", `{"operation":"awco_task_create"}`,
		"--body", requestBody,
		"--json",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id request --team-auth failed: %v\n%s", err, string(out))
	}
	if sawStableID != "" {
		t.Fatalf("local team-auth request set X-AWEB-DID-AW=%q", sawStableID)
	}
	if sawPayload["aud"] != server.URL {
		t.Fatalf("aud=%v want %s", sawPayload["aud"], server.URL)
	}
	if sawPayload["method"] != "POST" {
		t.Fatalf("method=%v want POST", sawPayload["method"])
	}
	if sawPayload["path"] != "/v1/awco/tasks?dry_run=true" {
		t.Fatalf("path=%v", sawPayload["path"])
	}
	if sawPayload["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", sawPayload["team_id"])
	}
	if sawPayload["body_sha256"] != wantBodyHash {
		t.Fatalf("body_sha256=%v want %s", sawPayload["body_sha256"], wantBodyHash)
	}
	if sawPayload["operation"] != "awco_task_create" {
		t.Fatalf("operation=%v", sawPayload["operation"])
	}
	if strings.TrimSpace(fmt.Sprint(sawPayload["timestamp"])) == "" {
		t.Fatalf("missing timestamp in signed payload: %v", sawPayload)
	}
}

func TestAwIDRequestTeamAuthRejectsReservedSignedFields(t *testing.T) {
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
	writeLocalTeamSignedRequestWorkspaceForTest(t, tmp, "https://app.aweb.ai", "backend:acme.com", "athena", did, priv)

	run := exec.CommandContext(ctx, bin, "id", "request", "GET", "https://service.example.test/v1/awco/tasks",
		"--team-auth",
		"--sign", `{"team_id":"other"}`,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected reserved field error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), `--sign field "team_id" is reserved by --team-auth`) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwIDRequestTeamAuthDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	var redirectedHit bool
	redirectTarget := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedHit = true
		t.Fatalf("unexpected redirected request with Authorization=%q Team-Certificate=%q", r.Header.Get("Authorization"), r.Header.Get("X-AWID-Team-Certificate"))
	}))

	redirectSource := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")) == "" {
			t.Fatal("missing team certificate on initial request")
		}
		w.Header().Set("Location", redirectTarget.URL+"/sink")
		w.WriteHeader(http.StatusFound)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeLocalTeamSignedRequestWorkspaceForTest(t, tmp, redirectSource.URL, "backend:acme.com", "athena", did, priv)

	run := exec.CommandContext(ctx, bin, "id", "request", "GET", redirectSource.URL+"/start",
		"--team-auth",
		"--sign", `{"operation":"ping"}`,
		"--json",
	)
	run.Env = testCommandEnv(tmp)
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

func writeLocalTeamSignedRequestWorkspaceForTest(t *testing.T, workingDir, serverURL, teamID, alias, did string, signingKey ed25519.PrivateKey) {
	t.Helper()
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), signingKey); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:         teamID,
		MemberDIDKey: did,
		Alias:        alias,
		Lifetime:     awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(workingDir, teamID, cert); err != nil {
		t.Fatal(err)
	}
	writeWorkspaceBindingForTest(t, workingDir, workspaceBinding(serverURL, teamID, alias, "workspace-1"))
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

func decodeSignedPayloadHeaderForTest(t *testing.T, encoded string) string {
	t.Helper()
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		t.Fatal("missing X-AWEB-Signed-Payload header")
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode signed payload header: %v", err)
	}
	return string(data)
}
