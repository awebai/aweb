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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const appTestGrantID = "3f2b8c1e-6d4a-4f7b-9c2e-1a5b7d9e0f11"

// appVerifyingServer behaves like an installed app's auth layer
// (naapp library/folio auth.py): it accepts only a team-auth v2 envelope whose
// signature, certificate and request binding all check out.
type appVerifyingServer struct {
	t        *testing.T
	teamPub  ed25519.PublicKey
	teamID   string
	mu       sync.Mutex
	seen     []string
	verified []string
	server   *httptest.Server
}

func newAppVerifyingServer(t *testing.T, teamPub ed25519.PublicKey, teamID string) *appVerifyingServer {
	a := &appVerifyingServer{t: t, teamPub: teamPub, teamID: teamID}
	a.server = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.server.Close)
	return a
}

func (a *appVerifyingServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.seen = append(a.seen, r.Method+" "+r.URL.RequestURI())
	a.mu.Unlock()
	if r.URL.Path == "/v1/things/redirect" {
		http.Redirect(w, r, "http://127.0.0.1:1/stolen", http.StatusTemporaryRedirect)
		return
	}
	fail := func(msg string) {
		http.Error(w, msg, http.StatusUnauthorized)
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 3 || parts[0] != "DIDKey" {
		fail("bad authorization")
		return
	}
	didKey, sigB64 := parts[1], parts[2]
	cert, err := awid.DecodeTeamCertificateHeader(r.Header.Get("X-AWID-Team-Certificate"))
	if err != nil || awid.VerifyTeamCertificate(cert, a.teamPub) != nil {
		fail("bad certificate")
		return
	}
	if cert.MemberDIDKey != didKey || cert.Team != a.teamID {
		fail("certificate member mismatch")
		return
	}
	canonical, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if err != nil {
		fail("bad signed payload")
		return
	}
	pub, err := awid.ExtractPublicKey(didKey)
	sig, sigErr := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil || sigErr != nil || !ed25519.Verify(pub, canonical, sig) {
		fail("bad signature")
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(canonical, &payload); err != nil {
		fail("bad payload json")
		return
	}
	sum := sha256.Sum256(body)
	want := map[string]any{
		"aud":         "http://" + r.Host,
		"method":      r.Method,
		"path":        r.URL.RequestURI(),
		"team_id":     a.teamID,
		"body_sha256": hex.EncodeToString(sum[:]),
	}
	for k, v := range want {
		if payload[k] != v {
			fail("payload " + k + " mismatch")
			return
		}
	}
	if payload["v"] != float64(2) || payload["timestamp"] != r.Header.Get("X-AWEB-Timestamp") {
		fail("payload version/timestamp mismatch")
		return
	}
	a.mu.Lock()
	a.verified = append(a.verified, r.Method+" "+r.URL.RequestURI()+" as "+didKey)
	a.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (a *appVerifyingServer) requests() ([]string, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.seen...), append([]string(nil), a.verified...)
}

func appTestManifest(origin, getPath string) string {
	return `{"manifest_version":1,"app":{"id":"testapp","version":"1.0.0","origin":"` + origin + `"},"tools":[` +
		`{"name":"get-thing","method":"GET","path":"` + getPath + `","input_schema":{"type":"object","properties":{"thing_id":{"type":"string"}}},"params":[{"name":"thing_id","in":"path"}],"body":{"mode":"json"},"mutation":false},` +
		`{"name":"create-thing","method":"POST","path":"/v1/things","input_schema":{"type":"object","properties":{"title":{"type":"string"}}},"params":[{"name":"title","in":"body"}],"body":{"mode":"json"},"mutation":true},` +
		`{"name":"wipe","method":"POST","path":"/v1/admin/wipe","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"},"mutation":true},` +
		`{"name":"catalog","method":"GET","path":"/v1/catalog","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"},"auth":"none","mutation":false}` +
		`]}`
}

func writeInstalledAppManifest(t *testing.T, awHome, manifest string) {
	t.Helper()
	path := manifestPluginManifestPath(filepath.Join(awHome, "plugins"), "testapp")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
}

type appCustodyFixture struct {
	grantHome    string
	residentHome string
	residentDID  string
	app          *appVerifyingServer
	svc          *custodyService
	grant        *awconfig.GrantHome
}

func setupAppCustodyFixture(t *testing.T, verbs []string) *appCustodyFixture {
	t.Helper()
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	t.Chdir(tmp)
	setGrantTestEnv(t, tmp)
	awHome := filepath.Join(tmp, "aw-home")
	t.Setenv("AW_HOME", awHome)

	teamPub, teamKey, _ := ed25519.GenerateKey(nil)
	_, residentKey, _ := ed25519.GenerateKey(nil)
	residentDID := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
	teamID := "backend:acme.com"
	app := newAppVerifyingServer(t, teamPub, teamID)
	writeInstalledAppManifest(t, awHome, appTestManifest(app.server.URL, "/v1/things/{thing_id}"))

	residentHome := filepath.Join(tmp, "resident", ".aw")
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: residentDID, MemberDIDAW: "did:aw:alice", MemberAddress: "acme.com/alice", Alias: "alice", IdentityScope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(residentHome, teamID, cert); err != nil {
		t.Fatal(err)
	}

	grantHome := filepath.Join(tmp, ".aw")
	_, grant := writeGrantHomeForTest(t, grantHome, "http://127.0.0.1:1")
	grant.GrantID = appTestGrantID
	grant.Subject.DIDKey = residentDID
	socketID, _ := awid.GenerateUUID4()
	runDir := filepath.Join("/tmp", "aw-custody-"+socketID[:8])
	_ = os.RemoveAll(runDir)
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	grant.Custody.SocketPath = filepath.Join(runDir, "custody.sock")
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(grantHome), grant); err != nil {
		t.Fatal(err)
	}

	if len(verbs) > 0 {
		apps, err := buildGrantAppSnapshots(map[string][]string{"testapp": verbs}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveGrantAppToolsSnapshot(residentHome, &grantAppToolsSnapshot{Version: grantAppToolsSnapshotVersion, GrantID: appTestGrantID, TeamID: teamID, Apps: apps}); err != nil {
			t.Fatal(err)
		}
	}

	sessionKey, err := awid.LoadSigningKey(awconfig.GrantHomeSigningKeyPath(grantHome))
	if err != nil {
		t.Fatal(err)
	}
	sessionDID := awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey))
	svc := &custodyService{
		residentHome:     residentHome,
		socketPath:       grant.Custody.SocketPath,
		identity:         &awconfig.ResolvedIdentity{DID: residentDID, StableID: grant.Subject.DIDAW, Address: grant.Subject.Address, Handle: grant.Subject.Alias},
		signingKey:       residentKey,
		appDeniedOrigins: grantAppDeniedOrigins("https://app.aweb.ai", ""),
		now:              time.Now,
		replay:           map[string]string{},
		replayAt:         map[string]time.Time{},
		results:          map[string]any{},
		grantStatus: func(ctx context.Context, grantID string) (custodyGrantStatus, error) {
			return custodyGrantStatus{Active: true, Status: "active", EffectiveStatus: "active", TeamID: teamID, GrantDIDKey: sessionDID, Scopes: grant.Scopes, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errc := make(chan error, 1)
	go func() { errc <- svc.serve(ctx) }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(grant.Custody.SocketPath); err == nil {
			break
		}
		select {
		case err := <-errc:
			t.Fatalf("custody service exited before creating socket: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &appCustodyFixture{grantHome: grantHome, residentHome: residentHome, residentDID: residentDID, app: app, svc: svc, grant: grant}
}

func runAppTool(t *testing.T, args ...string) (*installedManifestToolResult, error) {
	t.Helper()
	lastClient = nil
	result, handled, err := executeInstalledManifestTool("testapp", args)
	if !handled {
		t.Fatalf("app tool %v not handled", args)
	}
	return result, err
}

func TestGrantAppToolSignedThroughCustodyVerifiesAtApp(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing", "create-thing"})

	res, err := runAppTool(t, "get-thing", "--thing_id", "t1")
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("get-thing: status=%v err=%v body=%s", statusOf(res), err, bodyOf(res))
	}
	res, err = runAppTool(t, "create-thing", "--title", "hello")
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("create-thing: status=%v err=%v body=%s", statusOf(res), err, bodyOf(res))
	}
	_, verified := f.app.requests()
	want := []string{"GET /v1/things/t1 as " + f.residentDID, "POST /v1/things as " + f.residentDID}
	if strings.Join(verified, "|") != strings.Join(want, "|") {
		t.Fatalf("app verified %v, want %v (resident key, not the session key)", verified, want)
	}

	// Public tools stay unsigned and need no custody authority.
	res, err = runAppTool(t, "catalog")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusUnauthorized {
		t.Fatalf("auth:none tool should be sent unsigned (verifier rejects it), got %d", res.Status)
	}
}

func TestGrantAppToolDeniesUnlistedAdminTool(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	if _, err := runAppTool(t, "wipe"); err == nil || !strings.Contains(err.Error(), "app_tool_denied") {
		t.Fatalf("err=%v, want app_tool_denied", err)
	}
	if _, err := runAppTool(t, "create-thing", "--title", "x"); err == nil || !strings.Contains(err.Error(), "app_tool_denied") {
		t.Fatalf("err=%v, want app_tool_denied for an unlisted write", err)
	}
	if seen, _ := f.app.requests(); len(seen) != 0 {
		t.Fatalf("denied tools reached the app: %v", seen)
	}
}

func TestGrantAppToolWithoutSnapshotIsDenied(t *testing.T) {
	f := setupAppCustodyFixture(t, nil)
	if _, err := runAppTool(t, "get-thing", "--thing_id", "t1"); err == nil || !strings.Contains(err.Error(), "app_tool_denied") {
		t.Fatalf("err=%v, want app_tool_denied for a grant minted without app tools", err)
	}
	if seen, _ := f.app.requests(); len(seen) != 0 {
		t.Fatalf("request reached the app: %v", seen)
	}
}

func TestGrantAppToolIgnoresLocalManifestDrift(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	// The worker's installed manifest is edited to point get-thing at an admin
	// path. Custody signs only the mint-time snapshot.
	writeInstalledAppManifest(t, filepath.Join(filepath.Dir(f.grantHome), "aw-home"), appTestManifest(f.app.server.URL, "/v1/admin/wipe/{thing_id}"))
	res, err := runAppTool(t, "get-thing", "--thing_id", "t1")
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("status=%v err=%v", statusOf(res), err)
	}
	seen, _ := f.app.requests()
	if len(seen) != 1 || seen[0] != "GET /v1/things/t1" {
		t.Fatalf("app saw %v, want the snapshot path only", seen)
	}
}

func TestGrantAppToolRejectsDotSegmentParams(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	for _, value := range []string{"..", "."} {
		if _, err := runAppTool(t, "get-thing", "--thing_id", value); err == nil || !strings.Contains(err.Error(), "app_request_not_allowed") {
			t.Fatalf("value %q: err=%v, want app_request_not_allowed", value, err)
		}
	}
	if seen, _ := f.app.requests(); len(seen) != 0 {
		t.Fatalf("dot-segment request reached the app: %v", seen)
	}
}

func TestGrantAppToolDoesNotFollowRedirects(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	res, err := runAppTool(t, "get-thing", "--thing_id", "redirect")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusTemporaryRedirect {
		t.Fatalf("status=%d, want the 307 surfaced, not followed", res.Status)
	}
	if seen, _ := f.app.requests(); len(seen) != 1 {
		t.Fatalf("app saw %v, want exactly one request", seen)
	}
}

func TestGrantAppToolRefusesDeniedOrigin(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	f.svc.appDeniedOrigins = append(f.svc.appDeniedOrigins, f.app.server.URL)
	if _, err := runAppTool(t, "get-thing", "--thing_id", "t1"); err == nil || !strings.Contains(err.Error(), "app_request_not_allowed") {
		t.Fatalf("err=%v, want app_request_not_allowed", err)
	}
	if _, err := buildGrantAppSnapshots(map[string][]string{"testapp": {"get-thing"}}, []string{f.app.server.URL + "/"}); err == nil {
		t.Fatal("mint snapshot accepted an app whose origin is a denied coordination origin")
	}
}

func TestGrantAppToolCustodyUnavailableFailsClosed(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	f.grant.Custody.SocketPath = filepath.Join(t.TempDir(), "missing.sock")
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(f.grantHome), f.grant); err != nil {
		t.Fatal(err)
	}
	if _, err := runAppTool(t, "get-thing", "--thing_id", "t1"); err == nil {
		t.Fatal("custody unavailable should fail, not send")
	}
	f.grant.Custody.SocketPath = ""
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(f.grantHome), f.grant); err != nil {
		t.Fatal(err)
	}
	if _, err := runAppTool(t, "get-thing", "--thing_id", "t1"); err == nil || !strings.Contains(err.Error(), "custody_unavailable") {
		t.Fatalf("err=%v, want custody_unavailable without a custody locator", err)
	}
	if seen, _ := f.app.requests(); len(seen) != 0 {
		t.Fatalf("request reached the app without custody: %v", seen)
	}
}

func TestGrantAppSnapshotRejectsAmbiguousAndPublicTools(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	awHome := filepath.Join(tmp, "aw-home")
	t.Setenv("AW_HOME", awHome)
	dup := `{"manifest_version":1,"app":{"id":"testapp","version":"1.0.0","origin":"https://apps.example.com"},"tools":[` +
		`{"name":"get-thing","method":"GET","path":"/v1/a","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"},"mutation":false},` +
		`{"name":"get-thing","method":"GET","path":"/v1/b","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"},"mutation":false}]}`
	writeInstalledAppManifest(t, awHome, dup)
	if _, err := buildGrantAppSnapshots(map[string][]string{"testapp": {"get-thing"}}, nil); err == nil {
		// Validate may already reject duplicates; either way it must not snapshot.
		t.Fatal("duplicate tool names were snapshotted")
	}
	writeInstalledAppManifest(t, awHome, appTestManifest("https://apps.example.com", "/v1/things/{thing_id}"))
	if _, err := buildGrantAppSnapshots(map[string][]string{"testapp": {"catalog"}}, nil); err == nil || !strings.Contains(err.Error(), "public tool") {
		t.Fatalf("err=%v, want public tool refusal", err)
	}
	if _, err := buildGrantAppSnapshots(map[string][]string{"testapp": {"nope"}}, nil); err == nil {
		t.Fatal("unknown tool was snapshotted")
	}
	if _, err := parseGrantAppToolSpecs([]string{"testapp:*"}); err == nil {
		t.Fatal("wildcard accepted")
	}
}

func TestCustodySignAppRequestReplayOpAndOracle(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	sessionKey, err := awid.LoadSigningKey(awconfig.GrantHomeSigningKeyPath(f.grantHome))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.serviceID = "svc"
	req := &awid.AppRequestSignRequest{Version: 1, Operation: "sign_app_request", GrantID: appTestGrantID, TeamID: "backend:acme.com", SubjectDIDAW: f.grant.Subject.DIDAW, SubjectDIDKey: f.residentDID, Audience: "local-resident-custody:svc", AppID: "testapp", Verb: "get-thing", Args: map[string]any{"thing_id": "t1"}}
	if err := awid.SignAppRequestCustodyProof(sessionKey, req); err != nil {
		t.Fatal(err)
	}
	first, err := f.svc.signAppRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.svc.signAppRequest(context.Background(), req)
	if err != nil || again.Headers["Authorization"] != first.Headers["Authorization"] {
		t.Fatalf("exact replay should return the cached signed request: err=%v", err)
	}
	changed := *req
	changed.Args = map[string]any{"thing_id": "t2"}
	if err := awid.SignAppRequestCustodyProof(sessionKey, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Nonce = req.Nonce
	if err := awid.SignAppRequestCustodyProof(sessionKey, &changed); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.signAppRequest(context.Background(), &changed); err == nil || err.Error() != "replay_detected" {
		t.Fatalf("err=%v, want replay_detected", err)
	}
	wrongOp := *req
	wrongOp.Nonce = ""
	wrongOp.Operation = "sign_plain_message"
	if err := awid.SignAppRequestCustodyProof(sessionKey, &wrongOp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.signAppRequest(context.Background(), &wrongOp); err == nil || err.Error() != "unsupported_operation" {
		t.Fatalf("err=%v, want unsupported_operation", err)
	}

	// Oracle: the resident key signed exactly the fixed team-auth v2 keys.
	canonical, err := base64.RawURLEncoding.DecodeString(first.Headers["X-Aweb-Signed-Payload"])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(canonical, &payload); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	got := strings.Join(sortedStrings(keys), ",")
	if got != "aud,body_sha256,method,path,team_id,timestamp,v" {
		t.Fatalf("signed payload keys=%s", got)
	}

	// Unknown fields are refused at the handler.
	data, _ := json.Marshal(req)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	raw["url"] = "https://evil.example.com/v1/admin"
	data, _ = json.Marshal(raw)
	rr := httptest.NewRecorder()
	f.svc.handleSignAppRequest(rr, httptest.NewRequest(http.MethodPost, "/sign_app_request", strings.NewReader(string(data))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d %s", rr.Code, rr.Body.String())
	}
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func statusOf(res *installedManifestToolResult) int {
	if res == nil {
		return 0
	}
	return res.Status
}

func bodyOf(res *installedManifestToolResult) string {
	if res == nil {
		return ""
	}
	return string(res.Body)
}

func TestRunGrantMintSnapshotsNamedAppToolsIntoResidentHome(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	t.Chdir(tmp)
	setGrantTestEnv(t, tmp)
	awHome := filepath.Join(tmp, "aw-home")
	t.Setenv("AW_HOME", awHome)

	minted := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/identity-grants" {
			http.NotFound(w, r)
			return
		}
		minted++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"grant_id": appTestGrantID, "team_id": "backend:demo", "subject_alias": "alice", "subject_did_aw": "did:aw:alice", "grant_did_key": body["grant_did_key"], "scopes": body["scopes"], "issued_at": "2026-08-12T00:00:00Z", "expires_at": "2026-08-12T08:00:00Z"})
	}))
	t.Cleanup(server.Close)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)
	writeInstalledAppManifest(t, awHome, appTestManifest("https://apps.example.com", "/v1/things/{thing_id}"))

	// Refusals happen before any grant is minted.
	grantMintScopes = []string{"mail.read"}
	grantMintOut = filepath.Join(tmp, "refused")
	grantMintAppTools = []string{"testapp:catalog"}
	if err := runGrantMint(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "public tool") {
		t.Fatalf("err=%v, want public tool refusal", err)
	}
	writeInstalledAppManifest(t, awHome, appTestManifest(server.URL, "/v1/things/{thing_id}"))
	grantMintAppTools = []string{"testapp:get-thing"}
	if err := runGrantMint(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "coordination or registry origin") {
		t.Fatalf("err=%v, want refusal of the aweb server origin", err)
	}
	if minted != 0 {
		t.Fatalf("refused app tools still minted %d grants", minted)
	}

	writeInstalledAppManifest(t, awHome, appTestManifest("https://apps.example.com", "/v1/things/{thing_id}"))
	grantMintOut = filepath.Join(tmp, "worker-grant")
	grantMintAppTools = []string{"testapp:get-thing"}
	if _, err := os.Stat(grantMintOut); err == nil {
		_ = os.RemoveAll(grantMintOut)
	}
	var runErr error
	captureIDCommandStdout(t, func() { runErr = runGrantMint(&cobra.Command{}, nil) })
	if runErr != nil {
		t.Fatalf("runGrantMint: %v", runErr)
	}
	home, err := identityHomeForDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := loadGrantAppToolsSnapshot(home.Root, appTestGrantID)
	if err != nil {
		t.Fatalf("snapshot not written to resident home: %v", err)
	}
	app := snap.Apps["testapp"]
	if snap.TeamID != "backend:demo" || len(app.Tools) != 1 || app.Tools[0].Name != "get-thing" || app.Tools[0].Path != "/v1/things/{thing_id}" {
		t.Fatalf("snapshot=%+v", snap)
	}
	if !strings.HasPrefix(app.ManifestSHA256, "sha256:") {
		t.Fatalf("manifest digest missing: %q", app.ManifestSHA256)
	}
	if _, err := os.Stat(filepath.Join(grantMintOut, "grants")); !os.IsNotExist(err) {
		t.Fatalf("app tool policy leaked into the worker grant home: %v", err)
	}
}

// OATS hooks select the grant home explicitly via AWEB_IDENTITY_HOME from an
// otherwise empty instance directory; app verbs dispatch before cobra, so the
// environment (not --identity-home) is the supported selector here.
func TestGrantAppToolWithExplicitIdentityHomeEnv(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	instance := t.TempDir()
	t.Chdir(instance)
	t.Setenv(awconfig.IdentityHomeEnv, f.grantHome)
	res, err := runAppTool(t, "get-thing", "--thing_id", "t1")
	if err != nil || res.Status != http.StatusOK {
		t.Fatalf("status=%v err=%v body=%s", statusOf(res), err, bodyOf(res))
	}
	if _, verified := f.app.requests(); len(verified) != 1 || !strings.HasSuffix(verified[0], "as "+f.residentDID) {
		t.Fatalf("verified=%v", verified)
	}
	entries, err := os.ReadDir(instance)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("grant app call wrote into the instance directory: %v", entries)
	}
}
