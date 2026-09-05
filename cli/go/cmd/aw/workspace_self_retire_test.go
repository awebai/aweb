package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// planSelfRetire decides whether `aw workspace delete` retires the caller.
// Getting this wrong in either direction is a real failure: too permissive and
// the command tries to revoke someone else's certificate; too restrictive and it
// silently goes back to reporting a retirement that leaks the alias.

func TestPlanSelfRetireRefusesAnotherWorkspace(t *testing.T) {
	sel := &awconfig.Selection{
		WorkspaceID:   "11111111-1111-4111-8111-111111111111",
		TeamID:        "default:acme.aweb.ai",
		IdentityScope: "local",
		AwebURL:       "https://app.aweb.ai",
		Alias:         "mine",
	}
	plan := planSelfRetire(t.TempDir(), sel, "22222222-2222-4222-8222-222222222222")
	if plan.eligible {
		t.Fatal("self retirement must not be eligible for another workspace")
	}
	if plan.reason != aliasReleaseNotSelf {
		t.Fatalf("reason = %q, want %q", plan.reason, aliasReleaseNotSelf)
	}
}

func TestPlanSelfRetireRefusesNonHostedTeam(t *testing.T) {
	// Self-hosted and BYOT teams have no cloud-held controller to revoke through.
	for _, teamID := range []string{
		"default:acme.com",
		"default:evil-aweb.ai",
		"default:aweb.ai.example.com",
		"",
	} {
		sel := &awconfig.Selection{
			WorkspaceID:   "11111111-1111-4111-8111-111111111111",
			TeamID:        teamID,
			IdentityScope: "local",
			AwebURL:       "https://app.aweb.ai",
		}
		plan := planSelfRetire(t.TempDir(), sel, sel.WorkspaceID)
		if plan.eligible {
			t.Fatalf("team %q must not be treated as hosted", teamID)
		}
		if plan.reason != aliasReleaseNotHosted {
			t.Fatalf("team %q: reason = %q, want %q", teamID, plan.reason, aliasReleaseNotHosted)
		}
	}
}

func TestPlanSelfRetireRefusesGlobalAndUnknownScope(t *testing.T) {
	// Unknown scope must fail closed. Guessing "local" here would attempt to
	// revoke a global identity's certificate, which team-authorized removal owns.
	for _, scope := range []string{"global", "", "persistent", "ephemeral"} {
		sel := &awconfig.Selection{
			WorkspaceID:   "11111111-1111-4111-8111-111111111111",
			TeamID:        "default:acme.aweb.ai",
			IdentityScope: scope,
			AwebURL:       "https://app.aweb.ai",
		}
		plan := planSelfRetire(t.TempDir(), sel, sel.WorkspaceID)
		if plan.eligible {
			t.Fatalf("scope %q must not be eligible for self retirement", scope)
		}
		if plan.reason != aliasReleaseGlobalIdentity {
			t.Fatalf("scope %q: reason = %q, want %q", scope, plan.reason, aliasReleaseGlobalIdentity)
		}
	}
}

func TestPlanSelfRetireRefusesWithoutWorkspaceCredential(t *testing.T) {
	// No workspace.yaml at all: neither an API key nor a certificate.
	dir := t.TempDir()
	sel := &awconfig.Selection{
		WorkspaceID:   "11111111-1111-4111-8111-111111111111",
		TeamID:        "default:acme.aweb.ai",
		IdentityScope: "local",
		AwebURL:       "https://app.aweb.ai",
	}
	plan := planSelfRetire(dir, sel, sel.WorkspaceID)
	if plan.eligible {
		t.Fatal("self retirement must not be eligible without a workspace-bound key")
	}
	if plan.reason != aliasReleaseNoCredential {
		t.Fatalf("reason = %q, want %q", plan.reason, aliasReleaseNoCredential)
	}
}

func TestPlanSelfRetireEligibleForOwnHostedLocalWorkspace(t *testing.T) {
	dir := t.TempDir()
	writeSelfRetireWorkspaceConfig(t, dir, "aw_sk_selfretire", "https://app.aweb.ai")
	sel := &awconfig.Selection{
		WorkspaceID:   "11111111-1111-4111-8111-111111111111",
		TeamID:        "default:acme.aweb.ai",
		IdentityScope: "local",
		AwebURL:       "https://app.aweb.ai",
		Alias:         "oats-worker-1",
	}

	plan := planSelfRetire(dir, sel, sel.WorkspaceID)

	if !plan.eligible {
		t.Fatalf("own hosted local workspace must be eligible; reason = %q", plan.reason)
	}
	if plan.apiKey != "aw_sk_selfretire" {
		t.Fatalf("apiKey = %q, want the workspace-bound key", plan.apiKey)
	}
	if plan.teamID != "default:acme.aweb.ai" {
		t.Fatalf("teamID = %q", plan.teamID)
	}
	if plan.alias != "oats-worker-1" {
		t.Fatalf("alias = %q", plan.alias)
	}
	// A workspace-bound key is the narrower credential, so it stays in use where
	// it exists; the certificate path must not silently take over.
	if plan.certificate {
		t.Fatal("a workspace with an API key must not plan the certificate path")
	}
}

func TestSelfRetireAPIPathMatchesRoute(t *testing.T) {
	got := hostedRemovalAPIPath("https://app.aweb.ai", "default:acme.aweb.ai", selfRetireSuffix)
	want := "/api/v1/teams/default%3Aacme.aweb.ai/agents/self-remove"
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	// A base URL already ending in /api must not produce /api/api/...
	got = hostedRemovalAPIPath("https://app.aweb.ai/api", "default:acme.aweb.ai", selfRetireSuffix)
	want = "/v1/teams/default%3Aacme.aweb.ai/agents/self-remove"
	if got != want {
		t.Fatalf("path with /api base = %q, want %q", got, want)
	}
}

func writeSelfRetireWorkspaceConfig(t *testing.T, dir, apiKey, awebURL string) {
	t.Helper()
	awDir := filepath.Join(dir, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	contents := "aweb_url: " + awebURL + "\n"
	// An empty apiKey means the key is ABSENT, which is what a member that
	// joined by invite has. Writing "api_key:" with nothing after it would say
	// the same thing to the loader, but only by accident; omitting the key
	// keeps the fixture honest about which credential is on disk.
	if strings.TrimSpace(apiKey) != "" {
		contents += "api_key: " + apiKey + "\n"
	}
	contents += "memberships:\n" +
		"  - team_id: default:acme.aweb.ai\n" +
		"    alias: oats-worker-1\n" +
		"    workspace_id: 11111111-1111-4111-8111-111111111111\n" +
		"    cert_path: .aw/teams/default_acme.aweb.ai.json\n"
	if err := os.WriteFile(filepath.Join(awDir, "workspace.yaml"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A hosted member that joined by invite - the ordinary OATS case - holds
// signing.key, a team certificate and workspace.yaml, and NO API key. The
// self-remove route accepts that certificate, so refusing to call at all is the
// defect these tests pin down: it reported no_workspace_credential and left the
// alias held.

const selfRetireFixtureWorkspaceID = "11111111-1111-4111-8111-111111111111"
const selfRetireFixtureTeamID = "default:acme.aweb.ai"

func writeSelfRetireCertificateFixture(t *testing.T, dir, awebURL, alias string) {
	t.Helper()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate member keypair: %v", err)
	}
	writeSelectionFixtureForTest(t, dir, testSelectionFixture{
		AwebURL:       awebURL,
		TeamID:        selfRetireFixtureTeamID,
		Alias:         alias,
		WorkspaceID:   selfRetireFixtureWorkspaceID,
		DID:           awid.ComputeDIDKey(pub),
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		SigningKey:    priv,
		CreatedAt:     "2026-04-04T00:00:00Z",
	})
}

func selfRetireSelectionForTest(dir, awebURL, alias string) *awconfig.Selection {
	return &awconfig.Selection{
		WorkingDir:    dir,
		WorkspaceID:   selfRetireFixtureWorkspaceID,
		TeamID:        selfRetireFixtureTeamID,
		IdentityScope: "local",
		AwebURL:       awebURL,
		Alias:         alias,
	}
}

func TestPlanSelfRetireUsesTeamCertificateWithoutAPIKey(t *testing.T) {
	dir := t.TempDir()
	writeSelfRetireCertificateFixture(t, dir, "https://app.aweb.ai/api", "worker")

	plan := planSelfRetire(dir, selfRetireSelectionForTest(dir, "https://app.aweb.ai/api", "worker"), selfRetireFixtureWorkspaceID)

	if !plan.eligible {
		t.Fatalf("certificate-only member must be eligible; reason = %q", plan.reason)
	}
	if !plan.certificate {
		t.Fatal("plan must select the certificate path")
	}
	if plan.apiKey != "" {
		t.Fatalf("apiKey = %q, want empty on the certificate path", plan.apiKey)
	}
	if plan.teamID != selfRetireFixtureTeamID {
		t.Fatalf("teamID = %q", plan.teamID)
	}
	if plan.alias != "worker" {
		t.Fatalf("alias = %q", plan.alias)
	}
}

func TestPlanSelfRetireRefusesWithNeitherKeyNorCertificate(t *testing.T) {
	// workspace.yaml names a cert_path, but no certificate is on disk. A named
	// path is not a credential, and treating it as one would plan a call the
	// client cannot sign.
	dir := t.TempDir()
	writeSelfRetireWorkspaceConfig(t, dir, "", "https://app.aweb.ai/api")

	plan := planSelfRetire(dir, selfRetireSelectionForTest(dir, "https://app.aweb.ai/api", "oats-worker-1"), selfRetireFixtureWorkspaceID)

	if plan.eligible {
		t.Fatal("self retirement must not be eligible without a key or a certificate")
	}
	if plan.reason != aliasReleaseNoCredential {
		t.Fatalf("reason = %q, want %q", plan.reason, aliasReleaseNoCredential)
	}
}

func TestSelfRetireClientPathMatchesRoute(t *testing.T) {
	// The client addresses paths relative to a base URL that already carries
	// /api, so this path must NOT repeat it.
	got := selfRetireClientPath(selfRetireFixtureTeamID)
	want := "/v1/teams/default%3Aacme.aweb.ai/agents/self-remove"
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

// selfRetireCertServerHandler serves the self-remove route for a
// certificate-authenticated caller, verifying the credential the way the cloud
// middleware does before it will look at the body at all.
func selfRetireCertServerHandler(
	t *testing.T,
	alias string,
	sawSelfRemove *atomic.Bool,
	respond func(w http.ResponseWriter),
) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert := requireCertificateAuthForTest(t, r)
		switch {
		case r.URL.Path == "/api/v1/teams/"+selfRetireFixtureTeamID+"/agents/self-remove" && r.Method == http.MethodPost:
			sawSelfRemove.Store(true)
			if strings.TrimSpace(cert.Alias) != alias {
				t.Fatalf("certificate alias = %q, want %q", cert.Alias, alias)
			}
			if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
				t.Fatal("self-remove must be signed, not anonymous")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode self-remove body: %v", err)
			}
			// The route takes the subject from the credential; alias is only ever
			// compared. Sending it is what turns a credential/config mismatch
			// into a refusal.
			if body["alias"] != alias {
				t.Fatalf("body alias = %v, want %q", body["alias"], alias)
			}
			respond(w)
		case r.URL.Path == "/api/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
}

func runSelfRetireDeleteForTest(t *testing.T, serverURL, alias string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeSelfRetireCertificateFixture(t, tmp, serverURL+"/api", alias)

	run := exec.CommandContext(ctx, bin, "workspace", "delete", selfRetireFixtureWorkspaceID)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	return string(out), err
}

func TestAwWorkspaceDeleteSelfRetiresWithTeamCertificate(t *testing.T) {
	t.Parallel()

	var sawSelfRemove atomic.Bool
	server := newLocalHTTPServer(t, selfRetireCertServerHandler(t, "worker", &sawSelfRemove, func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":                "removed",
			"team_id":               selfRetireFixtureTeamID,
			"canonical_team_id":     selfRetireFixtureTeamID,
			"alias":                 "worker",
			"identity_scope":        "local",
			"alias_released":        true,
			"alias_released_reason": "certificate_revoked",
			"workspace_id":          selfRetireFixtureWorkspaceID,
		})
	}))

	out, err := runSelfRetireDeleteForTest(t, server.URL, "worker")
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if !sawSelfRemove.Load() {
		t.Fatalf("self-remove was never called:\n%s", out)
	}
	if !strings.Contains(out, "Released alias for reuse: true") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestAwWorkspaceDeleteSelfRetireReportsServerRefusalAsFailure(t *testing.T) {
	t.Parallel()

	// A refusal must never be reported as a delete. Falling back to the plain
	// workspace delete here is exactly the defect: it would print a success for a
	// retirement that did not happen and leave the alias held.
	var sawSelfRemove atomic.Bool
	server := newLocalHTTPServer(t, selfRetireCertServerHandler(t, "worker", &sawSelfRemove, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"detail": map[string]any{
				"code":    "self_removal_requires_member_credential",
				"message": "refused",
			},
		})
	}))

	out, err := runSelfRetireDeleteForTest(t, server.URL, "worker")
	if err == nil {
		t.Fatalf("refused retirement must fail the command:\n%s", out)
	}
	if !sawSelfRemove.Load() {
		t.Fatalf("self-remove was never called:\n%s", out)
	}
	if !strings.Contains(out, "workspace not retired") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if strings.Contains(out, "Deleted workspace") {
		t.Fatalf("a refused retirement must not report a delete:\n%s", out)
	}
}

func TestAwWorkspaceDeleteSelfRetireReportsUnreleasedAliasAsFailure(t *testing.T) {
	t.Parallel()

	// A 200 that says alias_released false is still not a retirement.
	var sawSelfRemove atomic.Bool
	server := newLocalHTTPServer(t, selfRetireCertServerHandler(t, "worker", &sawSelfRemove, func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":                "already_revoked",
			"team_id":               selfRetireFixtureTeamID,
			"canonical_team_id":     selfRetireFixtureTeamID,
			"alias":                 "worker",
			"identity_scope":        "local",
			"alias_released":        false,
			"alias_released_reason": "registry_unavailable",
			"workspace_id":          selfRetireFixtureWorkspaceID,
		})
	}))

	out, err := runSelfRetireDeleteForTest(t, server.URL, "worker")
	if err == nil {
		t.Fatalf("unreleased alias must fail the command:\n%s", out)
	}
	if !sawSelfRemove.Load() {
		t.Fatalf("self-remove was never called:\n%s", out)
	}
	if !strings.Contains(out, "registry_unavailable") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestAwWorkspaceDeleteSelfRetireStillUsesWorkspaceBoundKey(t *testing.T) {
	t.Parallel()

	// The certificate path is an addition, not a replacement. A workspace that
	// does have a bound key must still authenticate with it - the cloud records a
	// different actor for the two credentials, so switching silently would change
	// the audit trail of every keyed member.
	var sawBearer atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/teams/"+selfRetireFixtureTeamID+"/agents/self-remove" && r.Method == http.MethodPost:
			if got := strings.TrimSpace(r.Header.Get("Authorization")); got != "Bearer aw_sk_selfretire" {
				t.Fatalf("authorization = %q, want the workspace-bound key", got)
			}
			sawBearer.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":                "removed",
				"team_id":               selfRetireFixtureTeamID,
				"canonical_team_id":     selfRetireFixtureTeamID,
				"alias":                 "worker",
				"identity_scope":        "local",
				"alias_released":        true,
				"alias_released_reason": "certificate_revoked",
				"workspace_id":          selfRetireFixtureWorkspaceID,
			})
		case r.URL.Path == "/api/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeSelfRetireCertificateFixture(t, tmp, server.URL+"/api", "worker")
	addWorkspaceAPIKeyForTest(t, tmp, "aw_sk_selfretire")

	run := exec.CommandContext(ctx, bin, "workspace", "delete", selfRetireFixtureWorkspaceID)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !sawBearer.Load() {
		t.Fatalf("self-remove was not called with the workspace-bound key:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Released alias for reuse: true") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func addWorkspaceAPIKeyForTest(t *testing.T, dir, apiKey string) {
	t.Helper()
	path := filepath.Join(dir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(path)
	if err != nil {
		t.Fatalf("load workspace fixture: %v", err)
	}
	workspace.APIKey = apiKey
	if err := awconfig.SaveWorktreeWorkspaceTo(path, workspace); err != nil {
		t.Fatalf("write workspace fixture: %v", err)
	}
}
