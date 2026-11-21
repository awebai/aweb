package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestOATSWorkspaceStatusAlwaysSerializesPeerArray(t *testing.T) {
	for _, peers := range [][]aweb.WorkspaceInfo{{}, {{WorkspaceID: "peer"}}} {
		encoded, err := json.Marshal(workspaceStatusOutput{Team: peers})
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &result); err != nil {
			t.Fatal(err)
		}
		var team []aweb.WorkspaceInfo
		if err := json.Unmarshal(result["team"], &team); err != nil {
			t.Fatalf("team array: %v\n%s", err, encoded)
		}
		if team == nil || len(team) != len(peers) {
			t.Fatalf("team array: %s", encoded)
		}
	}
}

func TestOATSControllerKeyRefusalPreservesRemedyAndAddsCode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, cause := awconfig.LoadTeamKey("example.com", "one")
	if cause == nil || !errors.Is(cause, os.ErrNotExist) {
		t.Fatalf("missing local key: %v", cause)
	}
	err := teamKeyLoadError("one:example.com", "example.com", cause)
	want := "local team controller key for one:example.com was not found: " + cause.Error() + " (this command is for BYOIDT/BYOD teams where you hold ~/.awid/team-keys/<namespace>/<team>.key; hosted aweb.ai teams should use the dashboard Add existing agent action)"
	if err.Error() != want {
		t.Fatalf("changed remedy: %q", err)
	}
	if code := errorEnvelope(err, err.Error()).Error.Code; code != "controller_key_missing" {
		t.Fatalf("code %q: %v", code, err)
	}
}

// These tests run the production binary over real local identity state. No
// service fixture supplies the answer to an offline inspection command.
func TestOATSOfflineMembershipInspection(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "aw")
	buildAwBinary(t, ctx, bin)
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(dir), memberKey); err != nil {
		t.Fatal(err)
	}
	state := &awconfig.TeamState{ActiveTeam: "one:example.com"}
	workspace := &awconfig.WorktreeWorkspace{AwebURL: "https://service.invalid/api"}
	certs := map[string]*awid.TeamCertificate{}
	for _, name := range []string{"one", "two"} {
		_, key, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		team := name + ":example.com"
		cert, err := awid.SignTeamCertificate(key, awid.TeamCertificateFields{Team: team, MemberDIDKey: awid.ComputeDIDKey(memberPub), Alias: "worker", IdentityScope: awid.IdentityModeLocal})
		if err != nil {
			t.Fatal(err)
		}
		path, err := awconfig.SaveTeamCertificateForTeam(dir, team, cert)
		if err != nil {
			t.Fatal(err)
		}
		certs[team] = cert
		state.Memberships = append(state.Memberships, awconfig.TeamMembership{TeamID: team, Alias: "worker", CertPath: path, RegistryURL: "https://registry.invalid", AwebURL: "https://service.invalid/api"})
		workspace.Memberships = append(workspace.Memberships, awconfig.WorktreeMembership{TeamID: team, Alias: "worker", CertPath: path, WorkspaceID: "workspace-" + name})
	}
	if err := awconfig.SaveTeamState(dir, state); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(awconfig.WorktreeWorkspacePath(dir), workspace); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = dir
		cmd.Env = append(testCommandEnv(t.TempDir()), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
		return cmd.CombinedOutput()
	}
	t.Run("list exposes recorded coordinates for every team", func(t *testing.T) {
		out, err := run("id", "team", "list", "--json")
		if err != nil {
			t.Fatalf("list: %v\n%s", err, out)
		}
		var result struct {
			Memberships []map[string]any `json:"memberships"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if len(result.Memberships) != 2 {
			t.Fatalf("memberships: %s", out)
		}
		for _, row := range result.Memberships {
			team, ok := row["team_id"].(string)
			if !ok {
				t.Fatalf("team_id: %s", out)
			}
			cert := certs[team]
			if cert == nil {
				t.Fatalf("unexpected team: %s", out)
			}
			if row["registry_url"] != "https://registry.invalid" || row["aweb_url"] != "https://service.invalid/api" || row["certificate_id"] != cert.CertificateID || row["workspace_id"] != "workspace-"+strings.Split(team, ":")[0] {
				t.Fatalf("missing coordinates: %s", out)
			}
		}
	})
	t.Run("cert show selects inactive team", func(t *testing.T) {
		out, err := run("id", "cert", "show", "--team", "two:example.com", "--json")
		if err != nil {
			t.Fatalf("show: %v\n%s", err, out)
		}
		var result certShowOutput
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatal(err)
		}
		if result.CertificateID != certs["two:example.com"].CertificateID {
			t.Fatalf("wrong cert: %s", out)
		}
	})
	t.Run("cert show refuses absent team", func(t *testing.T) {
		out, err := run("id", "cert", "show", "--team", "missing:example.com", "--json")
		if err == nil || !strings.Contains(string(out), "teams state is missing selected team membership") {
			t.Fatalf("missing-team refusal: %v\n%s", err, out)
		}
	})
	t.Run("status proves complete local membership and pending markers", func(t *testing.T) {
		for _, marker := range []string{"", "pending-hosted-accept", "partial-init.yaml"} {
			if marker != "" {
				body := "pending-secret"
				if marker == "partial-init.yaml" {
					body = "version: 1\nresponse_json: secret-response\n"
				}
				if err := os.WriteFile(filepath.Join(dir, ".aw", marker), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := run("id", "status", "--team", "two:example.com", "--json")
			if err != nil {
				t.Fatalf("status: %v\n%s", err, out)
			}
			var result map[string]any
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}
			if result["mint_complete"] != (marker == "") || result["certificate_id"] != certs["two:example.com"].CertificateID || result["workspace_id"] != "workspace-two" || result["did"] != awid.ComputeDIDKey(memberPub) {
				t.Fatalf("completion for %q: %s", marker, out)
			}
			if strings.Contains(string(out), "secret") {
				t.Fatalf("status exposed recovery contents: %s", out)
			}
			if marker != "" {
				if err := os.Remove(filepath.Join(dir, ".aw", marker)); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
	t.Run("list preserves absent optional workspace coordinates", func(t *testing.T) {
		if err := os.Remove(awconfig.WorktreeWorkspacePath(dir)); err != nil {
			t.Fatal(err)
		}
		out, err := run("id", "team", "list", "--json")
		if err != nil {
			t.Fatalf("list without binding: %v\n%s", err, out)
		}
		var result struct {
			Memberships []map[string]any `json:"memberships"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatal(err)
		}
		for _, row := range result.Memberships {
			if value, exists := row["workspace_id"]; !exists || value != "" {
				t.Fatalf("absent workspace_id: %s", out)
			}
		}
	})
	t.Run("legacy certificate selection respects requested team", func(t *testing.T) {
		if err := os.Remove(awconfig.TeamStatePath(dir)); err != nil {
			t.Fatal(err)
		}
		out, err := run("id", "cert", "show", "--team", "two:example.com", "--json")
		if err != nil {
			t.Fatalf("legacy selected cert: %v\n%s", err, out)
		}
		var result certShowOutput
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatal(err)
		}
		if result.CertificateID != certs["two:example.com"].CertificateID {
			t.Fatalf("legacy wrong cert: %s", out)
		}
		out, err = run("id", "cert", "show", "--team", "missing:example.com", "--json")
		if err == nil || !strings.Contains(string(out), "no local certificate for team missing:example.com; join that team or select an installed team with --team") {
			t.Fatalf("legacy absent-team refusal: %v\n%s", err, out)
		}
	})
}

func TestOATSOnlineCheckFailsForIncompleteHome(t *testing.T) {
	t.Parallel()
	bin, dir := buildDoctorBinary(t)
	if err := os.MkdirAll(filepath.Join(dir, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(awconfig.WorktreeWorkspacePath(dir), []byte("{invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "check", "--online", "--json")
	cmd.Dir = dir
	cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var result doctorOutput
	if decodeErr := json.Unmarshal([]byte(stdout.String()), &result); decodeErr != nil {
		t.Fatalf("one JSON report: %v\n%s", decodeErr, stdout.String())
	}
	if result.Status != doctorStatusFail {
		t.Fatalf("want failed checks: %s", stdout.String())
	}
	if err == nil {
		t.Fatalf("failed checks exited zero: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Checks failed; follow the next_step for each failed check and rerun aw check --online.") {
		t.Fatalf("actionable failure: %s", stderr.String())
	}
	// Reporting remains useful even with failed checks; the check command owns
	// the exit verdict while doctor preserves its report-only behavior.
	if out, err := runDoctorCLI(t, bin, dir, "doctor", "--online", "--json"); err != nil {
		t.Fatalf("doctor report: %v\n%s", err, out)
	}
	if err := os.Remove(awconfig.WorktreeWorkspacePath(dir)); err != nil {
		t.Fatal(err)
	}
	if out, err := runDoctorCLI(t, bin, dir, "check", "--online", "--json"); err != nil {
		t.Fatalf("no failed checks: %v\n%s", err, out)
	}
}

func TestOATSStatusDistinguishesAbsentFromCorruptExplicitHome(t *testing.T) {
	t.Parallel()
	bin, dir := buildDoctorBinary(t)
	home := filepath.Join(dir, "principal")
	run := func() ([]byte, error) {
		cmd := exec.Command(bin, "--identity-home", home, "id", "status", "--team", "one:example.com", "--json")
		cmd.Dir = dir
		cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
		return cmd.CombinedOutput()
	}
	out, err := run()
	if err != nil {
		t.Fatalf("inspect fresh target: %v\n%s", err, out)
	}
	var status identityStatusOutput
	if err := json.Unmarshal(out, &status); err != nil {
		t.Fatal(err)
	}
	if status.MintComplete || status.SigningKeyPresent || status.IdentityPresent || status.CertificatePresent || status.WorkspaceBound || status.PartialInit.Present || status.PendingHostedAccept {
		t.Fatalf("fresh home claimed complete: %s", out)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "identity.yaml"), []byte("{invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = run()
	if err == nil || !strings.Contains(string(out), "repair that home's recorded state before retrying initialization") {
		t.Fatalf("corrupt is not absent: %v\n%s", err, out)
	}
}

func TestOATSJoinFromRefusesDirtyExplicitHomeBeforeMint(t *testing.T) {
	t.Parallel()
	bin, dir := buildDoctorBinary(t)
	target := filepath.Join(dir, "target")
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(target, "signing.key")
	if err := awid.SaveSigningKey(path, key); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--identity-home", target, "init", "--join-from", filepath.Join(dir, "missing-source"), "--name", "worker", "--do-not-touch-agents-md", "--json")
	cmd.Dir = dir
	cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "refusing to overwrite existing "+path) {
		t.Fatalf("dirty explicit target: %v\n%s", err, out)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("dirty target key changed")
	}
}

func TestOATSJoinFromInviteFailureHasStableCodeAndOriginalSuffix(t *testing.T) {
	t.Parallel()
	bin, dir := buildDoctorBinary(t)
	source := filepath.Join(dir, "source")
	state := &awconfig.TeamState{ActiveTeam: "one:example.com", Memberships: []awconfig.TeamMembership{{TeamID: "one:example.com", Alias: "root", CertPath: "team-certs/one__example.com.pem"}}}
	if err := awconfig.SaveTeamState(source, state); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "init", "--join-from", source, "--join-team", state.ActiveTeam, "--name", "worker", "--do-not-touch-agents-md", "--json")
	cmd.Dir = dir
	cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("missing source workspace must fail before an invite is minted")
	}
	var result cliErrorEnvelope
	if err := json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatalf("envelope: %v\n%s", err, stdout.String())
	}
	if result.Error.Code != "invite_not_created" || !strings.HasSuffix(result.Error.Message, "; alternatively use --admission-team-id one:example.com with host authorization") {
		t.Fatalf("invite refusal: %s\n%s", stdout.String(), stderr.String())
	}
}

func TestOATSValidationUsesPublishedCLIWithoutIdentity(t *testing.T) {
	t.Parallel()
	bin, dir := buildDoctorBinary(t)
	for _, test := range []struct{ kind, input, canonical, remedy string }{
		{kind: "alias", input: " Worker-1 ", canonical: "worker-1"},
		{kind: "alias", input: "a.b", canonical: "a.b"},
		{kind: "alias", input: "bad/name", remedy: "Use a nonempty enrollment alias without '/' and retry."},
		{kind: "team-id", input: "Backend:Example.COM", canonical: "backend:example.com"},
		{kind: "team-id", input: "missing-colon", remedy: "Use a team ID in name:domain form."},
		{kind: "team-server-url", input: "https://example.com/aw/api", canonical: "https://example.com/aw/api"},
		{kind: "team-server-url", input: "http://example.com", remedy: "Use an HTTPS team server URL, or an allowed loopback URL for local use."},
	} {
		t.Run(test.kind+"/"+test.input, func(t *testing.T) {
			cmd := exec.Command(bin, "validate", test.kind, test.input, "--json")
			cmd.Dir = dir
			cmd.Env = append(testCommandEnv(dir), "AWEB_IDENTITY_HOME="+filepath.Join(dir, "nonexistent-principal"), "AW_NO_UPDATE_CHECK=1")
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var result struct {
				Valid     bool   `json:"valid"`
				Canonical string `json:"canonical"`
			}
			if decodeErr := json.Unmarshal([]byte(stdout.String()), &result); decodeErr != nil {
				t.Fatalf("validation JSON: %v\n%s\n%s", decodeErr, stdout.String(), stderr.String())
			}
			if test.remedy == "" {
				if err != nil || !result.Valid || result.Canonical != test.canonical {
					t.Fatalf("validation: %v\n%s\n%s", err, stdout.String(), stderr.String())
				}
			} else if err == nil || result.Valid || !strings.Contains(stderr.String(), test.remedy) {
				t.Fatalf("invalid input remedy: %v\n%s\n%s", err, stdout.String(), stderr.String())
			}
		})
	}
}

func TestOATSWakeReadinessReportsProvenAbsenceWithoutClaimingReadiness(t *testing.T) {
	t.Parallel()
	bin, dir := buildDoctorBinary(t)
	cmd := exec.Command(bin, "wake", "status", "--home", dir, "--min-daemon-version", "1.36.13", "--json")
	cmd.Dir = dir
	cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=", "AW_WAKE_STATE_DIR="+filepath.Join(dir, "broker"))
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("wake status: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	var result struct {
		ControlError string `json:"control_error"`
		Readiness    struct {
			Ready  bool   `json:"ready"`
			Code   string `json:"code"`
			Reason string `json:"reason"`
		} `json:"readiness"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatal(err)
	}
	if result.Readiness.Ready || result.Readiness.Code != "daemon_not_running" || result.ControlError == "" || result.Readiness.Reason != "Start the wake service, then rerun aw wake status." {
		t.Fatalf("proved absence readiness: %s", stdout.String())
	}
}

func TestOATSRevokeUnusedLocalInviteAndReportConsumed(t *testing.T) {
	bin, dir := buildDoctorBinary(t)
	t.Setenv("HOME", dir)
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("example.com", "one", key); err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{InviteID: "unused-test-invite", Domain: "example.com", TeamName: "one", Secret: "not-for-output", IdentityScope: awid.IdentityModeLocal, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	run := func(id string) ([]byte, error) {
		cmd := exec.Command(bin, "id", "team", "revoke-invite", "--invite-id", id, "--json")
		cmd.Dir = dir
		cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
		return cmd.CombinedOutput()
	}
	out, err := run(invite.InviteID)
	if err != nil {
		t.Fatalf("cancel unused: %v\n%s", err, out)
	}
	var result struct {
		Status   string `json:"status"`
		Message  string `json:"message"`
		NextStep string `json:"next_step"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "cancelled" || !strings.Contains(result.Message, "unused invite") || !strings.Contains(result.Message, "does not revoke an issued certificate") || !strings.Contains(result.NextStep, "aw id team remove-member --team one --namespace example.com") {
		t.Fatalf("cancellation scope: %s", out)
	}
	if strings.Contains(string(out), invite.Secret) {
		t.Fatal("cancellation leaked token secret")
	}
	out, err = run(invite.InviteID)
	if err != nil {
		t.Fatalf("absent cancellation is idempotent: %v\n%s", err, out)
	}
	var absent inviteCancellationOutput
	if json.NewDecoder(strings.NewReader(string(out))).Decode(&absent) != nil || absent.Code != "invite_absent" || absent.Status != inviteAbsent || absent.Message != "No pending local invite is stored here; it may already have been used. This does not revoke an issued certificate." {
		t.Fatalf("absent did not distinguish used: %s", out)
	}
	// An existing secret-free tombstone establishes consumption; unlike an
	// absent legacy record it must never be described as a cancelled invite.
	used := *invite
	used.InviteID = "used-test-invite"
	if err := awconfig.SaveTeamInvite(&used); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.ConsumeTeamInvite(awconfig.ConsumeTeamInviteInput{InviteID: used.InviteID, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	out, err = run(used.InviteID)
	var consumed inviteCancellationOutput
	if err == nil || json.NewDecoder(strings.NewReader(string(out))).Decode(&consumed) != nil || consumed.Code != "invite_already_used" || consumed.Status != inviteAlreadyUsed || !strings.HasPrefix(consumed.NextStep, "aw id team remove-member ") {
		t.Fatalf("used is not cancelled: %v\n%s", err, out)
	}
	childStore := awconfig.IDInvitationFileStore{Dir: awconfig.IdentityInvitationsDir(filepath.Join(dir, "issuer"))}
	childID := "11111111-1111-4111-8111-111111111111"
	child := &awid.IDInvitation{InvitationID: childID, Mode: awid.IDInvitationSelfCustodial, Parent: map[string]any{"id": "did:aw:parent"}, Domain: "example.com", Kind: "agent", Recipient: "unused child", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := childStore.PutInvitation(child); err != nil {
		t.Fatal(err)
	}
	invite.InviteID = "linked-test-invite"
	invite.IDChild = &awconfig.TeamInviteIDChild{InvitationID: childID, Parent: "did:aw:parent", Domain: "example.com", IssuerHome: filepath.Join(dir, "issuer")}
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	out, err = run(invite.InviteID)
	if err != nil || !strings.Contains(string(out), "voided") {
		t.Fatalf("linked child disposition: %v\n%s", err, out)
	}
	child, err = childStore.Invitation(childID)
	if err != nil || child == nil || !child.Void {
		t.Fatalf("linked child was left usable: %#v; %v", child, err)
	}
}

func requireConsumedInviteRecord(t *testing.T, inviteID string) {
	t.Helper()
	invite, err := awconfig.LoadTeamInvite(inviteID)
	if err != nil {
		t.Fatalf("read consumed invite: %v", err)
	}
	if invite.Secret != "" || invite.ConsumedAt == "" {
		t.Fatalf("consumed invite must retain only a secret-free tombstone: %s", inviteID)
	}
}

func TestOATSRegistrationErrorDecoderPreservesEveryServiceSentenceAndCode(t *testing.T) {
	for _, code := range []string{"service_url_mismatch", "awid_team_not_found", "awid_team_controller_mismatch", "awid_team_missing_controller", "invalid_controller_signature", "invalid_controller_timestamp", "validation_error", "future_service_refusal"} {
		body := []byte(`{"detail":{"code":"` + code + `","message":"Choose the correct controller and retry."}}`)
		err := serviceRegisterRefusal(serviceRegisterFailure{Status: 422, Body: body})
		want := `service register: http 422: {"code":"` + code + `","message":"Choose the correct controller and retry."}`
		if err.Error() != want {
			t.Fatalf("service sentence changed: %q", err)
		}
		envelope := errorEnvelope(err, err.Error())
		if envelope.Error.Code != code || envelope.Error.Reason != code || envelope.Error.HTTPStatus != 422 || envelope.Error.Message != want {
			t.Fatalf("service error lost code/metadata: %#v", envelope)
		}
	}
}

func TestOATSNamespaceControllerRefusalHasCodeAndPreservesRemedy(t *testing.T) {
	t.Parallel()
	bin, dir := buildDoctorBinary(t)
	cmd := exec.Command(bin, "id", "team", "create", "--name", "one", "--namespace", "example.com", "--json")
	cmd.Dir = dir
	cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("missing namespace controller accepted")
	}
	var result cliErrorEnvelope
	if err := json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		t.Fatal(err)
	}
	want := "no local controller key for --namespace example.com; pass --hosted for a hosted sibling, or install the namespace controller key for BYOT (aw id namespace prepare-controller --domain example.com)"
	if result.Error.Code != codeControllerKeyMissing || result.Error.Message != want {
		t.Fatalf("controller remedy: %s\n%s", stdout.String(), stderr.String())
	}
}

func TestOATSInvitePreflightUsesMintAuthorityWithoutCreatingRecords(t *testing.T) {
	bin, dir := buildDoctorBinary(t)
	t.Setenv("HOME", dir)
	teamID := "one:example.com"
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{ActiveTeam: teamID, Memberships: []awconfig.TeamMembership{{TeamID: teamID, Alias: "root", CertPath: "team-certs/one__example.com.pem", RegistryURL: "https://registry.invalid", AwebURL: "https://service.invalid"}}}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(awconfig.WorktreeWorkspacePath(dir), &awconfig.WorktreeWorkspace{AwebURL: "https://service.invalid", Memberships: []awconfig.WorktreeMembership{{TeamID: teamID, Alias: "root", CertPath: "team-certs/one__example.com.pem", WorkspaceID: "11111111-1111-4111-8111-111111111111"}}}); err != nil {
		t.Fatal(err)
	}
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("example.com", "one", key); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"controller", "hosted"} {
		for _, prefix := range [][]string{{"team", "invite"}, {"id", "team", "invite"}} {
			cmd := exec.Command(bin, append(prefix, "--team-id", teamID, "--preflight", "--json")...)
			cmd.Dir = dir
			cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("preflight %s: %v\n%s", kind, err, out)
			}
			var result map[string]any
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}
			if result["kind"] != kind || result["team_id"] != teamID {
				t.Fatalf("wrong authority plan: %s", out)
			}
			if kind == "controller" {
				expiry, valid := result["expires_at"].(string)
				if !valid || result["expiry_known"] != true {
					t.Fatalf("controller preflight omitted its authoritative lifetime: %s", out)
				}
				parsed, err := time.Parse(time.RFC3339Nano, expiry)
				if err != nil || time.Until(parsed) < 23*time.Hour || time.Until(parsed) > 24*time.Hour {
					t.Fatalf("controller preflight did not use the 24h policy: %s; %v", out, err)
				}
			} else if result["expiry_known"] != false || result["expires_at"] != "" {
				t.Fatalf("hosted preflight guessed an unreported expiry: %s", out)
			}
			if _, exists := result["token"]; exists {
				t.Fatalf("preflight minted a token: %s", out)
			}
			for _, path := range []string{filepath.Join(dir, ".config", "aw", "team-invites"), filepath.Join(dir, ".aw", "invitations"), filepath.Join(dir, ".aw", "signing.key")} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("preflight created %s: %v", path, err)
				}
			}
		}
		if kind == "controller" {
			path, err := awconfig.TeamKeyPath("example.com", "one")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestOATSGlobalCompletionRequiresRecordedRegistration(t *testing.T) {
	t.Parallel()
	bin, dir := buildDoctorBinary(t)
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(dir), key); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamID := "one:example.com"
	identity := &awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(pub), StableID: awid.ComputeStableID(pub), Address: "example.com/worker", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryStatus: "pending"}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: identity.DID, MemberDIDAW: identity.StableID, MemberAddress: identity.Address, Alias: "worker", IdentityScope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatal(err)
	}
	certPath, err := awconfig.SaveTeamCertificateForTeam(dir, teamID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{ActiveTeam: teamID, Memberships: []awconfig.TeamMembership{{TeamID: teamID, Alias: "worker", CertPath: certPath}}}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(awconfig.WorktreeWorkspacePath(dir), &awconfig.WorktreeWorkspace{AwebURL: "https://service.invalid", Memberships: []awconfig.WorktreeMembership{{TeamID: teamID, Alias: "worker", CertPath: certPath, WorkspaceID: "workspace-one"}}}); err != nil {
		t.Fatal(err)
	}
	for _, registration := range []string{"pending", "registered"} {
		identity.RegistryStatus = registration
		if err := awconfig.SaveWorktreeIdentityTo(awconfig.WorktreeIdentityPath(dir), identity); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "id", "status", "--team", teamID, "--json")
		cmd.Dir, cmd.Env = dir, append(testCommandEnv(dir), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("status: %v\n%s", err, out)
		}
		var result map[string]any
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatal(err)
		}
		if result["mint_complete"] != (registration == "registered") {
			t.Fatalf("registration %s completion: %s", registration, out)
		}
	}
}
