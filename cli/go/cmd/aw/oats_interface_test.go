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
		{kind: "alias", input: " Worker-1 ", canonical: "Worker-1"},
		{kind: "alias", input: "bad/name", remedy: "Use 1 to 64 letters, digits, underscores or hyphens, starting with a letter or digit."},
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
