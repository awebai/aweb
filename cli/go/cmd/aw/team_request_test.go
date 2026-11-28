package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestTeamRequestLocalPrintsAddMemberCommandWithoutStableFields(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), memberKey); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "team", "request", "--team", "backend:acme.com", "--name", "laptop")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("team request failed: %v\n%s", err, string(out))
	}

	text := strings.TrimSpace(string(out))
	if !strings.Contains(text, "aw id team add-member") {
		t.Fatalf("output missing add-member command:\n%s", text)
	}
	if !strings.Contains(text, "--team backend") || !strings.Contains(text, "--namespace acme.com") {
		t.Fatalf("output missing team selector:\n%s", text)
	}
	if !strings.Contains(text, "--did "+memberDID) {
		t.Fatalf("output missing did:\n%s", text)
	}
	if !strings.Contains(text, "--name laptop") {
		t.Fatalf("output missing name:\n%s", text)
	}
	if strings.Contains(text, "--did-aw") || strings.Contains(text, "--address") || strings.Contains(text, "--lifetime") {
		t.Fatalf("local output unexpectedly included global compatibility flags:\n%s", text)
	}
}

func TestTeamRequestGlobalJSONIncludesStableFields(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	stableID := awid.ComputeStableID(memberPub)

	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), memberKey); err != nil {
		t.Fatal(err)
	}
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:           memberDID,
		StableID:      stableID,
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   "https://api.awid.ai",
		CreatedAt:     "2026-04-13T00:00:00Z",
	})

	run := exec.CommandContext(ctx, bin, "id", "team", "request", "--team", "backend:acme.com", "--name", "alice", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("team request failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", got["team_id"])
	}
	if got["did_key"] != memberDID {
		t.Fatalf("did_key=%v", got["did_key"])
	}
	if got["alias"] != "alice" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if got["did_aw"] != stableID {
		t.Fatalf("did_aw=%v", got["did_aw"])
	}
	if got["address"] != "acme.com/alice" {
		t.Fatalf("address=%v", got["address"])
	}
	command, _ := got["command"].(string)
	if !strings.Contains(command, "--global") {
		t.Fatalf("command missing global identity flag: %q", command)
	}
	if !strings.Contains(command, "--did-aw "+stableID) {
		t.Fatalf("command missing did-aw: %q", command)
	}
	if !strings.Contains(command, "--address acme.com/alice") {
		t.Fatalf("command missing address: %q", command)
	}
}

func TestTeamRequestRequiresSigningKey(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "id", "team", "request", "--team", "backend:acme.com", "--name", "alice")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected team request to fail:\n%s", string(out))
	}
	if !strings.Contains(string(out), "current identity has no local signing key") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

// A deprecation warning goes to stderr only: --json output stays one JSON
// document on stdout, wherever --json is placed and when the command fails.
func TestDeprecatedFlagWarningKeepsJSONOutputOneDocument(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	_, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), memberKey); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		team        string
		leadingJSON bool
		fails       bool
	}{
		{"leading-json", "backend:acme.com", true, false},
		{"trailing-json", "backend:acme.com", false, false},
		{"error-after-warning", "nocolon", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"id", "team", "request", "--team", tc.team, "--alias", "laptop"}
			if tc.leadingJSON {
				args = append([]string{"--json"}, args...)
			} else {
				args = append(args, "--json")
			}
			run := exec.CommandContext(ctx, bin, args...)
			run.Env = testCommandEnv(tmp)
			run.Dir = tmp
			var stdout, stderr bytes.Buffer
			run.Stdout, run.Stderr = &stdout, &stderr
			err := run.Run()
			if tc.fails {
				if exitCode(err) != 2 {
					t.Fatalf("expected usage refusal, got %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
				}
			} else if err != nil {
				t.Fatalf("team request failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "Flag --alias has been deprecated, use --name") {
				t.Fatalf("missing deprecation warning on stderr: %q", stderr.String())
			}
			assertOneJSONDocument(t, stdout.Bytes())
			var got map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("invalid stdout JSON: %v\n%s", err, stdout.String())
			}
			if tc.fails {
				if _, ok := got["error"].(map[string]any); !ok {
					t.Fatalf("missing JSON failure after warning: %v", got)
				}
			} else if got["name"] != "laptop" {
				t.Fatalf("request output lost the name: %v", got)
			}
		})
	}
}
