package main

import (
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

func TestTeamRequestEphemeralPrintsAddMemberCommandWithoutStableFields(t *testing.T) {
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

	run := exec.CommandContext(ctx, bin, "id", "team", "request", "--team", "backend:acme.com", "--alias", "laptop")
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
	if !strings.Contains(text, "--alias laptop") {
		t.Fatalf("output missing alias:\n%s", text)
	}
	if strings.Contains(text, "--did-aw") || strings.Contains(text, "--address") || strings.Contains(text, "--lifetime") {
		t.Fatalf("ephemeral output unexpectedly included persistent flags:\n%s", text)
	}
}

func TestTeamRequestPersistentJSONIncludesStableFields(t *testing.T) {
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
		DID:         memberDID,
		StableID:    stableID,
		Address:     "acme.com/alice",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: "https://api.awid.ai",
		CreatedAt:   "2026-04-13T00:00:00Z",
	})

	run := exec.CommandContext(ctx, bin, "id", "team", "request", "--team", "backend:acme.com", "--alias", "alice", "--json")
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
	if !strings.Contains(command, "--lifetime persistent") {
		t.Fatalf("command missing persistent lifetime: %q", command)
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

	run := exec.CommandContext(ctx, bin, "id", "team", "request", "--team", "backend:acme.com", "--alias", "alice")
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
