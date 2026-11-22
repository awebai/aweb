package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestClaimHumanRequestBinaryProducesSharedArtifactWithoutMemberHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	home := t.TempDir()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	writeTeamKeyForTest(t, home, "example.com", "research", key)
	run := func(timestamp string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bin, "id", "team", "claim-human-request",
			"--team", "Research", "--namespace", "Example.com", "--username", " Owner ",
			"--email", " Owner@Example.com ", "--timestamp", timestamp, "--json")
		cmd.Dir = home
		cmd.Env = append(testCommandEnv(home), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AWID_REGISTRY_URL=")
		return cmd.CombinedOutput()
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	output, err := run(timestamp)
	if err != nil {
		t.Fatalf("producer failed: %v\n%s", err, output)
	}
	artifact, err := awid.ParseUnownedTeamClaim(output)
	if err != nil {
		t.Fatalf("shared artifact reader refused output: %v\n%s", err, output)
	}
	if err := artifact.VerifyIntegrity(); err != nil {
		t.Fatal(err)
	}
	if artifact.SignerDIDKey != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) ||
		artifact.Request.AWIDTeamID != "research:example.com" || artifact.Request.Timestamp != timestamp ||
		artifact.Request.Email != "owner@example.com" || artifact.Request.Username != "owner" {
		t.Fatalf("artifact=%#v", artifact)
	}
	if _, err := os.Stat(filepath.Join(home, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("producer created member state: %v", err)
	}
	for _, timestamp := range []string{"1990-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "invalid"} {
		output, err := run(timestamp)
		if err == nil || !strings.Contains(string(output), "timestamp") {
			t.Fatalf("timestamp %q was not refused: error=%v output=%s", timestamp, err, output)
		}
		if _, err := awid.ParseUnownedTeamClaim(output); err == nil {
			t.Fatal("refused input emitted a usable claim artifact")
		}
	}
}
