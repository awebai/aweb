package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// A forced local-key replacement against the real server and registry: the
// member has lost its signing key, the team controller replaces it, and the
// home ends with a new key, a certificate for that key, no inherited
// ancestry, the same E2E key, and an E2E assertion doctor confirms.
func TestRealReplaceKeyRestoresALocalMemberThatLostItsSigningKey(t *testing.T) {
	world := newRealCommandWorld(t)
	t.Setenv("HOME", world.UserHome)
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerMeta(world.Domain, &awconfig.ControllerMeta{Domain: world.Domain, RegistryURL: world.Stack.RegistryURL}); err != nil {
		t.Fatal(err)
	}
	issuer := world.addLocalMember(t, "issuer")
	// The developer joins the way an agent does: an invite from a member, then
	// `aw team join` in a fresh directory, with no identity home selected.
	var invite teamInviteOutput
	if out := world.requireCommand(t, issuer.Home, "team", "invite", "--team-id", world.TeamID); json.Unmarshal([]byte(out), &invite) != nil || invite.Token == "" {
		t.Fatalf("invite: %s", out)
	}
	developerDir := t.TempDir()
	join := exec.CommandContext(world.Context, world.Binary, "--json", "team", "join", invite.Token, "--name", "developer")
	join.Dir = developerDir
	join.Env = append(idCreateCommandEnv(world.UserHome), "AWID_REGISTRY_URL="+world.Stack.RegistryURL, "AW_NO_UPDATE_CHECK=1", awconfig.IdentityHomeEnv+"=")
	if out, err := join.CombinedOutput(); err != nil {
		t.Fatalf("team join: %v\n%s", err, out)
	}
	developer := commandMember{Home: filepath.Join(developerDir, ".aw")}
	// A joined local home has no identity.yaml; recovery must not depend on one.
	if _, err := os.Stat(filepath.Join(developer.Home, "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("joined local home unexpectedly has identity.yaml: %v", err)
	}

	var oldIdentity struct {
		DIDKey string `json:"did_key"`
	}
	if out := world.requireCommand(t, developer.Home, "id", "show"); json.Unmarshal([]byte(out), &oldIdentity) != nil || oldIdentity.DIDKey == "" {
		t.Fatalf("decode developer identity: %s", out)
	}
	requireWhoLegacyLocal(t, world, developer.Home, oldIdentity.DIDKey)
	var oldEncryption struct {
		KeyID string `json:"key_id"`
	}
	if out := world.requireCommand(t, developer.Home, "id", "encryption-key", "show"); json.Unmarshal([]byte(out), &oldEncryption) != nil || oldEncryption.KeyID == "" {
		t.Fatalf("decode developer E2E key: %s", out)
	}
	if err := os.Remove(filepath.Join(developer.Home, "signing.key")); err != nil {
		t.Fatal(err)
	}

	replace := exec.CommandContext(world.Context, world.Binary, "--identity-home", issuer.Home, "--json", "team", "admin", "replace-key", "developer",
		"--old-did-key", oldIdentity.DIDKey,
		"--home", filepath.Dir(developer.Home),
		"--generate-new-key",
		"--aweb-url", world.Stack.ServerURL,
		"--registry", world.Stack.RegistryURL)
	replace.Dir = filepath.Dir(issuer.Home)
	replace.Env = append(idCreateCommandEnv(world.UserHome), "AWID_REGISTRY_URL="+world.Stack.RegistryURL, "AW_NO_UPDATE_CHECK=1")
	var stderr bytes.Buffer
	replace.Stderr = &stderr
	stdout, err := replace.Output()
	out := string(stdout)
	if err != nil {
		t.Fatalf("replace-key: %v\n%s\n%s", err, out, stderr.String())
	}
	if !strings.Contains(stderr.String(), "The new key will not have the old key's mail or chat conversations.") {
		t.Fatalf("replace-key did not warn on stderr: %s", stderr.String())
	}
	var replaced struct {
		NewDIDKey       string `json:"new_did_key"`
		SigningKeyPath  string `json:"signing_key_path"`
		CertificatePath string `json:"certificate_path"`
		EncryptionKeyID string `json:"encryption_key_id"`
	}
	if json.Unmarshal([]byte(out), &replaced) != nil || replaced.NewDIDKey == "" || replaced.NewDIDKey == oldIdentity.DIDKey ||
		replaced.SigningKeyPath == "" || replaced.CertificatePath == "" {
		t.Fatalf("incomplete replace-key output: %s", out)
	}
	if replaced.EncryptionKeyID != oldEncryption.KeyID {
		t.Fatalf("replace-key rotated the E2E key: got %s, want %s", replaced.EncryptionKeyID, oldEncryption.KeyID)
	}

	var newIdentity struct {
		DIDKey string `json:"did_key"`
	}
	if out := world.requireCommand(t, developer.Home, "id", "show"); json.Unmarshal([]byte(out), &newIdentity) != nil || newIdentity.DIDKey != replaced.NewDIDKey {
		t.Fatalf("home identity after replacement: %s", out)
	}
	// The replacement key inherits no ancestry from the key it replaces.
	requireWhoLegacyLocal(t, world, developer.Home, replaced.NewDIDKey)
	var certificate struct {
		MemberDIDKey string `json:"member_did_key"`
	}
	if out := world.requireCommand(t, developer.Home, "id", "cert", "show"); json.Unmarshal([]byte(out), &certificate) != nil || certificate.MemberDIDKey != replaced.NewDIDKey {
		t.Fatalf("replacement certificate: %s", out)
	}
	var doctor struct {
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	doctorOut, _ := world.runInIdentityHome(developer.Home, "doctor")
	if json.Unmarshal([]byte(doctorOut), &doctor) != nil {
		t.Fatalf("decode doctor: %s", doctorOut)
	}
	for _, check := range doctor.Checks {
		if check.ID == "identity.e2ee.assertion" && check.Status == "ok" {
			return
		}
	}
	t.Fatalf("doctor did not confirm the refreshed E2E assertion: %s", doctorOut)
}

// requireWhoLegacyLocal checks `aw who` for a local did:key identity made
// without an id-tree chain.
func requireWhoLegacyLocal(t *testing.T, world *realCommandWorld, home, didKey string) {
	t.Helper()
	out := world.requireCommand(t, home, "who")
	var who map[string]any
	if err := json.Unmarshal([]byte(out), &who); err != nil {
		t.Fatalf("decode aw who: %v\n%s", err, out)
	}
	for _, field := range []string{"human_id", "identity_valid", "kind"} {
		if value, ok := who[field]; !ok || value != nil {
			t.Fatalf("aw who %s = %v (present %v), want null:\n%s", field, value, ok, out)
		}
	}
	if _, hasChain := who["chain"]; who["id"] != didKey || who["outcome"] != "unknown" || who["reason"] != "legacy_no_chain" || hasChain {
		t.Fatalf("aw who for %s:\n%s", didKey, out)
	}
}
