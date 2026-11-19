package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const installedChainHuman = "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"

func installedAgentCertificate(issuer string) map[string]any {
	return map[string]any{"v": json.Number("1"), "type": "aweb.id-certificate", "id": "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f",
		"domain": "customer.example", "parent": map[string]any{"kind": "identity", "id": installedChainHuman}, "kind": "agent",
		"issuer_key": issuer, "issued_at": "2026-11-13T10:00:00Z"}
}

func signedCertificate(t *testing.T, key ed25519.PrivateKey, artifact map[string]any) map[string]any {
	t.Helper()
	signing, err := awid.IDCertificateSigningBytes(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"certificate": artifact, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, signing))}
}

func signedHumanCertificate(t *testing.T, humanKey ed25519.PrivateKey) map[string]any {
	t.Helper()
	human := map[string]any{"v": json.Number("1"), "type": "aweb.id-certificate", "id": installedChainHuman, "domain": "example.com",
		"parent": map[string]any{"kind": "namespace", "id": "example.com"}, "kind": "human",
		"issuer_key": awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey)), "issued_at": "2026-11-13T09:00:00Z"}
	signing, err := awid.IDCertificateSigningBytes(human)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"certificate": human, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanKey, signing))}
}

func TestAnAgentInvitesAChildOnlyWithItsInstalledChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	_, humanKey, _ := ed25519.GenerateKey(nil)
	humanDID := awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey))
	artifact := installedAgentCertificate(humanDID)
	signed := signedCertificate(t, humanKey, artifact)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "root-home")
	_, rootKey, _ := ed25519.GenerateKey(nil)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID: awid.ComputeDIDKey(rootKey.Public().(ed25519.PublicKey)), StableID: artifact["id"].(string), Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal, RegistryURL: "https://registry.customer.example", RegistryStatus: "registered",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), rootKey); err != nil {
		t.Fatal(err)
	}
	invite := func() (map[string]any, string, error) {
		command := exec.CommandContext(ctx, bin, "--json", "--identity-home", home, "id", "child", "invite", "--kind", "agent",
			"--recipient", "spawned agent", "--registry", "https://registry.customer.example")
		command.Dir, command.Env = root, testCommandEnv(root)
		out, err := command.CombinedOutput()
		var result map[string]any
		_ = json.Unmarshal(out, &result)
		return result, string(out), err
	}
	if _, out, err := invite(); err == nil || !strings.Contains(out, "no installed chain") {
		t.Fatalf("a root with no installed chain invited: %v %s", err, out)
	}
	if err := awconfig.SaveInstalledIDChain(home, map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{signedHumanCertificate(t, humanKey), signed}}); err != nil {
		t.Fatal(err)
	}
	invited, out, err := invite()
	if err != nil || invited["kind"] != "agent" || invited["invitation_id"] == "" {
		t.Fatalf("invite: %v %s", err, out)
	}
	if parent, _ := invited["parent"].(map[string]any); parent["kind"] != "identity" || parent["id"] != artifact["id"] {
		t.Fatalf("parent %v", invited["parent"])
	}
}
