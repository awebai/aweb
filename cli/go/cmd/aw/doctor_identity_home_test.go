package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestExternalIdentityHomeDoctorIdentityAndRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	canonicalTmp, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(canonicalTmp, "aw")
	instance := filepath.Join(canonicalTmp, "instance")
	principalDir := filepath.Join(canonicalTmp, "principal")
	identityHome := filepath.Join(principalDir, ".aw")
	if err := os.MkdirAll(instance, 0o755); err != nil {
		t.Fatal(err)
	}
	buildAwBinary(t, ctx, bin)

	principalPub, principalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	principalStableID := awid.ComputeStableID(principalPub)
	writeStandaloneSelfCustodyIdentity(t, principalDir, "external.aweb.ai/principal", principalDID, principalStableID, "https://registry.external.example", principalKey)
	writeWorkspaceBindingForTest(t, principalDir, workspaceBinding("https://aweb.external.example", "default:external.aweb.ai", "principal", "principal-workspace"))
	principalIdentity, err := awconfig.ResolveIdentityFromHome(instance, identityHome)
	if err != nil {
		t.Fatal(err)
	}
	principalEncryption, _, err := createLocalEncryptionKeyRecord(principalIdentity, principalKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveEncryptionKeyStateTo(filepath.Join(identityHome, "encryption.yaml"), &awconfig.EncryptionKeyState{
		ActiveKeyID: principalEncryption.KeyID,
		Keys:        []awconfig.EncryptionKeyRecord{*principalEncryption},
	}); err != nil {
		t.Fatal(err)
	}

	runDoctor := func(category string) doctorOutput {
		t.Helper()
		command := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "doctor", category, "--offline", "--json")
		command.Env = testCommandEnv(tmp)
		command.Dir = instance
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("doctor %s failed: %v\n%s", category, err, out)
		}
		var result doctorOutput
		if err := json.Unmarshal(extractJSON(t, out), &result); err != nil {
			t.Fatalf("decode doctor %s output: %v\n%s", category, err, out)
		}
		return result
	}
	findCheck := func(out doctorOutput, id string) doctorCheck {
		t.Helper()
		for _, check := range out.Checks {
			if check.ID == id {
				return check
			}
		}
		t.Fatalf("doctor output omitted check %s", id)
		return doctorCheck{}
	}
	assertExternalSubject := func(out doctorOutput) {
		t.Helper()
		if out.Subject.Alias != "principal" || out.Subject.WorkspaceID != "principal-workspace" || out.Subject.IdentityPath != filepath.Join(identityHome, "identity.yaml") {
			t.Fatalf("doctor subject did not use external principal: %+v", out.Subject)
		}
	}
	assertIdentity := func(out doctorOutput) {
		t.Helper()
		assertExternalSubject(out)
		contextCheck := findCheck(out, doctorCheckIdentityLocalContext)
		if contextCheck.Status != doctorStatusOK || contextCheck.Detail["source"] != ".aw/identity.yaml" {
			t.Fatalf("identity doctor did not load external identity.yaml: %+v", contextCheck)
		}
		address := findCheck(out, doctorCheckIdentityLocalAddress)
		if address.Status != doctorStatusOK || address.Target == nil || address.Target.ID != "external.aweb.ai/principal" {
			t.Fatalf("identity doctor inspected wrong address: %+v", address)
		}
		signing := findCheck(out, doctorCheckIdentityLocalSigningKey)
		if signing.Status != doctorStatusOK || signing.Target == nil || signing.Target.ID != principalDID {
			t.Fatalf("identity doctor inspected wrong signing key: %+v", signing)
		}
		encryption := findCheck(out, doctorCheckIdentityEncryptionState)
		if encryption.Status != doctorStatusOK || encryption.Target == nil || encryption.Target.ID != filepath.Join(identityHome, "encryption.yaml") {
			t.Fatalf("identity doctor inspected wrong encryption state path: %+v", encryption)
		}
		private := findCheck(out, doctorCheckIdentityEncryptionPrivate)
		privatePath, _ := resolveIdentityStoredPath(instance, identityHome, principalEncryption.PrivateKeyPath)
		if private.Status != doctorStatusOK || private.Target == nil || private.Target.ID != privatePath {
			t.Fatalf("identity doctor inspected wrong encryption private key: %+v", private)
		}
		assertion := findCheck(out, doctorCheckIdentityEncryptionAssertion)
		assertionPath, _ := resolveIdentityStoredPath(instance, identityHome, principalEncryption.AssertionPath)
		if assertion.Status != doctorStatusOK || assertion.Target == nil || assertion.Target.ID != assertionPath {
			t.Fatalf("identity doctor inspected wrong encryption assertion: %+v", assertion)
		}
	}
	assertRegistry := func(out doctorOutput) {
		t.Helper()
		assertExternalSubject(out)
		resolve := findCheck(out, doctorCheckAWIDDIDResolve)
		if resolve.Status != doctorStatusUnknown || resolve.Detail["reason"] != "offline_mode" {
			t.Fatalf("registry doctor did not inspect external global identity: %+v", resolve)
		}
	}

	if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("disposable instance was not initially empty: %v", err)
	}
	assertIdentity(runDoctor("identity"))
	assertRegistry(runDoctor("registry"))
	if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("doctor created state in empty instance: %v", err)
	}

	identityPath := filepath.Join(identityHome, "identity.yaml")
	identityData, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(identityPath); err != nil {
		t.Fatal(err)
	}
	certificateFallback := runDoctor("identity")
	contextCheck := findCheck(certificateFallback, doctorCheckIdentityLocalContext)
	if contextCheck.Status != doctorStatusFail || contextCheck.Detail["source"] != "team_certificate" || contextCheck.Detail["expected_identity_scope"] != awid.IdentityModeGlobal {
		t.Fatalf("identity doctor did not use external certificate fallback: %+v", contextCheck)
	}
	fallbackSigning := findCheck(certificateFallback, doctorCheckIdentityLocalSigningKey)
	if fallbackSigning.Status != doctorStatusOK || fallbackSigning.Target == nil || fallbackSigning.Target.ID != principalDID {
		t.Fatalf("certificate fallback used wrong external signing key: %+v", fallbackSigning)
	}
	if err := os.WriteFile(identityPath, identityData, 0o600); err != nil {
		t.Fatal(err)
	}

	shadowPub, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	shadowDID := awid.ComputeDIDKey(shadowPub)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(instance), shadowKey); err != nil {
		t.Fatal(err)
	}
	writeIdentityForTest(t, instance, awconfig.WorktreeIdentity{
		DID:           shadowDID,
		Address:       "shadow.local/shadow",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     "2026-07-26T00:00:00Z",
	})
	writeWorkspaceBindingForTest(t, instance, workspaceBinding("https://shadow.invalid", "shadow:local", "shadow", "shadow-workspace"))
	shadowIdentity, err := awconfig.ResolveIdentity(instance)
	if err != nil {
		t.Fatal(err)
	}
	shadowEncryption, _, err := createLocalEncryptionKeyRecord(shadowIdentity, shadowKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveEncryptionKeyStateTo(awconfig.WorktreeEncryptionStatePath(instance), &awconfig.EncryptionKeyState{
		ActiveKeyID: shadowEncryption.KeyID,
		Keys:        []awconfig.EncryptionKeyRecord{*shadowEncryption},
	}); err != nil {
		t.Fatal(err)
	}
	shadowBefore := fileDigestsForTest(t, filepath.Join(instance, ".aw"))
	shadowIdentityOutput := runDoctor("identity")
	assertIdentity(shadowIdentityOutput)
	shadowRegistryOutput := runDoctor("registry")
	assertRegistry(shadowRegistryOutput)
	for category, output := range map[string]doctorOutput{"identity": shadowIdentityOutput, "registry": shadowRegistryOutput} {
		data, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "shadow.local") || strings.Contains(string(data), shadowDID) || strings.Contains(string(data), "shadow-workspace") || strings.Contains(string(data), shadowEncryption.KeyID) {
			t.Fatalf("doctor %s leaked disposable shadow state: %s", category, data)
		}
	}
	if shadowAfter := fileDigestsForTest(t, filepath.Join(instance, ".aw")); !reflect.DeepEqual(shadowAfter, shadowBefore) {
		t.Fatal("doctor read path mutated the disposable instance shadow")
	}
}

func TestExternalIdentityHomeUnsafeDoctorCommandsRemainRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(tmp, "aw")
	instance := filepath.Join(tmp, "instance")
	identityHome := filepath.Join(tmp, "principal")
	if err := os.MkdirAll(instance, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(identityHome, 0o755); err != nil {
		t.Fatal(err)
	}
	buildAwBinary(t, ctx, bin)

	bundlePath := filepath.Join(tmp, "support.json")
	commands := [][]string{
		{"doctor", "--offline", "--json"},
		{"check", "--offline", "--json"},
		{"doctor", "support-bundle", "--offline", "--output", bundlePath},
	}
	for _, args := range commands {
		command := exec.CommandContext(ctx, bin, append([]string{"--identity-home", identityHome}, args...)...)
		command.Env = testCommandEnv(tmp)
		command.Dir = instance
		out, err := command.CombinedOutput()
		text := string(out)
		if err == nil || !strings.Contains(text, "not yet identity-home-aware") {
			t.Fatalf("unsafe aw %s did not remain default-denied: err=%v\n%s", strings.Join(args, " "), err, out)
		}
		if args[0] == "doctor" {
			for _, alternative := range []string{"aw doctor identity", "aw doctor registry"} {
				if !strings.Contains(text, alternative) {
					t.Fatalf("doctor refusal omitted derived safe alternative %q:\n%s", alternative, text)
				}
			}
		} else if !strings.Contains(text, "No command in this group is currently supported for an attached principal") {
			t.Fatalf("empty-group refusal was not actionable:\n%s", text)
		}
	}
	if _, err := os.Lstat(bundlePath); !os.IsNotExist(err) {
		t.Fatalf("refused support bundle wrote an artifact: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("refused diagnostics mutated instance: %v", err)
	}
}
