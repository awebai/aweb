package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
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
	type observedDoctorRequest struct {
		authorization string
		certificate   string
		timestamp     string
		body          []byte
	}
	var requestMu sync.Mutex
	var authenticatedRequests []observedDoctorRequest
	principalServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
			requestMu.Lock()
			authenticatedRequests = append(authenticatedRequests, observedDoctorRequest{
				authorization: r.Header.Get("Authorization"),
				certificate:   r.Header.Get("X-AWID-Team-Certificate"),
				timestamp:     r.Header.Get("X-AWEB-Timestamp"),
				body:          body,
			})
			requestMu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	writeStandaloneSelfCustodyIdentity(t, principalDir, "external.aweb.ai/principal", principalDID, principalStableID, principalServer.URL, principalKey)
	principalWorkspaceFixture := workspaceBinding(principalServer.URL, "default:external.aweb.ai", "principal", "principal-workspace")
	principalWorkspaceFixture.AwebTmuxTmpdir = "/tmp/principal-tmux"
	writeWorkspaceBindingForTest(t, principalDir, principalWorkspaceFixture)
	principalTeamFixture, err := awconfig.LoadTeamStateFromIdentityHome(identityHome)
	if err != nil {
		t.Fatal(err)
	}
	principalMembership := principalTeamFixture.Membership("default:external.aweb.ai")
	if principalMembership == nil {
		t.Fatal("external principal team state omitted active membership")
	}
	principalMembership.RegistryURL = "https://registry.membership.external.example"
	principalMembership.AwebURL = principalServer.URL
	if err := awconfig.SaveTeamStateToIdentityHome(identityHome, principalTeamFixture); err != nil {
		t.Fatal(err)
	}
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
	var shadowHits atomic.Int64
	shadowServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	writeWorkspaceBindingForTest(t, instance, workspaceBinding(shadowServer.URL, "shadow:local", "shadow", "shadow-workspace"))
	shadowWorkspacePath := awconfig.WorktreeWorkspacePath(instance)
	shadowWorkspace, err := awconfig.LoadWorktreeWorkspaceFrom(shadowWorkspacePath)
	if err != nil {
		t.Fatal(err)
	}
	shadowWorkspace.APIKey = "shadow-api-secret"
	shadowWorkspace.Hostname = "shadow-api-secret"
	if err := awconfig.SaveWorktreeWorkspaceTo(shadowWorkspacePath, shadowWorkspace); err != nil {
		t.Fatal(err)
	}
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
	for commandName, args := range map[string][]string{
		"doctor": {"--identity-home", identityHome, "doctor", "--offline", "--json"},
		"check":  {"--identity-home", identityHome, "check", "--offline", "--json"},
	} {
		command := exec.CommandContext(ctx, bin, args...)
		command.Env = testCommandEnv(tmp)
		command.Dir = instance
		data, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("external %s failed: %v\n%s", commandName, err, data)
		}
		var output doctorOutput
		if err := json.Unmarshal(extractJSON(t, data), &output); err != nil {
			t.Fatalf("decode external %s: %v\n%s", commandName, err, data)
		}
		assertExternalSubject(output)
		localWorkspace := findCheck(output, doctorCheckWorkspaceExists)
		if localWorkspace.Status != doctorStatusOK || localWorkspace.Target == nil || localWorkspace.Target.ID != filepath.Join(identityHome, "workspace.yaml") {
			t.Fatalf("%s local collector used wrong workspace: %+v", commandName, localWorkspace)
		}
		serverConfig := findCheck(output, doctorCheckServerAwebURLConfigured)
		if serverConfig.Status != doctorStatusOK || serverConfig.Detail["aweb_url"] != principalServer.URL {
			t.Fatalf("%s aweb collector used wrong workspace: %+v", commandName, serverConfig)
		}
		mailSignature := findCheck(output, doctorCheckMessagingMailSignature)
		if mailSignature.Status != doctorStatusOK || mailSignature.Target == nil || mailSignature.Target.ID != principalDID {
			t.Fatalf("%s messaging collector used wrong signing identity: %+v", commandName, mailSignature)
		}
		encoded, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "shadow.local") || strings.Contains(string(encoded), shadowDID) || strings.Contains(string(encoded), "shadow-workspace") {
			t.Fatalf("%s leaked disposable shadow state: %s", commandName, encoded)
		}
	}

	onlineCommand := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "doctor", "--online", "--json")
	onlineCommand.Env = testCommandEnv(tmp)
	onlineCommand.Dir = instance
	onlineData, err := onlineCommand.CombinedOutput()
	if err != nil {
		t.Fatalf("external online doctor failed: %v\n%s", err, onlineData)
	}
	var onlineOutput doctorOutput
	if err := json.Unmarshal(extractJSON(t, onlineData), &onlineOutput); err != nil {
		t.Fatal(err)
	}
	assertExternalSubject(onlineOutput)
	teamAuth := findCheck(onlineOutput, doctorCheckServerTeamAuth)
	if teamAuth.Status != doctorStatusOK {
		t.Fatalf("online doctor did not complete external certificate-auth request: %+v", teamAuth)
	}
	requestMu.Lock()
	requests := append([]observedDoctorRequest(nil), authenticatedRequests...)
	requestMu.Unlock()
	if len(requests) == 0 {
		t.Fatal("online doctor sent no authenticated principal requests")
	}
	certificateRequestCount := 0
	for _, request := range requests {
		parts := strings.Fields(request.authorization)
		if len(parts) != 3 || parts[1] != principalDID {
			t.Fatalf("online doctor request used wrong identity: %q", request.authorization)
		}
		payload := []byte(nil)
		if strings.TrimSpace(request.certificate) != "" {
			certificateRequestCount++
			cert, err := awid.DecodeTeamCertificateHeader(request.certificate)
			if err != nil {
				t.Fatal(err)
			}
			if cert.MemberDIDKey != principalDID || cert.Team != "default:external.aweb.ai" {
				t.Fatalf("online doctor request used wrong certificate: %+v", cert)
			}
			payload = messagingCertificateAuthPayload(cert.Team, request.timestamp, request.body)
		} else {
			hash := sha256.Sum256(request.body)
			payload = []byte(fmt.Sprintf(`{"body_sha256":"%s","did_aw":"%s","timestamp":"%s"}`,
				hex.EncodeToString(hash[:]), principalStableID, request.timestamp))
		}
		signature, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(principalPub, payload, signature) || ed25519.Verify(shadowPub, payload, signature) {
			t.Fatalf("online doctor request did not bind external principal: %q", request.authorization)
		}
	}
	if certificateRequestCount == 0 {
		t.Fatal("online doctor sent no external certificate-auth request")
	}

	principalWorkspacePath := filepath.Join(identityHome, "workspace.yaml")
	principalWorkspace, err := awconfig.LoadWorktreeWorkspaceFrom(principalWorkspacePath)
	if err != nil {
		t.Fatal(err)
	}
	principalWorkspace.APIKey = "principal-api-secret"
	principalWorkspace.Hostname = "principal-api-secret"
	if err := awconfig.SaveWorktreeWorkspaceTo(principalWorkspacePath, principalWorkspace); err != nil {
		t.Fatal(err)
	}
	principalSigningKeyBytes, err := os.ReadFile(filepath.Join(identityHome, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(canonicalTmp, "attached-support.json")
	bundleCommand := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "doctor", "support-bundle", "--offline", "--output", bundlePath, "--json")
	bundleCommand.Env = testCommandEnv(tmp)
	bundleCommand.Dir = instance
	bundleStdout, err := bundleCommand.CombinedOutput()
	if err != nil {
		t.Fatalf("external support bundle failed: %v\n%s", err, bundleStdout)
	}
	if strings.Contains(string(bundleStdout), `"detail"`) || strings.Contains(string(bundleStdout), "future-confidential-payload") {
		t.Fatalf("printed external support bundle exported dynamic diagnostic detail: %s", bundleStdout)
	}
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle doctorOutput
	if err := json.Unmarshal(bundleData, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Subject.Alias != "principal" || bundle.Subject.WorkspaceID != "principal-workspace" || bundle.Subject.IdentityPath != filepath.Join(doctorIdentityHomePathMarker, "identity.yaml") {
		t.Fatalf("support bundle subject did not symbolically identify external principal: %+v", bundle.Subject)
	}
	if strings.Contains(string(bundleData), identityHome) {
		t.Fatalf("support bundle exposed raw external identity-home path %q: %s", identityHome, bundleData)
	}
	if strings.Contains(string(bundleData), `"detail"`) {
		t.Fatalf("support bundle exported a dynamic detail surface: %s", bundleData)
	}
	bundleWorkspace := findCheck(bundle, doctorCheckWorkspaceExists)
	if bundleWorkspace.Target == nil || bundleWorkspace.Target.ID != filepath.Join(doctorIdentityHomePathMarker, "workspace.yaml") {
		t.Fatalf("support bundle did not symbolize principal workspace path: %+v", bundleWorkspace)
	}
	if bundle.SupportBundle == nil || bundle.SupportBundle.LocalMetadata.Alias != "principal" || bundle.SupportBundle.LocalMetadata.WorkspaceID != "principal-workspace" || bundle.SupportBundle.LocalMetadata.DIDKey != principalDID {
		t.Fatalf("support bundle metadata did not describe external principal: %+v", bundle.SupportBundle)
	}
	if bundle.SupportBundle.LocalMetadata.Hostname != doctorRedactedMarker {
		t.Fatalf("allowlisted hostname echo of a principal secret was not redacted: %+v", bundle.SupportBundle.LocalMetadata)
	}
	knownSecrets := collectDoctorKnownSecretsAt(instance, identityHome)
	knownSecretValues := map[string]bool{}
	for _, secret := range knownSecrets {
		knownSecretValues[secret.Value] = true
	}
	if !knownSecretValues["principal-api-secret"] || knownSecretValues["shadow-api-secret"] {
		t.Fatalf("known-secret collection was not principal-only: %+v", knownSecrets)
	}
	if strings.Contains(string(bundleData), "shadow.local") || strings.Contains(string(bundleData), shadowDID) || strings.Contains(string(bundleData), "shadow-workspace") {
		t.Fatalf("support bundle leaked disposable shadow state: %s", bundleData)
	}
	for _, secret := range []string{"principal-api-secret", "shadow-api-secret", strings.TrimSpace(string(principalSigningKeyBytes))} {
		if secret != "" && strings.Contains(string(bundleData), secret) {
			t.Fatalf("support bundle exported principal secret %q: %s", secret, bundleData)
		}
	}

	for category, output := range map[string]doctorOutput{"identity": shadowIdentityOutput, "registry": shadowRegistryOutput} {
		data, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "shadow.local") || strings.Contains(string(data), shadowDID) || strings.Contains(string(data), "shadow-workspace") || strings.Contains(string(data), shadowEncryption.KeyID) {
			t.Fatalf("doctor %s leaked disposable shadow state: %s", category, data)
		}
	}

	runFix := func(target string) doctorOutput {
		t.Helper()
		command := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "doctor", "--offline", "--fix", target, "--json")
		command.Env = testCommandEnv(tmp)
		command.Dir = instance
		data, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("external doctor fix %s failed: %v\n%s", target, err, data)
		}
		var output doctorOutput
		if err := json.Unmarshal(extractJSON(t, data), &output); err != nil {
			t.Fatal(err)
		}
		if len(output.Fixes) != 1 || output.Fixes[0].Status != doctorFixStatusApplied {
			t.Fatalf("external doctor fix %s was not applied: %+v", target, output.Fixes)
		}
		return output
	}
	principalWorkspace, err = awconfig.LoadWorktreeWorkspaceFrom(principalWorkspacePath)
	if err != nil {
		t.Fatal(err)
	}
	principalWorkspace.AwebURL = "https://user:password@aweb.external.example/api?credential=secret#fragment"
	if err := awconfig.SaveWorktreeWorkspaceTo(principalWorkspacePath, principalWorkspace); err != nil {
		t.Fatal(err)
	}
	runFix(doctorCheckWorkspaceAwebURL)
	principalWorkspace, err = awconfig.LoadWorktreeWorkspaceFrom(principalWorkspacePath)
	if err != nil || principalWorkspace.AwebURL != "https://aweb.external.example/api" {
		t.Fatalf("workspace URL fix did not target external principal: workspace=%+v err=%v", principalWorkspace, err)
	}
	if principalWorkspace.AwebTmuxTmpdir != "/tmp/principal-tmux" {
		t.Fatalf("workspace URL fix discarded canonical aweb_tmux_tmpdir: %+v", principalWorkspace)
	}
	principalIdentityFile, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	principalIdentityFile.RegistryURL = "https://registry.external.example/path?credential=secret#fragment"
	if err := awconfig.SaveWorktreeIdentityTo(identityPath, principalIdentityFile); err != nil {
		t.Fatal(err)
	}
	runFix(doctorCheckIdentityRegistryURL)
	principalIdentityFile, err = awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil || principalIdentityFile.RegistryURL != "https://registry.external.example/path" {
		t.Fatalf("registry URL fix did not target external principal: identity=%+v err=%v", principalIdentityFile, err)
	}
	principalTeamState, err := awconfig.LoadTeamStateFromIdentityHome(identityHome)
	if err != nil {
		t.Fatal(err)
	}
	teamStatePath := filepath.Join(identityHome, "teams.yaml")
	teamStateData, err := os.ReadFile(teamStatePath)
	if err != nil {
		t.Fatal(err)
	}
	teamStateLines := strings.Split(string(teamStateData), "\n")
	for i, line := range teamStateLines {
		if strings.HasPrefix(strings.TrimSpace(line), "active_team:") {
			teamStateLines[i] = "active_team: \"\""
			break
		}
	}
	if err := os.WriteFile(teamStatePath, []byte(strings.Join(teamStateLines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	runFix(doctorCheckTeamsActiveTeam)
	principalTeamState, err = awconfig.LoadTeamStateFromIdentityHome(identityHome)
	if err != nil || principalTeamState.ActiveTeam != "default:external.aweb.ai" {
		t.Fatalf("active-team fix did not target external principal: state=%+v err=%v", principalTeamState, err)
	}
	principalMembership = principalTeamState.Membership("default:external.aweb.ai")
	if principalMembership == nil || principalMembership.RegistryURL != "https://registry.membership.external.example" || principalMembership.AwebURL != principalServer.URL {
		t.Fatalf("active-team fix discarded external membership service metadata: %+v", principalTeamState)
	}
	malformedExternalTeamState := []byte("active_team: \"\"\nmemberships:\n  - team_id: default:external.aweb.ai\n    registry_url: https://registry.membership.must-survive.example\n    aweb_url: [malformed\n")
	if err := os.WriteFile(teamStatePath, malformedExternalTeamState, 0o600); err != nil {
		t.Fatal(err)
	}
	malformedFix := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "doctor", "--offline", "--fix", doctorCheckTeamsActiveTeam, "--json")
	malformedFix.Env = testCommandEnv(tmp)
	malformedFix.Dir = instance
	malformedFixData, err := malformedFix.CombinedOutput()
	if err != nil {
		t.Fatalf("external malformed teams fix failed: %v\n%s", err, malformedFixData)
	}
	var malformedFixOutput doctorOutput
	if err := json.Unmarshal(extractJSON(t, malformedFixData), &malformedFixOutput); err != nil {
		t.Fatal(err)
	}
	if len(malformedFixOutput.Fixes) != 1 || malformedFixOutput.Fixes[0].Status != doctorFixStatusRefused {
		t.Fatalf("external malformed teams fix was not refused: %+v", malformedFixOutput.Fixes)
	}
	afterMalformedExternal, err := os.ReadFile(teamStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterMalformedExternal, malformedExternalTeamState) {
		t.Fatalf("external malformed teams.yaml was overwritten\nbefore:\n%s\nafter:\n%s", malformedExternalTeamState, afterMalformedExternal)
	}

	if hits := shadowHits.Load(); hits != 0 {
		t.Fatalf("doctor contacted disposable shadow server %d times", hits)
	}
	if shadowAfter := fileDigestsForTest(t, filepath.Join(instance, ".aw")); !reflect.DeepEqual(shadowAfter, shadowBefore) {
		t.Fatal("doctor read path mutated the disposable instance shadow")
	}
}

func TestExternalIdentityHomeUnadmittedDoctorCategoriesRemainRefused(t *testing.T) {
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

	commands := [][]string{
		{"doctor", "local", "--offline", "--json"},
		{"doctor", "workspace", "--offline", "--json"},
		{"doctor", "team", "--offline", "--json"},
		{"doctor", "messaging", "--offline", "--json"},
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
		for _, alternative := range []string{"aw doctor", "aw doctor identity", "aw doctor registry", "aw doctor support-bundle"} {
			if !strings.Contains(text, alternative) {
				t.Fatalf("doctor refusal omitted derived safe alternative %q:\n%s", alternative, text)
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("refused diagnostics mutated instance: %v", err)
	}
}
